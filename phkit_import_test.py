#!/usr/bin/env python3
"""Does a stamped file survive PhotoKit's own import path?

Every arm so far reached the camera roll the jailbreak way: scp into DCIM,
drop Photos.sqlite, let the index rebuild. That is not the door an app goes
through. An app calls PHAssetCreationRequest, and Photos is free to rewrite
the file on the way in -- which is what cost clip 2 seven kilobytes.

This calls that API for real, from inside a process that already holds photo
library permission, and reports where the resulting asset landed so it can be
pulled back and diffed against the input.

    python phkit_import_test.py --file testfiles/ai-nativized-v2.mov

Read-only with respect to the audit: it adds one asset to the roll and touches
nothing else. Remove it afterwards if you care about a clean library.
"""

import argparse
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

BUNDLE = "com.zhiliaoapp.musically"
REMOTE = "/tmp/phkit_import_probe"

# Runs inside the app. PHPhotoLibrary.performChanges is async, so the result
# comes back over the message channel rather than as a return value.
PROBE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                     "tools", "phkit_probe.compiled.js")



def sh(cmd, timeout=90):
    from automation.device import ssh
    return ssh(cmd, timeout=timeout)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--file", required=True, help="the stamped file to import")
    ap.add_argument("--wait", type=float, default=12.0,
                    help="seconds to wait on the completion handler")
    args = ap.parse_args()

    src = os.path.abspath(args.file)
    if not os.path.isfile(src):
        sys.exit("error: no such file: %s" % src)

    import frida
    from automation.device import UsbTunnel, scp_put

    name = os.path.basename(src)
    remote = "%s/%s" % (REMOTE, name)

    tunnel = UsbTunnel()
    owned = False
    try:
        tunnel.start()
        owned = True
    except OSError as e:
        if "already in use" not in str(e).lower() and getattr(e, "winerror", None) != 10048:
            raise
    try:
        print("attaching to %s ..." % BUNDLE)
        dev = frida.get_usb_device(timeout=10)
        pid = next((a.pid for a in dev.enumerate_applications()
                    if a.identifier == BUNDLE and a.pid), None)
        if not pid:
            print("  app is not running; spawning it")
            pid = dev.spawn([BUNDLE])
            session = dev.attach(pid)
            dev.resume(pid)
            time.sleep(4)
        else:
            # a backgrounded app can be suspended, and the first attach then
            # times out rather than failing outright
            session = None
            for n in range(4):
                try:
                    session = dev.attach(pid)
                    break
                except frida.TransportError as e:
                    print("  attach attempt %d: %s" % (n + 1, e))
                    time.sleep(3)
            if session is None:
                sys.exit("could not attach to pid %d. Bring TikTok to the "
                         "foreground and try again." % pid)
        print("  pid %d" % pid)

        seen = []

        def on_message(msg, _data):
            if msg.get("type") == "send":
                p = msg["payload"]
                seen.append(p)
                print("  %-12s %s" % (p.get("stage"), p.get("detail")))
            elif msg.get("type") == "error":
                print("  script error:", msg.get("description"))

        # the compiled bundle declares its own byte length in the header,
        # so it must be loaded verbatim; the path goes over rpc instead
        with open(PROBE, encoding="utf-8") as fh:
            probe_src = fh.read()
        script = session.create_script(probe_src)
        script.on("message", on_message)
        script.load()

        # a sandboxed app cannot read /tmp, so stage inside its own container
        dirs = script.exports_sync.app_dirs()
        remote = "%s/%s" % (dirs["tmp"], name)
        print("staging into the app sandbox ...")
        r = scp_put(Path(src), remote)
        if r.returncode != 0:
            sys.exit("scp failed: %s" % (r.stderr or ""))
        sh("chown mobile:mobile '%s'; chmod 644 '%s'" % (remote, remote))
        before = sh("ls /var/mobile/Media/DCIM/100APPLE/").stdout.split()
        print("  %s" % remote)

        script.exports_sync.run_import(remote)
        time.sleep(args.wait)
        try:
            session.detach()
        except Exception:                                      # noqa: BLE001
            pass

        stages = {p.get("stage"): p.get("detail") for p in seen}
        if stages.get("result") != "success":
            print("\nimport did not report success. stages seen: %s"
                  % ", ".join(stages) or "none")
            return 1

        # PhotoKit writes the new asset into DCIM under its own name
        time.sleep(2)
        after = sh("ls /var/mobile/Media/DCIM/100APPLE/").stdout.split()
        added = [f for f in after if f not in before]
        print("\nasset written by PhotoKit: %s" % (", ".join(added) or "none visible in DCIM"))
        if added:
            print("\npull it back and diff with:")
            for f in added:
                print("  scp from /var/mobile/Media/DCIM/100APPLE/%s, then" % f)
                print("  python nativize.py --check <pulled> --reference %s" % args.file)
        return 0
    finally:
        sh("rm -f '%s'" % remote)
        if owned:
            tunnel.stop()


if __name__ == "__main__":
    sys.exit(main())
