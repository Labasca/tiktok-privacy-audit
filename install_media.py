#!/usr/bin/env python3
"""Import a folder of files into the camera roll through PhotoKit, reversibly.

    python install_media.py --dir testfiles/roll-sweep --kind image
    python install_media.py --undo runs/roll-sweep-imported.json

Generalises install_image_arms.py, which had its five arms hard-coded. The
door is the same one an app walks through, so nothing is stashed, no index is
rebuilt and the rest of the library is untouched.

Every import writes the local identifiers it created to a manifest, and --undo
hands that manifest back to PhotoKit. That is not a nicety: these experiments
put hundreds of files into a real camera roll, and a tool that can only add
them has no business running.

TikTok must be in the foreground -- a backgrounded app gets suspended and the
attach times out.
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

HERE = os.path.dirname(os.path.abspath(__file__))
BUNDLE = "com.zhiliaoapp.musically"
PROBE = os.path.join(HERE, "tools", "phkit_probe.compiled.js")
EXTS = {"image": (".heic", ".heif", ".jpg", ".jpeg", ".png"),
        "video": (".mov", ".mp4", ".m4v")}
# PhotoKit takes a batch as one transaction; too large a one is slow to commit
# and gives no partial progress if it fails.
CHUNK = 60


def sh(cmd, timeout=90):
    from automation.device import ssh
    return ssh(cmd, timeout=timeout)


def attach(frida):
    dev = frida.get_usb_device(timeout=10)
    pid = next((a.pid for a in dev.enumerate_applications()
                if a.identifier == BUNDLE and a.pid), None)
    if not pid:
        sys.exit("TikTok is not running. Open it, leave it in the foreground, "
                 "and run this again.")
    for n in range(4):
        try:
            return dev.attach(pid), pid
        except frida.TransportError as e:
            print("  attach attempt %d: %s" % (n + 1, e))
            time.sleep(3)
    sys.exit("could not attach to pid %d. Bring TikTok to the foreground." % pid)


def load_script(session, on_message):
    with open(PROBE, encoding="utf-8") as fh:
        src = fh.read()
    script = session.create_script(src)
    script.on("message", on_message)
    script.load()
    return script


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dir", help="folder of files to import")
    ap.add_argument("--kind", choices=("image", "video"), default="image")
    ap.add_argument("--manifest", help="where to write the identifiers "
                                       "(default: alongside the folder)")
    ap.add_argument("--undo", help="a manifest to delete from the library")
    ap.add_argument("--wait", type=float, default=25.0)
    args = ap.parse_args()
    if not args.dir and not args.undo:
        ap.error("give --dir to import, or --undo with a manifest")

    import frida
    from automation.device import UsbTunnel, scp_put

    tunnel = UsbTunnel()
    owned = False
    try:
        tunnel.start()
        owned = True
    except OSError as e:
        if "already in use" not in str(e).lower() and getattr(e, "winerror", None) != 10048:
            raise

    seen = []

    def on_message(msg, _data):
        if msg.get("type") == "send":
            p = msg["payload"]
            seen.append(p)
            print("  %-12s %s" % (p.get("stage"), p.get("detail")))
        elif msg.get("type") == "error":
            print("  script error:", msg.get("description"))

    staged = []
    try:
        print("attaching to %s ..." % BUNDLE)
        session, pid = attach(frida)
        print("  pid %d" % pid)
        script = load_script(session, on_message)

        if args.undo:
            with open(args.undo, encoding="utf-8") as fh:
                ids = json.load(fh)["identifiers"]
            print("deleting %d assets ..." % len(ids))
            print("  iOS shows a confirmation sheet on the phone -- accept it there")
            script.exports_sync.delete_assets(ids)
            time.sleep(args.wait)
            ok = {p.get("stage"): p.get("detail") for p in seen}.get("result")
            print("\n%s" % ("removed" if ok == "success"
                            else "not removed -- the sheet may still be waiting"))
            return 0 if ok == "success" else 1

        files = sorted(os.path.join(args.dir, f) for f in os.listdir(args.dir)
                       if f.lower().endswith(EXTS[args.kind]))
        if not files:
            sys.exit("no %s files in %s" % (args.kind, args.dir))

        dirs = script.exports_sync.app_dirs()
        print("staging %d file(s) into the app sandbox ..." % len(files))
        for n, f in enumerate(files, 1):
            remote = "%s/%s" % (dirs["tmp"], os.path.basename(f))
            r = scp_put(Path(f), remote)
            if r.returncode != 0:
                sys.exit("scp failed for %s: %s" % (f, r.stderr or ""))
            staged.append(remote)
            if n % 25 == 0 or n == len(files):
                print("  %d/%d" % (n, len(files)))
        sh("chown mobile:mobile '%s'/* ; chmod 644 '%s'/*" % (dirs["tmp"], dirs["tmp"]))

        ids = []
        for i in range(0, len(staged), CHUNK):
            batch = staged[i:i + CHUNK]
            print("\nimporting %d-%d of %d ..." % (i + 1, i + len(batch), len(staged)))
            before = len(seen)
            script.exports_sync.run_import_batch(batch, args.kind)
            time.sleep(args.wait)
            got = [p["detail"] for p in seen[before:]
                   if p.get("stage") == "identifiers" and p.get("detail")]
            ids += [x for g in got for x in g.split(",") if x]
        try:
            session.detach()
        except Exception:                                      # noqa: BLE001
            pass

        manifest = args.manifest or os.path.join(
            "runs", os.path.basename(args.dir.rstrip("/\\")) + "-imported.json")
        os.makedirs(os.path.dirname(manifest) or ".", exist_ok=True)
        with open(manifest, "w", encoding="utf-8") as fh:
            json.dump({"kind": args.kind, "dir": args.dir,
                       "identifiers": ids}, fh, indent=1)
        print("\n%d asset(s) created. Manifest: %s" % (len(ids), manifest))
        print("undo with:  python install_media.py --undo %s" % manifest)
        return 0 if ids else 1
    finally:
        for remote in staged:
            sh("rm -f '%s'" % remote)
        if owned:
            tunnel.stop()


if __name__ == "__main__":
    sys.exit(main())
