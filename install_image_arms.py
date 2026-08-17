#!/usr/bin/env python3
"""Put the five stills arms in the camera roll through PhotoKit, then verify.

The video arms all reached the roll the jailbreak way: scp into DCIM, drop
Photos.sqlite, wait for the index to rebuild. That destroys the library every
time and takes a reboot. Phase 0 showed PHAssetCreationRequest returns the
video byte-identical, so this uses the door an app actually walks through --
no stashing, no reindex, nothing else in the library disturbed.

    python install_image_arms.py

Stills are the untested half: the image creation request is a different code
path from the video one, and Photos is free to transcode a HEIC on the way in.
So every arm is pulled back off the device afterwards and compared to what went
in. An arm that did not survive byte-identical is reported, not silently used,
because a rewritten file measures Photos rather than TikTok.

TikTok must be in the foreground: a backgrounded app gets suspended and the
attach times out.
"""

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

HERE = os.path.dirname(os.path.abspath(__file__))
BUNDLE = "com.zhiliaoapp.musically"
DCIM = "/var/mobile/Media/DCIM/100APPLE"
PROBE = os.path.join(HERE, "tools", "phkit_probe.compiled.js")
ARMS_DIR = os.path.join(HERE, "testfiles", "image-arms")

# name, file, and the string that identifies the arm in a pulled-back file
ARMS = [
    ("1 CLEAN", "img-1-clean.jpg", None),
    ("2 CAMERA", "img-2-camera.heic", "Apple"),
    ("3 CANARY HEIC", "img-3-canary.heic", "CANARYMK-9B2E"),
    ("4 CANARY XMP", "img-4-canary-xmp.jpg", "CANARYMK-9B4F"),
    ("5 CANARY JPEG", "img-5-canary.jpg", "CANARYMK-9B60"),
]


def sh(cmd, timeout=90):
    from automation.device import ssh
    return ssh(cmd, timeout=timeout)


def tags(path):
    """Every metadata tag exiftool can see, keyspace preserved."""
    r = subprocess.run(["exiftool", "-j", "-G1", "-n",
                        "-api", "largefilesupport=1", path],
                       capture_output=True, text=True)
    try:
        d = json.loads(r.stdout)[0]
    except Exception:                                          # noqa: BLE001
        return {}
    drop = ("SourceFile", "File", "System", "ExifTool", "Composite")
    return {k: v for k, v in d.items() if k.split(":")[0] not in drop}


def identify(path):
    """Which arm is this pulled-back file? Read it, do not trust the order."""
    t = tags(path)
    for group in ("IFD0:Make", "XMP-tiff:Make"):
        if group in t:
            return str(t[group])
    return None


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--wait", type=float, default=20.0,
                    help="seconds to wait on the completion handler")
    ap.add_argument("--keep-staged", action="store_true",
                    help="leave the staged copies in the app container")
    args = ap.parse_args()

    import frida
    from automation.device import UsbTunnel, scp_put, scp_get

    files = []
    for label, name, _ in ARMS:
        p = os.path.join(ARMS_DIR, name)
        if not os.path.isfile(p):
            sys.exit("error: missing arm %s (%s). Run "
                     "testfiles/make_image_arms.py first." % (label, p))
        files.append(p)

    tunnel = UsbTunnel()
    owned = False
    try:
        tunnel.start()
        owned = True
    except OSError as e:
        if "already in use" not in str(e).lower() and getattr(e, "winerror", None) != 10048:
            raise

    staged = []
    try:
        print("attaching to %s ..." % BUNDLE)
        dev = frida.get_usb_device(timeout=10)
        pid = next((a.pid for a in dev.enumerate_applications()
                    if a.identifier == BUNDLE and a.pid), None)
        if not pid:
            sys.exit("TikTok is not running. Open it and bring it to the "
                     "foreground, then run this again.")
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

        with open(PROBE, encoding="utf-8") as fh:
            probe_src = fh.read()
        script = session.create_script(probe_src)
        script.on("message", on_message)
        script.load()

        # a sandboxed app cannot read /tmp, so stage inside its own container
        dirs = script.exports_sync.app_dirs()
        print("\nstaging five arms into the app sandbox ...")
        for p in files:
            remote = "%s/%s" % (dirs["tmp"], os.path.basename(p))
            r = scp_put(Path(p), remote)
            if r.returncode != 0:
                sys.exit("scp failed for %s: %s" % (p, r.stderr or ""))
            sh("chown mobile:mobile '%s'; chmod 644 '%s'" % (remote, remote))
            staged.append(remote)
            print("  %8d B  %s" % (os.path.getsize(p), remote))

        before = set(sh("ls %s" % DCIM).stdout.split())

        print("\nimporting through PHAssetCreationRequest ...")
        script.exports_sync.run_import_batch(staged, "image")
        time.sleep(args.wait)
        try:
            session.detach()
        except Exception:                                      # noqa: BLE001
            pass

        stages = {p.get("stage"): p.get("detail") for p in seen}
        if stages.get("result") != "success":
            print("\nimport did not report success. stages seen: %s"
                  % (", ".join(stages) or "none"))
            return 1

        time.sleep(3)
        after = sh("ls %s" % DCIM).stdout.split()
        added = sorted(f for f in after if f not in before)
        print("\nPhotos wrote %d new asset(s): %s"
              % (len(added), ", ".join(added) or "none visible in DCIM"))
        if not added:
            print("nothing landed in DCIM -- the assets may be elsewhere; "
                  "check Recents on the phone before posting.")
            return 1

        # pull each one back and prove it is the same file that went in
        pulled_dir = os.path.join(HERE, "testfiles", "image-arms-pulled")
        os.makedirs(pulled_dir, exist_ok=True)
        by_marker = {marker: (label, path)
                     for (label, _n, marker), path in zip(ARMS, files) if marker}

        print("\n%-16s %-14s %-9s %-9s %s"
              % ("arm", "on device", "sent", "returned", "verdict"))
        ok_all = True
        for f in added:
            local = Path(pulled_dir) / f
            r = scp_get("%s/%s" % (DCIM, f), local)
            if r.returncode != 0:
                print("  could not pull %s: %s" % (f, r.stderr or ""))
                ok_all = False
                continue
            marker = identify(str(local))
            label, src = by_marker.get(marker, ("? unmatched", None))
            if src is None:
                # arm 1 carries nothing to match on; fall back to byte size
                for lb, name, mk in ARMS:
                    if mk is None:
                        cand = os.path.join(ARMS_DIR, name)
                        if os.path.getsize(cand) == os.path.getsize(local):
                            label, src = lb, cand
                        break
            if src is None:
                print("  %-16s %-14s %-9s %-9s %s"
                      % ("? unmatched", f, "-", os.path.getsize(local),
                         "could not tie this asset to an arm"))
                ok_all = False
                continue
            sent, back = os.path.getsize(src), os.path.getsize(local)
            same_bytes = sent == back
            lost = sorted(set(tags(src)) - set(tags(str(local))))
            verdict = ("identical" if same_bytes and not lost
                       else "REWRITTEN: %d tag(s) lost%s"
                            % (len(lost), (" " + ", ".join(lost[:4])) if lost else ""))
            if not (same_bytes and not lost):
                ok_all = False
            print("  %-16s %-14s %-9d %-9d %s" % (label, f, sent, back, verdict))

        print("\ncanary ids: heic 9B2E, xmp 9B4F, jpeg 9B60 -- one per arm, so all")
        print("five can sit in Recents together and a hit still names one file.")
        if ok_all:
            print("\nall arms survived import unchanged. Post them one at a time,")
            print("each inside its own observe window.")
        else:
            print("\nat least one arm did not survive import unchanged. An arm that")
            print("Photos rewrote measures Photos, not TikTok -- read the table above")
            print("before treating its run as evidence.")
        return 0
    finally:
        if not args.keep_staged:
            for remote in staged:
                sh("rm -f '%s'" % remote)
        if owned:
            tunnel.stop()


if __name__ == "__main__":
    sys.exit(main())
