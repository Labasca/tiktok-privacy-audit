#!/usr/bin/env python3
"""Push a nativize.py output onto the phone as the only clip in Recents.

    python gallery-id/apply_nativized.py path/to/ready.mov

Then run a solo Frida window and post it by hand:

    .\\tiktok-audit.ps1 180 -Touch -Run unique-10-nativized

Pulls the file back after the Photos import so you can confirm Photos did not
rewrite the stamp -- the same check that made clip 6 (CANARY) trustworthy.
"""
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from automation.device import UsbTunnel, scp_get, scp_put, ssh  # noqa: E402

HERE = Path(__file__).resolve().parent
PULL = HERE / "IMG_0034-after-index.MOV"


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    clip = Path(sys.argv[1]).resolve()
    if not clip.is_file():
        print("no such file: %s" % clip, file=sys.stderr)
        return 2

    sh = HERE / "install_nativized.sh"
    sh.write_bytes(sh.read_text(encoding="utf-8").replace("\r\n", "\n").encode())

    tunnel = UsbTunnel()
    owned = False
    try:
        tunnel.start()
        owned = True
    except OSError as e:
        if "already in use" not in str(e).lower() and getattr(e, "winerror", None) != 10048:
            raise
    try:
        for local, remote in ((clip, "/tmp/nativized.mov"),
                              (sh, "/tmp/install_nativized.sh")):
            r = scp_put(local, remote)
            print("put", local.name, r.returncode, (r.stderr or "").strip())
            if r.returncode != 0:
                return r.returncode
        out = ssh(
            "export PATH=/var/jb/usr/bin:/var/jb/bin:/usr/bin:/bin; "
            "/var/jb/bin/sh /tmp/install_nativized.sh",
            timeout=60,
        )
        print(out.stdout)
        if out.stderr:
            print(out.stderr, file=sys.stderr)
        if out.returncode != 0:
            return out.returncode
        g = scp_get("/var/mobile/Media/DCIM/100APPLE/IMG_0034.MOV", PULL)
        print("get IMG_0034.MOV", g.returncode,
              PULL.stat().st_size if PULL.is_file() else 0)
        if g.returncode == 0 and PULL.is_file():
            print("\nchecking the stamp survived the Photos import ...")
            subprocess.run([sys.executable, str(HERE.parent / "nativize.py"),
                            "--check", str(PULL), "--reference", str(clip)])
        return g.returncode
    finally:
        if owned:
            tunnel.stop()


if __name__ == "__main__":
    sys.exit(main())
