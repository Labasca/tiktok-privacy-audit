#!/usr/bin/env python3
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from automation.device import UsbTunnel, scp_get, scp_put, ssh

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
CLIP = ROOT / "testfiles" / "unique-6-canary.mov"
PULL = HERE / "IMG_0027-after-index.MOV"


def main() -> int:
    sh = HERE / "install_canary.sh"
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
        for local, remote in (
            (CLIP, "/tmp/unique-6-canary.mov"),
            (sh, "/tmp/install_canary.sh"),
        ):
            r = scp_put(local, remote)
            print("put", local.name, r.returncode, (r.stderr or "").strip())
            if r.returncode != 0:
                return r.returncode
        out = ssh(
            "export PATH=/var/jb/usr/bin:/var/jb/bin:/usr/bin:/bin; "
            "/var/jb/bin/sh /tmp/install_canary.sh"
        )
        print(out.stdout)
        if out.stderr:
            print(out.stderr, file=sys.stderr)
        if out.returncode != 0:
            return out.returncode
        PULL.parent.mkdir(parents=True, exist_ok=True)
        g = scp_get("/var/mobile/Media/DCIM/100APPLE/IMG_0027.MOV", PULL)
        print("get IMG_0027.MOV", g.returncode, (g.stderr or "").strip(),
              PULL.stat().st_size if PULL.is_file() else 0)
        return g.returncode
    finally:
        if owned:
            tunnel.stop()


if __name__ == "__main__":
    raise SystemExit(main())
