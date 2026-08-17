#!/usr/bin/env python3
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from automation.device import UsbTunnel, scp_get, scp_put, ssh

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
CLIP = ROOT / "testfiles" / "ai-sora-ships.mp4"
PULL = HERE / "IMG_0028-after-index.MP4"


def main() -> int:
    sh = HERE / "install_ai.sh"
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
            (CLIP, "/tmp/ai-sora-ships.mp4"),
            (sh, "/tmp/install_ai.sh"),
        ):
            r = scp_put(local, remote)
            print("put", local.name, r.returncode, (r.stderr or "").strip())
            if r.returncode != 0:
                return r.returncode
        out = ssh(
            "export PATH=/var/jb/usr/bin:/var/jb/bin:/usr/bin:/bin; "
            "/var/jb/bin/sh /tmp/install_ai.sh",
            timeout=60,
        )
        print(out.stdout)
        if out.stderr:
            print(out.stderr, file=sys.stderr)
        if out.returncode != 0:
            return out.returncode
        g = scp_get("/var/mobile/Media/DCIM/100APPLE/IMG_0028.MP4", PULL)
        print("get IMG_0028.MP4", g.returncode,
              PULL.stat().st_size if PULL.is_file() else 0)
        return g.returncode
    finally:
        if owned:
            tunnel.stop()


if __name__ == "__main__":
    raise SystemExit(main())
