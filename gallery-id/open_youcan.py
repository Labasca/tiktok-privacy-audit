#!/usr/bin/env python3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from automation.device import UsbTunnel, scp_put, ssh

HERE = Path(__file__).resolve().parent


def main() -> int:
    sh = HERE / "open_youcan.sh"
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
        p = scp_put(sh, "/tmp/open_youcan.sh")
        print("put", p.returncode, (p.stderr or "").strip())
        out = ssh(
            "export PATH=/var/jb/usr/bin:/var/jb/bin:/usr/bin:/bin; "
            "/var/jb/bin/sh /tmp/open_youcan.sh",
            timeout=45,
        )
        print(out.stdout)
        if out.stderr:
            print(out.stderr, file=sys.stderr)
        return out.returncode
    finally:
        if owned:
            tunnel.stop()


if __name__ == "__main__":
    raise SystemExit(main())
