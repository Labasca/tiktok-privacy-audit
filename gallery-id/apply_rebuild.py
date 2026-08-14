#!/usr/bin/env python3
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from automation.device import UsbTunnel, scp_put, ssh

HERE = Path(__file__).resolve().parent


def main() -> int:
    sh = HERE / "rebuild_library.sh"
    sh.write_bytes(sh.read_text(encoding="utf-8").replace("\r\n", "\n").encode())
    accounts = HERE / "accounts-edit" / "Accounts3.sqlite"
    if not accounts.is_file():
        print("run disable_cloudphotos.py first")
        return 2
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
            (accounts, "/tmp/Accounts3.sqlite"),
            (sh, "/tmp/rebuild_library.sh"),
        ):
            r = scp_put(local, remote)
            print("put", local.name, r.returncode, (r.stderr or "").strip())
            if r.returncode != 0:
                return r.returncode
        out = ssh(
            "export PATH=/var/jb/usr/bin:/var/jb/bin:/usr/bin:/bin; "
            "chmod +x /tmp/rebuild_library.sh; /var/jb/bin/sh /tmp/rebuild_library.sh"
        )
        print(out.stdout)
        if out.stderr:
            print(out.stderr)
        return out.returncode
    finally:
        if owned:
            tunnel.stop()


if __name__ == "__main__":
    raise SystemExit(main())
