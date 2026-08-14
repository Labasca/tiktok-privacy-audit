#!/usr/bin/env python3
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from automation.device import UsbTunnel, scp_put, ssh

HERE = Path(__file__).resolve().parent
EDIT = HERE / "photos-db-edit"


def main() -> int:
    sh = HERE / "apply_cleanup.sh"
    sh.write_bytes(sh.read_text(encoding="utf-8").replace("\r\n", "\n").encode("utf-8"))
    tunnel = UsbTunnel()
    owned = False
    try:
        tunnel.start()
        owned = True
    except OSError as e:
        if "already in use" not in str(e).lower() and getattr(e, "winerror", None) != 10048:
            raise
        print("tunnel already up")
    try:
        print(ssh("export PATH=/var/jb/usr/bin:/var/jb/bin:/usr/bin:/bin; killall -9 photolibraryd photoanalysisd cameracaptured MobileSlideShow cloudphotod mediaplaybackd 2>/dev/null; echo killed").stdout)
        for local, remote in (
            (EDIT / "Photos.sqlite", "/var/mobile/Media/PhotoData/Photos.sqlite"),
            (EDIT / "delete_paths.txt", "/tmp/delete_paths.txt"),
            (sh, "/tmp/apply_cleanup.sh"),
        ):
            r = scp_put(local, remote)
            print("put", local.name, r.returncode, (r.stderr or "").strip())
            if r.returncode != 0:
                return r.returncode
        out = ssh(
            "export PATH=/var/jb/usr/bin:/var/jb/bin:/usr/bin:/bin; "
            "chmod +x /tmp/apply_cleanup.sh; /var/jb/bin/sh /tmp/apply_cleanup.sh"
        )
        print(out.stdout)
        print("rc", out.returncode)
        if out.stderr:
            print(out.stderr)
        return out.returncode
    finally:
        if owned:
            tunnel.stop()


if __name__ == "__main__":
    raise SystemExit(main())
