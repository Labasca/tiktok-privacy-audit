#!/usr/bin/env python3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from automation.device import UsbTunnel, ssh


def main() -> int:
    tunnel = UsbTunnel()
    owned = False
    try:
        tunnel.start()
        owned = True
    except OSError as e:
        print("tunnel", e)
    try:
        out = ssh(
            "export PATH=/var/jb/usr/bin:/var/jb/bin:/usr/bin:/bin; "
            "echo HOST=$(uname -a); "
            "echo PRODUCT=$(sw_vers -productVersion 2>/dev/null); "
            "echo ---youcan-ls---; "
            "ls /var/containers/Bundle/Application 2>/dev/null | wc -l; "
            "find /var/containers/Bundle/Application /Applications /var/jb/Applications "
            "-iname '*youcan*' -o -iname '*toned*' 2>/dev/null; "
            "echo ---no-find-end---; "
            "uicache --list 2>/dev/null | grep -i youcan || true; "
            "echo done",
            timeout=30,
        )
        print(out.stdout)
        if out.stderr:
            print(out.stderr, file=sys.stderr)
        return out.returncode
    except Exception as e:
        print("ssh fail", type(e), e)
        return 1
    finally:
        if owned:
            tunnel.stop()


if __name__ == "__main__":
    raise SystemExit(main())
