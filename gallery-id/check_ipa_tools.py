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
            "export PATH=/var/jb/usr/bin:/var/jb/bin:/usr/sbin:/usr/bin:/bin; "
            "echo ---tools---; "
            "for t in ipainstaller appinst dpkg ldid plutil uicache unzip zip filza; do "
            "command -v $t 2>/dev/null || ls /var/jb/usr/bin/$t /var/jb/bin/$t 2>/dev/null || echo missing-$t; "
            "done; "
            "echo ---tweaks---; "
            "dpkg -l 2>/dev/null | grep -iE 'appsync|trollstore|filza|appinst|ipa' || echo no-dpkg-hits; "
            "echo ---airdrop-dirs---; "
            "ls -ld /var/mobile/Downloads /var/mobile/Media/Downloads "
            "/var/mobile/Media/Inbox /var/mobile/Library/Application\\ Support/Xcode 2>/dev/null; "
            "echo ---recent-ipa---; "
            "find /var/mobile/Downloads /var/mobile/Media /var/tmp /tmp "
            "-iname '*.ipa' 2>/dev/null | head",
            timeout=35,
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
