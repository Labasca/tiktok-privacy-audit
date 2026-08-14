"""
USB shell and the one-time bootstrap that turns it on.

Standing control is OpenSSH over usbmux, key-only. Frida is used once, to
install that key, and only by spawning /var/jb/bin/sh. It is never pointed
at TikTok. A Frida-spawned shell as the everyday channel would couple the
poster to the same process class the observer uses, and TikTok's launch
sweep (DYLD_INSERT_LIBRARIES, _dyld_image_count, entitlements,
kern.secure_kernel) is exactly the class of check that logs a jailbroken
device out.

Live on this handset, measured this session, not assumed:

  palera1n rootless, marker at /var/jb/.installed_palera1n
  OpenSSH_9.7 already packaged, socket-activated on :22 and :2222
  inetd-style: launchd accepts the TCP, sshd -i is spawned per connection,
    so `ps` not showing sshd is not "sshd is off"
  dropbear 2022.83 on :44 (palera1n's own hatch; we do not touch it)
  Procursus passwd: root home is /var/jb/var/root, password field is locked
    (`root:*:`). The alpine hash in iOS /etc/passwd is not what sshd reads.
  Coreutils live under /var/jb/usr/bin. A raw spawn has an empty PATH.

Semi-tethered persistence: the plist is a LaunchDaemon under /var/jb with
no Disabled key. After a reboot the jailbreak is gone until palera1n is
re-applied; after re-apply, /var/jb remounts and the loader should pick
the plist back up. This file records that claim. It does not reboot the
phone to prove it.
"""
from __future__ import annotations

import os
import plistlib
import select
import shutil
import socket
import struct
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
KEYS_DIR = HERE / "keys"
POSTER_KEY = KEYS_DIR / "poster_ed25519"
POSTER_PUB = KEYS_DIR / "poster_ed25519.pub"
INBOX = "/var/mobile/Media/poster-inbox"
JB_ROOT_HOME = "/var/jb/var/root"
JB_MOBILE_HOME = "/var/jb/var/mobile"
IOS_ROOT_HOME = "/var/root"
IOS_MOBILE_HOME = "/var/mobile"
SSHD_CONFIG = "/var/jb/etc/ssh/sshd_config"
SSHD_PLIST = "/var/jb/Library/LaunchDaemons/com.openssh.sshd.plist"
SH = "/var/jb/bin/sh"
PATH_EXPORT = "export PATH=/var/jb/usr/bin:/var/jb/bin:/usr/bin:/bin:/usr/sbin:/sbin"

# Host side of the USB tunnel. Device already listens on both 22 and 2222;
# we forward host:2222 -> device:22, which is the brief's `iproxy 2222 22`.
HOST = "127.0.0.1"
HOST_PORT = 2222
DEVICE_PORT = 22
USBMUX_ADDR = ("127.0.0.1", 27015)

# Anything we will refuse to spawn or attach to. Bundle ids AND process
# names, because enumerate_applications and enumerate_processes disagree
# on which field they fill.
TIKTOK_NAMES = frozenset({
    "com.zhiliaoapp.musically",
    "com.ss.iphone.ugc.Ame",
    "TikTok",
    "Musically",
})

# Processes the poster is allowed to drive with Frida. SpringBoard for
# HID (system event tap, not an app). Photos for PhotoKit (the import is
# the experiment). /var/jb/bin/sh for the one-shot key install.
ALLOWED_FRIDA_TARGETS = frozenset({
    "SpringBoard",
    "com.apple.springboard",
    "Photos",
    "MobileSlideShow",
    "com.apple.mobileslideshow",
    SH,
    "/var/jb/bin/sh",
    "/bin/sh",
})


class PosterError(RuntimeError):
    pass


class InjectionGuard(PosterError):
    """Raised when a call would touch TikTok. This is a hard stop, not a skip."""


def is_tiktok(name: Optional[str], identifier: Optional[str] = None) -> bool:
    for v in (name, identifier):
        if not v:
            continue
        if v in TIKTOK_NAMES:
            return True
        low = v.lower()
        if "tiktok" in low or "zhiliao" in low or "musically" in low:
            return True
    return False


def refuse_tiktok(name: Optional[str], identifier: Optional[str] = None) -> None:
    if is_tiktok(name, identifier):
        raise InjectionGuard(
            "refusing to attach/spawn %r (%r): the poster never enters "
            "TikTok's process. Drive it from SpringBoard HID or SSH."
            % (name, identifier)
        )


def require_allowed_target(name: Optional[str], identifier: Optional[str] = None) -> None:
    refuse_tiktok(name, identifier)
    cand = {n for n in (name, identifier) if n}
    if cand and not (cand & ALLOWED_FRIDA_TARGETS):
        # Absolute paths of the jailbreak shell are allowed by suffix.
        if any(str(n).endswith("/sh") or str(n).endswith("/bash") for n in cand):
            return
        raise InjectionGuard(
            "refusing Frida target %r (%r): not in the allow-list "
            "(SpringBoard, Photos, jailbreak shell). Adding TikTok to "
            "that list is the thing this guard exists to stop."
            % (name, identifier)
        )


def safe_run_name(name: str) -> str:
    """Same two-pass sanitiser run_observe.py uses, so a poster arm and
    an observer run land in the same directory."""
    import re
    safe = re.sub(r"[^A-Za-z0-9._-]+", "-", (name or "").strip()).lstrip(".-")
    if not safe.strip("._-"):
        return "run"
    return safe


# ---------------------------------------------------------------------------
# usbmux. Apple Mobile Device Service on Windows listens on 27015 and
# speaks the same 16-byte header + XML plist as usbmuxd. No iproxy, no
# extra pip package. PortNumber is htons(port) stuffed into a uint32.
# ---------------------------------------------------------------------------

def _mux_pack(msg: dict, tag: int = 1) -> bytes:
    body = plistlib.dumps(msg)
    return struct.pack("<IIII", 16 + len(body), 1, 8, tag) + body


def _mux_read(sock: socket.socket) -> dict:
    hdr = _recv_exact(sock, 16)
    length, _ver, _typ, _tag = struct.unpack("<IIII", hdr)
    body = _recv_exact(sock, length - 16)
    return plistlib.loads(body)


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise PosterError("usbmux: connection closed after %d/%d bytes" % (len(buf), n))
        buf += chunk
    return buf


def usbmux_list_devices(timeout: float = 3.0) -> list[dict]:
    sock = socket.create_connection(USBMUX_ADDR, timeout)
    try:
        sock.sendall(_mux_pack({
            "MessageType": "ListDevices",
            "ClientVersionString": "poster",
            "ProgName": "poster",
        }))
        msg = _mux_read(sock)
    finally:
        sock.close()
    return list(msg.get("DeviceList") or [])


def usbmux_connect(port: int, device_id: Optional[int] = None,
                   timeout: float = 5.0) -> socket.socket:
    devices = usbmux_list_devices(timeout)
    if not devices:
        raise PosterError(
            "usbmux sees no USB iPhone. Unlock it, trust this PC, confirm "
            "Apple Mobile Device Service is running."
        )
    if device_id is None:
        device_id = int(devices[0]["DeviceID"])
    sock = socket.create_connection(USBMUX_ADDR, timeout)
    try:
        sock.sendall(_mux_pack({
            "MessageType": "Connect",
            "ClientVersionString": "poster",
            "ProgName": "poster",
            "DeviceID": device_id,
            "PortNumber": socket.htons(port),
        }))
        result = _mux_read(sock)
    except Exception:
        sock.close()
        raise
    number = result.get("Number", -1)
    if number != 0:
        sock.close()
        raise PosterError("usbmux Connect to device:%d failed (Number=%s)" % (port, number))
    sock.settimeout(None)
    return sock


def probe_ssh_banner(port: int = DEVICE_PORT, timeout: float = 3.0) -> str:
    sock = usbmux_connect(port, timeout=timeout)
    try:
        sock.settimeout(timeout)
        banner = sock.recv(256)
    finally:
        sock.close()
    return banner.decode("utf-8", "replace").split("\r")[0].split("\n")[0]


class UsbTunnel:
    """Host TCP -> usbmux -> device:22. Replaces `iproxy 2222 22`."""

    def __init__(self, host: str = HOST, host_port: int = HOST_PORT,
                 device_port: int = DEVICE_PORT):
        self.host = host
        self.host_port = host_port
        self.device_port = device_port
        self._sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self.connections = 0
        self.errors: list[str] = []

    @property
    def alive(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> "UsbTunnel":
        if self.alive:
            return self
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.host, self.host_port))
        srv.listen(16)
        srv.settimeout(0.4)
        self._sock = srv
        self._stop.clear()
        self._thread = threading.Thread(target=self._serve, name="poster-usbmux", daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        if self._thread is not None:
            self._thread.join(timeout=2)
            self._thread = None

    def __enter__(self) -> "UsbTunnel":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()

    def _serve(self) -> None:
        assert self._sock is not None
        while not self._stop.is_set():
            try:
                client, _addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                if self._stop.is_set():
                    return
                continue
            try:
                device = usbmux_connect(self.device_port)
            except Exception as e:
                self.errors.append(str(e))
                try:
                    client.close()
                except OSError:
                    pass
                continue
            self.connections += 1
            t = threading.Thread(target=self._pipe, args=(client, device), daemon=True)
            t.start()

    @staticmethod
    def _pipe(a: socket.socket, b: socket.socket) -> None:
        try:
            while True:
                readable, _, _ = select.select([a, b], [], [], 60)
                if not readable:
                    continue
                for src in readable:
                    data = src.recv(65536)
                    if not data:
                        return
                    (b if src is a else a).sendall(data)
        except OSError:
            pass
        finally:
            for s in (a, b):
                try:
                    s.close()
                except OSError:
                    pass


# ---------------------------------------------------------------------------
# SSH over the tunnel. Windows OpenSSH translates CRLF on a text stdin, so
# remote scripts are written as files on the phone and then executed.
# ---------------------------------------------------------------------------

def ssh_exe() -> str:
    found = shutil.which("ssh")
    if found:
        return found
    for p in (r"C:\Windows\System32\OpenSSH\ssh.exe",
              r"C:\Program Files\OpenSSH\ssh.exe"):
        if os.path.isfile(p):
            return p
    raise PosterError("OpenSSH client not on PATH")


def scp_exe() -> str:
    found = shutil.which("scp")
    if found:
        return found
    for p in (r"C:\Windows\System32\OpenSSH\scp.exe",
              r"C:\Program Files\OpenSSH\scp.exe"):
        if os.path.isfile(p):
            return p
    raise PosterError("scp not on PATH")


def ssh_keygen_exe() -> str:
    found = shutil.which("ssh-keygen")
    if found:
        return found
    for p in (r"C:\Windows\System32\OpenSSH\ssh-keygen.exe",
              r"C:\Program Files\OpenSSH\ssh-keygen.exe"):
        if os.path.isfile(p):
            return p
    raise PosterError("ssh-keygen not on PATH")


def ssh_base_args(identity: Path = POSTER_KEY, port: int = HOST_PORT,
                  port_flag: str = "-p") -> list[str]:
    # ssh wants -p, scp wants -P. Same options otherwise.
    return [
        "-i", str(identity),
        port_flag, str(port),
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=" + os.devnull,
        "-o", "IdentitiesOnly=yes",
        "-o", "PreferredAuthentications=publickey",
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=8",
    ]


def ssh(remote: str, identity: Path = POSTER_KEY, port: int = HOST_PORT,
        timeout: float = 30, user: str = "root") -> subprocess.CompletedProcess:
    if not identity.is_file():
        raise PosterError("no poster key at %s; run: poster.py setup-ssh" % identity)
    cmd = [ssh_exe(), *ssh_base_args(identity, port, "-p"),
           "%s@%s" % (user, HOST), remote]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def scp_put(local: Path, remote: str, identity: Path = POSTER_KEY,
            port: int = HOST_PORT, user: str = "root",
            timeout: float = 120) -> subprocess.CompletedProcess:
    if not local.is_file():
        raise PosterError("nothing to push: %s" % local)
    dest = "%s@%s:%s" % (user, HOST, remote)
    cmd = [scp_exe(), "-q", *ssh_base_args(identity, port, "-P"), str(local), dest]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def scp_get(remote: str, local: Path, identity: Path = POSTER_KEY,
            port: int = HOST_PORT, user: str = "root",
            timeout: float = 120) -> subprocess.CompletedProcess:
    local = Path(local)
    local.parent.mkdir(parents=True, exist_ok=True)
    src = "%s@%s:%s" % (user, HOST, remote)
    cmd = [scp_exe(), "-q", *ssh_base_args(identity, port, "-P"), src, str(local)]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def ensure_key(identity: Path = POSTER_KEY) -> Path:
    identity.parent.mkdir(parents=True, exist_ok=True)
    if identity.is_file() and identity.with_suffix(identity.suffix + ".pub").is_file():
        return identity
    pub = identity.with_name(identity.name + ".pub")
    # empty passphrase: this key only ever talks to 127.0.0.1 over USB.
    r = subprocess.run(
        [ssh_keygen_exe(), "-t", "ed25519", "-f", str(identity),
         "-N", "", "-C", "tiktok-audit-poster"],
        capture_output=True, text=True,
    )
    if r.returncode != 0 or not identity.is_file():
        raise PosterError("ssh-keygen failed: %s" % (r.stderr or r.stdout))
    if not pub.is_file():
        # some builds write identity.pub rather than identity + .pub
        alt = Path(str(identity) + ".pub")
        if not alt.is_file():
            raise PosterError("ssh-keygen wrote no .pub")
    return identity


def public_key_text(identity: Path = POSTER_KEY) -> str:
    pub = Path(str(identity) + ".pub")
    if not pub.is_file():
        pub = identity.with_suffix(identity.suffix + ".pub")
    return pub.read_text(encoding="ascii").strip() + "\n"


# ---------------------------------------------------------------------------
# One-shot Frida bootstrap. Spawns the jailbreak shell as root, never TikTok.
# Used to drop authorized_keys and lock sshd_config. After that, SSH is the
# channel and this path is idle.
# ---------------------------------------------------------------------------

_WRITE_JS = r"""
'use strict';
function writeFile(p, text){
  var open_ = new NativeFunction(Module.getGlobalExportByName('open'), 'int', ['pointer','int','int']);
  var write_ = new NativeFunction(Module.getGlobalExportByName('write'), 'long', ['int','pointer','ulong']);
  var close_ = new NativeFunction(Module.getGlobalExportByName('close'), 'int', ['int']);
  var mkdir_ = new NativeFunction(Module.getGlobalExportByName('mkdir'), 'int', ['pointer','int']);
  mkdir_(Memory.allocUtf8String('/var/mobile/Media/poster-inbox'), 493);
  var fd = open_(Memory.allocUtf8String(p), 1|0x200|0x400, 420);
  if (fd < 0) return 'open-fail';
  var n = Number(write_(fd, Memory.allocUtf8String(text), text.length));
  close_(fd);
  return 'wrote '+n;
}
function readFile(p){
  var open_ = new NativeFunction(Module.getGlobalExportByName('open'), 'int', ['pointer','int']);
  var read_ = new NativeFunction(Module.getGlobalExportByName('read'), 'long', ['int','pointer','ulong']);
  var close_ = new NativeFunction(Module.getGlobalExportByName('close'), 'int', ['int']);
  var fd = open_(Memory.allocUtf8String(p), 0);
  if (fd < 0) return null;
  var chunks = []; var buf = Memory.alloc(4096);
  while (true) {
    var n = Number(read_(fd, buf, 4096));
    if (n <= 0) break;
    chunks.push(buf.readUtf8String(n));
  }
  close_(fd);
  return chunks.join('');
}
function exists(p){
  var a = new NativeFunction(Module.getGlobalExportByName('access'), 'int', ['pointer','int']);
  return a(Memory.allocUtf8String(p), 0) === 0;
}
rpc.exports = { writefile: writeFile, readfile: readFile, exists: exists };
"""


def _frida_device():
    import frida
    return frida.get_usb_device(timeout=8)


def springboard_rpc(fn: Callable):
    """Attach to SpringBoard (not TikTok), run fn(api), detach."""
    import frida
    dev = _frida_device()
    proc = next((p for p in dev.enumerate_processes() if p.name == "SpringBoard"), None)
    if proc is None:
        raise PosterError("SpringBoard is not running")
    require_allowed_target(proc.name)
    session = dev.attach(proc.pid)
    try:
        script = session.create_script(_WRITE_JS)
        script.load()
        return fn(script.exports_sync)
    finally:
        try:
            session.detach()
        except Exception:
            pass


def write_inbox(name: str, text: str) -> str:
    """Write a *new* filename under poster-inbox. Overwrite of an existing
    file from SpringBoard is flaky on this phone (open() returns EPERM
    once the file has been executed as root); callers use a fresh name."""
    path = "%s/%s" % (INBOX, name)
    result = springboard_rpc(lambda api: api.writefile(path, text))
    if not str(result).startswith("wrote"):
        raise PosterError("SpringBoard could not write %s: %s" % (path, result))
    return path


def read_inbox(name: str) -> Optional[str]:
    path = "%s/%s" % (INBOX, name)
    return springboard_rpc(lambda api: api.readfile(path))


def spawn_root_script(path: str, wait: float = 2.5) -> None:
    """frida-server is root, so a spawn of the jailbreak shell is root.
    That is the one permitted use of Frida as a control channel, and it
    is a spawn of sh, not of TikTok."""
    require_allowed_target(SH)
    refuse_tiktok(path)
    dev = _frida_device()
    pid = dev.spawn(SH, argv=[SH, path])
    dev.resume(pid)
    time.sleep(wait)


SSHD_CONFIG_LOCKED = "\n".join([
    "# OpenSSH_9.7 on palera1n rootless. Written by the poster for key-only.",
    "# Package original saved next to this file as sshd_config.bak-poster.",
    "# dropbear on :44 is the emergency hatch; this file does not touch it.",
    "PermitRootLogin prohibit-password",
    "PubkeyAuthentication yes",
    "AuthorizedKeysFile .ssh/authorized_keys",
    "PasswordAuthentication no",
    "KbdInteractiveAuthentication no",
    "ChallengeResponseAuthentication no",
    "PermitEmptyPasswords no",
    "UsePAM yes",
    "UsePrivilegeSeparation no",
    "Subsystem sftp /var/jb/usr/libexec/sftp-server",
    "",
])


def _install_script(pub: str, stamp: str) -> str:
    # PATH is empty on a raw spawn. Everything is absolute.
    homes = [JB_ROOT_HOME, JB_MOBILE_HOME, IOS_ROOT_HOME, IOS_MOBILE_HOME]
    lines = [
        "#!/var/jb/bin/sh",
        PATH_EXPORT,
        "exec > %s/bootstrap-%s.log 2>&1" % (INBOX, stamp),
        "set -e",
        "echo start",
        "/var/jb/usr/bin/id",
        "PUB=%s/poster-%s.pub" % (INBOX, stamp),
        "CFGNEW=%s/sshd-%s.conf" % (INBOX, stamp),
    ]
    for h in homes:
        lines += [
            "/var/jb/usr/bin/mkdir -p %s/.ssh" % h,
            "/var/jb/usr/bin/cp \"$PUB\" %s/.ssh/authorized_keys" % h,
            "/var/jb/usr/bin/chmod 700 %s/.ssh" % h,
            "/var/jb/usr/bin/chmod 600 %s/.ssh/authorized_keys" % h,
        ]
    lines += [
        "/var/jb/usr/bin/chown 501:501 %s/.ssh %s/.ssh/authorized_keys" % (
            JB_MOBILE_HOME, JB_MOBILE_HOME),
        "/var/jb/usr/bin/chown 501:501 %s/.ssh %s/.ssh/authorized_keys" % (
            IOS_MOBILE_HOME, IOS_MOBILE_HOME),
        "if [ -f %s ] && [ ! -f %s.bak-poster ]; then /var/jb/usr/bin/cp -a %s %s.bak-poster; fi" % (
            SSHD_CONFIG, SSHD_CONFIG, SSHD_CONFIG, SSHD_CONFIG),
        "/var/jb/usr/bin/cp \"$CFGNEW\" %s" % SSHD_CONFIG,
        "echo --- homes ---",
        "/var/jb/usr/bin/ls -la %s/.ssh %s/.ssh" % (JB_ROOT_HOME, JB_MOBILE_HOME),
        "echo --- sshd ---",
        "/var/jb/usr/bin/grep -n -E 'PermitRootLogin|PasswordAuthentication|KbdInteractive|PubkeyAuthentication' %s" % SSHD_CONFIG,
        "echo DONE",
        "",
    ]
    return "\n".join(lines)


@dataclass
class SetupReport:
    key: str = ""
    banner_22: str = ""
    banner_2222: str = ""
    banner_44: str = ""
    bootstrap_log: str = ""
    ssh_id: str = ""
    ssh_ok: bool = False
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "key": self.key,
            "banner_22": self.banner_22,
            "banner_2222": self.banner_2222,
            "banner_44": self.banner_44,
            "bootstrap_log": self.bootstrap_log,
            "ssh_id": self.ssh_id,
            "ssh_ok": self.ssh_ok,
            "notes": list(self.notes),
        }


def setup_ssh(tunnel: Optional[UsbTunnel] = None) -> SetupReport:
    """Generate the poster key if needed, install it into every home
    sshd will look at, lock sshd_config, open the USB tunnel, prove
    key-only login works."""
    report = SetupReport()
    ensure_key()
    pub = public_key_text()
    report.key = pub.strip()

    for port, attr in ((22, "banner_22"), (2222, "banner_2222"), (44, "banner_44")):
        try:
            setattr(report, attr, probe_ssh_banner(port))
        except Exception as e:
            setattr(report, attr, "closed (%s)" % e)

    if "OpenSSH" not in report.banner_22 and "OpenSSH" not in report.banner_2222:
        report.notes.append(
            "OpenSSH is packaged (plist at %s) but neither :22 nor :2222 "
            "answered. The jailbreak loader may not have bootstrapped the "
            "LaunchDaemon this boot. dropbear on :44 is %s."
            % (SSHD_PLIST, report.banner_44 or "also closed")
        )

    stamp = time.strftime("%H%M%S")
    write_inbox("poster-%s.pub" % stamp, pub)
    write_inbox("sshd-%s.conf" % stamp, SSHD_CONFIG_LOCKED)
    script_path = write_inbox("bootstrap-%s.sh" % stamp, _install_script(pub, stamp))
    spawn_root_script(script_path, wait=3.0)
    report.bootstrap_log = read_inbox("bootstrap-%s.log" % stamp) or ""
    if "DONE" not in report.bootstrap_log:
        raise PosterError("bootstrap script did not finish:\n%s" % report.bootstrap_log)

    own = tunnel is None
    tun = tunnel or UsbTunnel()
    if not tun.alive:
        tun.start()
    try:
        r = ssh("id; echo HOME=$HOME")
        report.ssh_id = (r.stdout or "").strip()
        report.ssh_ok = r.returncode == 0 and "uid=0" in r.stdout
        if not report.ssh_ok:
            raise PosterError(
                "key installed but ssh still failed (%s):\n%s\n%s"
                % (r.returncode, r.stdout, r.stderr)
            )
    finally:
        if own:
            # leave the tunnel up only if the caller owns it; setup-ssh
            # as a CLI command starts one and keeps it in the process.
            pass

    report.notes.append(
        "sshd is socket-activated. A missing sshd process is not a "
        "missing server. Persistence across a semi-tethered reboot is "
        "the LaunchDaemon at %s being loaded when /var/jb remounts; "
        "this setup does not reboot to prove that." % SSHD_PLIST
    )
    report.notes.append(
        "dropbear on :44 is palera1n's hatch and was left alone."
    )
    return report


def uiopen_bundle(bundle_id: str, allow_tiktok: bool = False) -> None:
    """Foreground an app by bundle id over SSH. This is a launch, not
    a Frida attach. TikTok is refused by default so a stray call cannot
    couple the observer; pass allow_tiktok=True when the job is to
    open the app like a user would."""
    if not allow_tiktok:
        refuse_tiktok(bundle_id, bundle_id)
    r = ssh("uiopen --bundleid %s" % bundle_id)
    if r.returncode != 0:
        raise PosterError("uiopen %s failed: %s" % (bundle_id, r.stderr or r.stdout))


def ssh_preflight(tunnel: Optional[UsbTunnel] = None) -> dict:
    out = {
        "usbmux_devices": [],
        "banner_22": None,
        "banner_2222": None,
        "banner_44": None,
        "tunnel": False,
        "ssh": None,
        "key": POSTER_KEY.is_file(),
        "errors": [],
    }
    try:
        out["usbmux_devices"] = [
            {
                "id": d.get("DeviceID"),
                "udid": (d.get("Properties") or {}).get("SerialNumber"),
            }
            for d in usbmux_list_devices()
        ]
    except Exception as e:
        out["errors"].append("usbmux: %s" % e)
        return out
    for port, key in ((22, "banner_22"), (2222, "banner_2222"), (44, "banner_44")):
        try:
            out[key] = probe_ssh_banner(port)
        except Exception as e:
            out[key] = "closed (%s)" % e
    if tunnel is not None:
        out["tunnel"] = tunnel.alive
    if POSTER_KEY.is_file() and (tunnel is None or tunnel.alive):
        try:
            r = ssh("id; echo HOME=$HOME")
            out["ssh"] = {
                "ok": r.returncode == 0,
                "stdout": (r.stdout or "").strip(),
                "stderr": (r.stderr or "").strip(),
            }
        except Exception as e:
            out["errors"].append("ssh: %s" % e)
    return out
