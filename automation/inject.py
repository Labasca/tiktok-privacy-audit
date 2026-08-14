"""
Out-of-process actuators: HID via SpringBoard, PhotoKit via Photos.app.

Neither of these attaches to TikTok. The observer already running against
TikTok is the other half of the experiment; sharing a Frida session with
it would put the control plane inside the process whose injection sweep
we are trying not to trip.

HID prefers ZXTouch (pccontrol.dylib in SpringBoard, TCP 6000) because
late Frida IOHID clients are accepted and then ignored by the glass.
ZXTouch is still out-of-process: it is injected into SpringBoard only.
appdelegate.dylib's UIKit-wide filter is rewritten to SpringBoard so
nothing from this package is loaded into TikTok. The Frida IOHID path
in hid_inject.js remains as a fallback when port 6000 is down.

PhotoKit is PHAssetCreationRequest against original bytes. The DCIM drop
is the thing this replaces: the indexer is free to rewrite the file, and
a rewrite would collapse the stamping matrix.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Optional

from .device import (
    HERE,
    INBOX,
    PosterError,
    refuse_tiktok,
    require_allowed_target,
    scp_put,
    ssh,
    uiopen_bundle,
)

PHONE = HERE / "phone"
HID_JS = PHONE / "hid_inject.js"
IMPORT_JS = PHONE / "import_photokit.js"
IMPORT_COMPILED = PHONE / "import_photokit.compiled.js"
SCREEN_JS = PHONE / "screen.js"
SCREEN_COMPILED = PHONE / "screen.compiled.js"
CACHE = HERE / ".cache"

PHOTOS_BUNDLE = "com.apple.mobileslideshow"
PHOTOS_NAMES = frozenset({"Photos", "MobileSlideShow", PHOTOS_BUNDLE})
SPRINGBOARD_NAMES = frozenset({"SpringBoard", "com.apple.springboard"})

VIDEO_EXT = {".mov", ".mp4", ".m4v", ".3gp", ".avi"}


def _frida():
    import frida
    return frida


def _device():
    return _frida().get_usb_device(timeout=8)


def _compile_import() -> Path:
    """frida-compile inlines frida-objc-bridge. Photos import needs ObjC;
    HID does not, and is loaded as raw JS on purpose."""
    if IMPORT_COMPILED.is_file() and IMPORT_JS.is_file():
        if IMPORT_COMPILED.stat().st_mtime >= IMPORT_JS.stat().st_mtime:
            return IMPORT_COMPILED
    compiler = shutil.which("frida-compile")
    if compiler is None:
        compiler = str(HERE.parent / ".venv" / "Scripts" / "frida-compile.exe")
        if os.name != "nt":
            compiler = str(HERE.parent / ".venv" / "bin" / "frida-compile")
    if not os.path.isfile(compiler):
        raise PosterError(
            "import_photokit.js needs frida-compile (frida-objc-bridge). "
            "The compiled bundle is missing and %s is not on disk." % compiler
        )
    IMPORT_COMPILED.parent.mkdir(parents=True, exist_ok=True)
    r = subprocess.run(
        [compiler, str(IMPORT_JS), "-o", str(IMPORT_COMPILED)],
        capture_output=True, text=True,
    )
    if r.returncode != 0 or not IMPORT_COMPILED.is_file():
        raise PosterError("frida-compile failed on import_photokit.js:\n%s" % r.stderr)
    return IMPORT_COMPILED


class _Session:
    def __init__(self, target_name: str, script_source: str,
                 identifier: Optional[str] = None, prefer_spawn: bool = False):
        refuse_tiktok(target_name, identifier)
        require_allowed_target(target_name, identifier)
        self.dev = _device()
        self.session = None
        self.script = None
        self.api = None
        self.pid = None
        self.spawned = False
        self.target_name = target_name
        self.identifier = identifier
        self._attach(target_name, identifier, script_source, prefer_spawn)

    def _attach(self, name: str, identifier: Optional[str], source: str,
                prefer_spawn: bool) -> None:
        pid = None
        # Photos.app's already-running instance on this phone does not
        # accept attach (Frida times out). SpringBoard does. Spawn is
        # therefore the Photos path; attach is the SpringBoard path.
        if prefer_spawn and identifier:
            refuse_tiktok(name, identifier)
            require_allowed_target(name, identifier)
            pid = self.dev.spawn([identifier])
            self.spawned = True
            self.pid = pid
            self.session = self.dev.attach(pid)
            self.dev.resume(pid)
            time.sleep(3.0)
        else:
            for p in self.dev.enumerate_processes():
                if p.name == name or (identifier and p.name == identifier):
                    refuse_tiktok(p.name)
                    pid = p.pid
                    break
            if pid is None and identifier:
                app = next((a for a in self.dev.enumerate_applications()
                            if a.identifier == identifier), None)
                if app is not None:
                    refuse_tiktok(app.name, app.identifier)
                    if app.pid:
                        pid = app.pid
                    else:
                        require_allowed_target(app.name, app.identifier)
                        pid = self.dev.spawn([identifier])
                        self.spawned = True
            if pid is None:
                raise PosterError("%s is not running and could not be spawned" % name)
            self.pid = pid
            self.session = self.dev.attach(pid)
            if self.spawned:
                self.dev.resume(pid)
                time.sleep(3.0)
        self.script = self.session.create_script(source)
        self.script.load()
        self.api = self.script.exports_sync

    def close(self) -> None:
        try:
            if self.script is not None:
                self.script.unload()
        except Exception:
            pass
        try:
            if self.session is not None:
                self.session.detach()
        except Exception:
            pass
        # Never kill SpringBoard. Photos we spawned can be left; killing it
        # is a Photos crash report for no gain.
        self.script = None
        self.session = None
        self.api = None

    def __enter__(self) -> "_Session":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


def springboard_hid() -> _Session:
    src = HID_JS.read_text(encoding="utf-8")
    return _Session("SpringBoard", src)


def backboard_hid() -> _Session:
    src = HID_JS.read_text(encoding="utf-8")
    return _Session("backboardd", src)


def photos_import() -> _Session:
    compiled = _compile_import()
    src = compiled.read_text(encoding="utf-8")
    # Background Photos refuses attach (timeout). Spawned Photos has no
    # running main queue. uiopen brings the real app forward; then attach
    # works. Measured this session.
    uiopen_bundle(PHOTOS_BUNDLE)
    time.sleep(2.0)
    return _Session("Photos", src, identifier=PHOTOS_BUNDLE, prefer_spawn=False)


def hid_ping() -> dict:
    from .touch import ping as zxtouch_ping
    z = zxtouch_ping()
    if z.get("ok"):
        return z
    with springboard_hid() as s:
        rec = dict(s.api.ping())
        rec["via"] = "frida-iohid"
        rec["zxtouch"] = z
        return rec


def plant_digitizer_sender() -> dict:
    """pccontrol comes up with senderID 0 after a respring. Events
    are accepted on :6000 and ignored by the glass until this is a
    real SPI digitizer registry id. Do not dlopen+init pccontrol —
    that crashes SpringBoard into ElleKit safe mode."""
    src = (PHONE / "seed_sender.js").read_text(encoding="utf-8")
    with _Session("SpringBoard", src) as s:
        rec = dict(s.api.discover())
        rec.pop("services", None)
        return rec


def wake_and_unlock() -> dict:
    """Turn the backlight on and dismiss the lock screen. SpringBoard
    only. A respring leaves the panel black; _UICreateScreenUIImage
    then returns a stale 52KB frame."""
    compiled = _compile_js(PHONE / "undim.js", PHONE / "undim.compiled.js")
    src = compiled.read_text(encoding="utf-8")
    with _Session("SpringBoard", src) as s:
        rec = dict(s.api.undim())
    time.sleep(1.5)
    return rec


def _compile_js(src: Path, dest: Path) -> Path:
    if dest.is_file() and src.is_file() and dest.stat().st_mtime >= src.stat().st_mtime:
        return dest
    compiler = shutil.which("frida-compile")
    if compiler is None:
        compiler = str(HERE.parent / ".venv" / "Scripts" / "frida-compile.exe")
        if os.name != "nt":
            compiler = str(HERE.parent / ".venv" / "bin" / "frida-compile")
    if not os.path.isfile(compiler):
        if dest.is_file():
            return dest
        raise PosterError("frida-compile missing and %s is not built" % dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    r = subprocess.run([compiler, str(src), "-o", str(dest)],
                       capture_output=True, text=True)
    if r.returncode != 0 or not dest.is_file():
        raise PosterError("frida-compile failed on %s:\n%s" % (src, r.stderr))
    return dest


def screenshot(dest: Optional[Path] = None) -> Path:
    """Full display PNG via SpringBoard. The frontmost app is in the
    picture; we never attached to it."""
    dest = dest or (CACHE / "screen.png")
    dest.parent.mkdir(parents=True, exist_ok=True)
    compiled = _compile_js(SCREEN_JS, SCREEN_COMPILED)
    src = compiled.read_text(encoding="utf-8")
    blob = {"png": None}

    with _Session("SpringBoard", src) as s:
        def on_message(message, data):
            if message.get("type") == "send" and data:
                blob["png"] = bytes(data)

        s.script.on("message", on_message)
        rec = dict(s.api.snapshot())
        # send() may land just after the rpc return
        t0 = time.time()
        while blob["png"] is None and time.time() - t0 < 4:
            time.sleep(0.05)
    if blob["png"] is None:
        raise PosterError("screenshot produced no PNG (%s)" % rec)
    dest.write_bytes(blob["png"])
    return dest


def points_to_norm(x: float, y: float, logical: tuple[float, float]) -> tuple[float, float]:
    w, h = logical
    if w <= 0 or h <= 0:
        raise PosterError("logical size must be positive")
    # Values already in 0-1 are left alone so a calibrated file can speak
    # either language. A tap at point (0.4, 0.8) on a 375-wide phone is
    # not a real layout coordinate, so the heuristic is safe in practice.
    if 0.0 <= x <= 1.0 and 0.0 <= y <= 1.0:
        return x, y
    return max(0.0, min(1.0, x / w)), max(0.0, min(1.0, y / h))


DEFAULT_HID_OPTS = {
    "major": 0.008,
    "minor": 0.007,
    "pressure": 0.55,
    "samples": 3,
    "hold_ms": 70,
}


def hid_tap(x: float, y: float, logical: tuple[float, float] = (375.0, 812.0),
            space: str = "norm", **opts) -> dict:
    from .touch import probe_zxtouch, zxtouch_tap
    if probe_zxtouch():
        return zxtouch_tap(
            x, y, logical, space=space,
            hold_ms=int(opts.get("hold_ms") or DEFAULT_HID_OPTS["hold_ms"]),
        )
    if space == "points":
        nx, ny = float(x), float(y)
    elif space == "pixels":
        scale = 3.0
        nx, ny = float(x) * scale, float(y) * scale
    else:
        nx, ny = points_to_norm(x, y, logical)
    payload = dict(DEFAULT_HID_OPTS)
    payload.update({k: v for k, v in opts.items() if v is not None})
    with springboard_hid() as s:
        rec = dict(s.api.tap(nx, ny, payload))
        rec["space"] = space
        rec["sent_xy"] = [nx, ny]
        rec["via"] = "frida-iohid"
        return rec


def hid_swipe(x1: float, y1: float, x2: float, y2: float,
              logical: tuple[float, float] = (375.0, 812.0),
              **opts) -> dict:
    from .touch import probe_zxtouch, zxtouch_swipe
    if probe_zxtouch():
        return zxtouch_swipe(x1, y1, x2, y2, logical, space="norm",
                             ms=int(opts.get("ms") or 280))
    a = points_to_norm(x1, y1, logical)
    b = points_to_norm(x2, y2, logical)
    payload = dict(DEFAULT_HID_OPTS)
    payload.update({k: v for k, v in opts.items() if v is not None})
    with springboard_hid() as s:
        rec = dict(s.api.swipe(a[0], a[1], b[0], b[1], payload))
        rec["via"] = "frida-iohid"
        return rec


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def guess_kind(path: Path) -> str:
    return "video" if path.suffix.lower() in VIDEO_EXT else "photo"


def push_and_import(local: Path, kind: Optional[str] = None,
                    remote_name: Optional[str] = None) -> dict:
    """SCP the file to poster-inbox, then PhotoKit-import it from Photos.app.

    Returns the measurement the stamping work actually needs: source
    hash/size, the PHAsset localIdentifier, and whatever Photos reports
    for the stored resource. Equal fileSize is evidence the bytes
    survived. Unequal fileSize is the finding, not a failure of this
    function.
    """
    local = Path(local)
    if not local.is_file():
        raise PosterError("no such file: %s" % local)
    kind = kind or guess_kind(local)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    remote_name = remote_name or ("%s-%s" % (stamp, local.name))
    remote = "%s/%s" % (INBOX, remote_name)
    # inbox has to exist; mkdir via ssh (standing channel) not Frida
    mk = ssh("export PATH=/var/jb/usr/bin:/var/jb/bin:/usr/bin:/bin; mkdir -p %s" % INBOX)
    if mk.returncode != 0:
        raise PosterError("mkdir inbox failed: %s" % (mk.stderr or mk.stdout))
    put = scp_put(local, remote)
    if put.returncode != 0:
        raise PosterError("scp failed: %s" % (put.stderr or put.stdout))
    source = {
        "path": str(local.resolve()),
        "remote": remote,
        "bytes": local.stat().st_size,
        "sha256": sha256_file(local),
        "kind": kind,
        "name": local.name,
    }
    dcim_before = _dcim_listing()
    with photos_import() as s:
        ping = dict(s.api.ping())
        imported = dict(s.api.import_file(remote, kind))
    # UIKit save is async. Give the indexer a moment, then look at DCIM.
    stored = None
    for _ in range(12):
        time.sleep(0.5)
        stored = _dcim_new_file(dcim_before)
        if stored:
            break
    if stored:
        imported["stored"] = stored
        imported["bytes_match"] = (
            stored.get("bytes") == source["bytes"]
            if stored.get("bytes") is not None else None
        )
    return {
        "source": source,
        "import": imported,
        "photos_ping": ping,
        "dcim_before_count": len(dcim_before),
        "bytes_match": (imported.get("bytes_match")
                        if "bytes_match" in imported
                        else _bytes_match(source, imported)),
    }


def _dcim_listing() -> dict[str, int]:
    """path -> size for every file under DCIM. SSH, not PhotoKit: fetch
    APIs terminate Photos.app on this build."""
    r = ssh(
        "export PATH=/var/jb/usr/bin:/var/jb/bin:/usr/bin:/bin; "
        "find /var/mobile/Media/DCIM -type f -printf '%s %p\\n' 2>/dev/null"
    )
    out: dict[str, int] = {}
    if r.returncode != 0:
        return out
    for line in (r.stdout or "").splitlines():
        parts = line.strip().split(" ", 1)
        if len(parts) != 2:
            continue
        try:
            out[parts[1]] = int(parts[0])
        except ValueError:
            continue
    return out


def _dcim_new_file(before: dict[str, int]) -> Optional[dict]:
    after = _dcim_listing()
    new_paths = [p for p in after if p not in before]
    if not new_paths:
        # a rewrite of an existing file: size change
        changed = [p for p, n in after.items() if before.get(p) != n]
        if not changed:
            return None
        new_paths = changed
    # newest by name; Apple DCIM names are sortable
    path = sorted(new_paths)[-1]
    rec = {"path": path, "bytes": after[path]}
    hashed = ssh(
        "export PATH=/var/jb/usr/bin:/var/jb/bin:/usr/bin:/bin; "
        "sha256sum %s" % path
    )
    if hashed.returncode == 0 and hashed.stdout:
        rec["sha256"] = hashed.stdout.split()[0]
    return rec


def _bytes_match(source: dict, imported: dict) -> Optional[bool]:
    measure = imported.get("measure") or {}
    sizes = [r.get("fileSize") for r in measure.get("resources") or [] if r.get("fileSize")]
    if not sizes:
        return None
    return any(int(s) == int(source["bytes"]) for s in sizes)


def write_import_record(record: dict, dest: Path) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return dest
