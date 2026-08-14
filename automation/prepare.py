"""
Build the six-arm files from what you can actually drop.

You owe two originals the laptop cannot invent:

  testfiles/01-native.mov     a clip this iPhone X shot (AirDrop/USB, not re-saved)
  testfiles/03-scraped.mov    something that did not come from this phone

This script then derives the rest with ffmpeg + exiftool, which are
already on this machine:

  02-stripped          01 with provenance Keys/GPS/EXIF removed
  04-scraped-stamped   03 wearing 01's Make/Model/GPS/CreationDate
  05-generated         synthetic lavfi clip, no Apple tags
  06-generated-stamped 05 wearing the same native stamp

An imported 01-native is still an import. This does not produce a
camera-original PHAsset.sourceType. It produces the file arms.

    python automation/poster.py prepare-arms
    python automation/poster.py prepare-arms --check
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Optional

from .device import PosterError, ROOT

TESTFILES = ROOT / "testfiles"

# The Keys: block a native iPhone MOV carries. Matches the fixture the
# rig already knows how to name. Stamping writes these; stripping deletes
# them. EXIF/GPS come along for stills.
NATIVE_STAMP = {
    "Keys:Make": "Apple",
    "Keys:Model": "iPhone X",
    "Keys:Software": "16.7.16",
    "Keys:CreationDate": "2026:08:11 14:02:31+03:00",
    "Keys:LocationISO6709": "+54.6872+025.2797+096.500/",
    "Make": "Apple",
    "Model": "iPhone X",
    "Software": "16.7.16",
    "GPSLatitude": "54.6872",
    "GPSLatitudeRef": "N",
    "GPSLongitude": "25.2797",
    "GPSLongitudeRef": "E",
}

STRIP_ARGS = [
    "-Keys:all=",
    "-UserData:all=",
    "-ItemList:all=",
    "-GPS:all=",
    "-EXIF:all=",
    "-XMP:all=",
    "-MakerNotes:all=",
    "-QuickTime:Make=",
    "-QuickTime:Model=",
    "-QuickTime:Software=",
    "-QuickTime:GPSCoordinates=",
]


def _which(name: str) -> Optional[str]:
    return shutil.which(name)


def require_tools() -> None:
    missing = [n for n in ("ffmpeg", "exiftool") if not _which(n)]
    if missing:
        raise PosterError("prepare-arms needs %s on PATH" % " and ".join(missing))


def arm_path(name: str) -> Path:
    return TESTFILES / name


def existing_arms() -> dict[str, Optional[Path]]:
    names = {
        "01-native": ("01-native.mov", "01-native.MOV", "01-native.mp4",
                      "01-native.jpg", "01-native.heic"),
        "02-stripped": ("02-stripped.mov", "02-stripped.jpg"),
        "03-scraped": ("03-scraped.mov", "03-scraped.mp4", "03-scraped.jpg"),
        "04-scraped-stamped": ("04-scraped-stamped.mov", "04-scraped-stamped.jpg"),
        "05-generated": ("05-generated.mov",),
        "06-generated-stamped": ("06-generated-stamped.mov",),
    }
    out = {}
    for arm, cands in names.items():
        hit = next((TESTFILES / n for n in cands if (TESTFILES / n).is_file()), None)
        out[arm] = hit
    return out


def run(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True)


def generate_mov(dest: Path, seconds: float = 1.0) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        "ffmpeg", "-y", "-hide_banner", "-loglevel", "error",
        "-f", "lavfi", "-i", "testsrc2=duration=%s:size=720x1280:rate=24" % seconds,
        "-f", "lavfi", "-i", "anullsrc=r=44100:cl=stereo",
        "-c:v", "libx264", "-pix_fmt", "yuv420p", "-t", str(seconds),
        "-c:a", "aac", "-shortest", str(dest),
    ]
    r = run(cmd)
    if r.returncode != 0 or not dest.is_file():
        raise PosterError("ffmpeg failed to write %s:\n%s" % (dest, r.stderr))
    return dest


def copy_to(src: Path, dest: Path) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dest)
    return dest


def strip_file(src: Path, dest: Path) -> Path:
    copy_to(src, dest)
    r = run(["exiftool", "-overwrite_original", "-q"] + STRIP_ARGS + [str(dest)])
    if r.returncode != 0:
        raise PosterError("exiftool strip failed on %s:\n%s" % (dest, r.stderr))
    return dest


def stamp_file(src: Path, dest: Path, stamp: Optional[dict] = None) -> Path:
    copy_to(src, dest)
    stamp = stamp or dict(NATIVE_STAMP)
    args = ["exiftool", "-overwrite_original", "-q"]
    for k, v in stamp.items():
        args.append("-%s=%s" % (k, v))
    args.append(str(dest))
    r = run(args)
    if r.returncode != 0:
        raise PosterError("exiftool stamp failed on %s:\n%s" % (dest, r.stderr))
    return dest


def stamp_from_native(native: Path) -> dict:
    """Prefer the real file's Make/Model/GPS over the canned iPhone X set."""
    r = run(["exiftool", "-a", "-G1", "-s", "-j", "-n", str(native)])
    if r.returncode != 0 or not r.stdout.strip():
        return dict(NATIVE_STAMP)
    try:
        raw = json.loads(r.stdout)[0]
    except (json.JSONDecodeError, IndexError):
        return dict(NATIVE_STAMP)
    out = dict(NATIVE_STAMP)
    for key in NATIVE_STAMP:
        if key in raw and raw[key] not in (None, ""):
            out[key] = raw[key]
    return out


def prepare(testfiles: Path = TESTFILES) -> dict:
    """Derive whatever we can. Never overwrite 01-native or 03-scraped."""
    global TESTFILES
    TESTFILES = testfiles
    require_tools()
    testfiles.mkdir(parents=True, exist_ok=True)
    have = existing_arms()
    did = []
    skipped = []
    need_you = []

    if not have["01-native"]:
        need_you.append("drop a this-phone capture at testfiles/01-native.mov")
    else:
        dest = testfiles / "02-stripped.mov"
        strip_file(have["01-native"], dest)
        did.append("02-stripped.mov  from %s" % have["01-native"].name)

    if not have["03-scraped"]:
        need_you.append("drop a not-this-phone clip at testfiles/03-scraped.mov")
    elif have["01-native"]:
        dest = testfiles / "04-scraped-stamped.mov"
        stamp_file(have["03-scraped"], dest, stamp_from_native(have["01-native"]))
        did.append("04-scraped-stamped.mov  from %s" % have["03-scraped"].name)
    else:
        skipped.append("04-scraped-stamped  (need 01-native to copy stamps from)")

    gen = testfiles / "05-generated.mov"
    generate_mov(gen)
    did.append("05-generated.mov  synthetic (no Apple tags)")
    stamp_src = have["01-native"]
    stamp = stamp_from_native(stamp_src) if stamp_src else dict(NATIVE_STAMP)
    stamp_file(gen, testfiles / "06-generated-stamped.mov", stamp)
    did.append("06-generated-stamped.mov  05 + %s stamp" % (
        "01-native" if stamp_src else "canned iPhone X"))

    return {
        "did": did,
        "need_you": need_you,
        "skipped": skipped,
        "have": {k: (str(v) if v else None) for k, v in existing_arms().items()},
    }


def check(testfiles: Path = TESTFILES) -> dict:
    global TESTFILES
    TESTFILES = testfiles
    have = existing_arms()
    return {
        "tools": {"ffmpeg": bool(_which("ffmpeg")), "exiftool": bool(_which("exiftool"))},
        "have": {k: (str(v) if v else None) for k, v in have.items()},
        "need_you": [
            n for n, p in (
                ("testfiles/01-native.mov  (this iPhone shot it)", have["01-native"]),
                ("testfiles/03-scraped.mov (not this phone)", have["03-scraped"]),
            ) if p is None
        ],
    }
