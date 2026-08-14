#!/usr/bin/env python3
"""Build one visually unique clip with searchable canary stamps.

These strings are deliberately not Apple/iPhone/this-phone-GPS so a hit
in tags.json cannot be confused with gestalt or the real camera file.
GPS uses Keys:GPSCoordinates (QuickTime mdta). XMP-only GPS is ignored
by TikTok — unique-2-stamped already proved that.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
from automation.prepare import stamp_file  # noqa: E402

_WIN = Path(r"C:\Windows\Fonts\arialbd.ttf")
if not _WIN.is_file():
    _WIN = Path(r"C:\Windows\Fonts\arial.ttf")
FONT = HERE / "arialbd.ttf"
if _WIN.is_file() and not FONT.is_file():
    shutil.copy2(_WIN, FONT)

# Unique, grep-able. 11.1111/22.2222 is not Vilnius (54.63/24.93).
CANARY_ID = "7F3A"
CANARIES = {
    "id": CANARY_ID,
    "make": "CANARYMK-%s" % CANARY_ID,
    "model": "CANARYMD-%s" % CANARY_ID,
    "software": "CANARYSW-%s" % CANARY_ID,
    "title": "CANARY-TITLE-%s" % CANARY_ID,
    "comment": "CANARY-CMT-%s" % CANARY_ID,
    "created": "2025:01:02 03:04:05+00:00",
    "gps_lat": "11.1111",
    "gps_lon": "22.2222",
    "gps_alt": "33.3",
    "gps_acc": "12.0",
}


def stamp_for(c: dict) -> dict:
    return {
        "Keys:Make": c["make"],
        "Keys:Model": c["model"],
        "Keys:Software": c["software"],
        "Keys:CreationDate": c["created"],
        "Keys:GPSCoordinates": "%s, %s, %s" % (c["gps_lat"], c["gps_lon"], c["gps_alt"]),
        "Keys:LocationAccuracyHorizontal": c["gps_acc"],
        "Make": c["make"],
        "Model": c["model"],
        "Software": c["software"],
        "UserData:Title": c["title"],
        "UserData:Comment": c["comment"],
    }


def make_clip(dest: Path) -> None:
    font = FONT.name
    vf = (
        "drawtext=fontfile=%s:text=6:fontsize=360:fontcolor=black:"
        "x=(w-text_w)/2:y=(h-text_h)/2-90,"
        "drawtext=fontfile=%s:text=CANARY:fontsize=64:fontcolor=black:"
        "x=(w-text_w)/2:y=(h-text_h)/2+200"
        % (font, font)
    )
    cmd = [
        "ffmpeg", "-y", "-hide_banner", "-loglevel", "error",
        "-f", "lavfi", "-i", "color=c=0xF4C430:s=720x1280:d=1.5:r=24",
        "-f", "lavfi", "-i", "anullsrc=r=44100:cl=stereo",
        "-vf", vf,
        "-c:v", "libx264", "-pix_fmt", "yuv420p", "-t", "1.5",
        "-c:a", "aac", "-shortest", str(dest),
    ]
    r = subprocess.run(cmd, capture_output=True, text=True, cwd=str(HERE))
    if r.returncode != 0 or not dest.is_file():
        raise SystemExit("ffmpeg failed:\n%s" % r.stderr)


def main() -> None:
    if not FONT.is_file():
        raise SystemExit("no Arial font at %s" % FONT)
    raw = HERE / "_unique-6-unstamped.mov"
    dest = HERE / "unique-6-canary.mov"
    manifest = HERE / "unique-6-canary.json"
    make_clip(raw)
    stamp_file(raw, dest, stamp_for(CANARIES))
    raw.unlink(missing_ok=True)
    manifest.write_text(json.dumps(CANARIES, indent=2) + "\n", encoding="utf-8")
    print("wrote", dest, dest.stat().st_size)
    print("wrote", manifest)


if __name__ == "__main__":
    main()
