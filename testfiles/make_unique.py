#!/usr/bin/env python3
"""Two generated clips that cannot be confused by eye."""
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
from automation.prepare import stamp_file, NATIVE_STAMP

_WIN = Path(r"C:\Windows\Fonts\arialbd.ttf")
if not _WIN.is_file():
    _WIN = Path(r"C:\Windows\Fonts\arial.ttf")
FONT = HERE / "arialbd.ttf"
if _WIN.is_file() and not FONT.is_file():
    shutil.copy2(_WIN, FONT)


def make(dest: Path, color: str, number: str, label: str) -> None:
    font = FONT.name  # no drive-letter colon; cwd is testfiles/
    vf = (
        "drawtext=fontfile=%s:text=%s:fontsize=360:fontcolor=white:"
        "x=(w-text_w)/2:y=(h-text_h)/2-90,"
        "drawtext=fontfile=%s:text=%s:fontsize=72:fontcolor=white:"
        "x=(w-text_w)/2:y=(h-text_h)/2+200"
        % (font, number, font, label)
    )
    cmd = [
        "ffmpeg", "-y", "-hide_banner", "-loglevel", "error",
        "-f", "lavfi", "-i", "color=c=%s:s=720x1280:d=1.5:r=24" % color,
        "-f", "lavfi", "-i", "anullsrc=r=44100:cl=stereo",
        "-vf", vf,
        "-c:v", "libx264", "-pix_fmt", "yuv420p", "-t", "1.5",
        "-c:a", "aac", "-shortest", str(dest),
    ]
    r = subprocess.run(cmd, capture_output=True, text=True, cwd=str(HERE))
    if r.returncode != 0 or not dest.is_file():
        raise SystemExit("ffmpeg failed for %s:\n%s" % (dest, r.stderr))


def main() -> None:
    if not FONT.is_file():
        raise SystemExit("no Arial font at %s" % FONT)
    clean = HERE / "unique-1-clean.mov"
    stamped_src = HERE / "_unique-2-unstamped.mov"
    stamped = HERE / "unique-2-stamped.mov"
    make(clean, "0xC62828", "1", "CLEAN")
    make(stamped_src, "0x1565C0", "2", "STAMPED")
    stamp_file(stamped_src, stamped, dict(NATIVE_STAMP))
    stamped_src.unlink(missing_ok=True)
    print("wrote", clean, clean.stat().st_size)
    print("wrote", stamped, stamped.stat().st_size)


if __name__ == "__main__":
    main()
