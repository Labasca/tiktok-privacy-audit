#!/usr/bin/env python3
"""Two clips, two canaries: does the picker sweep video the way it sweeps stills?

    python testfiles/make_video_sweep.py

Every clip arm so far ran against an emptied camera roll, which is exactly the
condition under which a sweep is invisible. Clip 8 was the one exception and it
did show picker-walk values in its column, but that was an accident of setup
rather than an isolated test, so it proves nothing on its own.

Two clips, each carrying a canary the other does not. Post A and look for B.
Post B and look for A. If neither shows the other, video does not sweep and
roll hygiene is a stills-only problem.

Colours differ so the operator can tell them apart in the picker without
reading metadata.
"""

import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "video-sweep")

# Deliberately unlike Apple, unlike this phone's real GPS, and unlike the
# stills canaries: a hit has to be unambiguous about which file it came from.
ARMS = [
    dict(id="A", colour="#1F6F4A", gps="12.3456, 65.4321, 12.3",
         date="2025:03:04 05:06:07"),
    dict(id="B", colour="#7A3E9D", gps="76.5432, 21.0987, 76.5",
         date="2025:07:08 09:10:11"),
]


def run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True)


def main():
    os.makedirs(OUT, exist_ok=True)
    made = []
    for arm in ARMS:
        path = os.path.join(OUT, "sweep-%s.mov" % arm["id"])
        r = run(["ffmpeg", "-v", "error", "-y", "-f", "lavfi",
                 "-i", "color=c=%s:s=1080x1920:d=3" % arm["colour"],
                 "-f", "lavfi", "-i", "anullsrc=channel_layout=mono:sample_rate=44100",
                 "-shortest", "-c:v", "libx264", "-pix_fmt", "yuv420p",
                 "-c:a", "aac", "-f", "mov", path])
        if r.returncode != 0:
            sys.exit("ffmpeg failed on arm %s:\n%s" % (arm["id"], r.stderr[-500:]))
        run(["exiftool", "-overwrite_original", "-q", "-all=", path])
        cmd = ["exiftool", "-overwrite_original", "-q",
               "-Keys:Make=CANARYMK-SWEEP%s" % arm["id"],
               "-Keys:Model=CANARYMD-SWEEP%s" % arm["id"],
               "-Keys:Software=CANARYSW-SWEEP%s" % arm["id"],
               "-Keys:CreationDate=%s" % arm["date"],
               # comma-separated on write; exiftool reads it back space-separated
               "-Keys:GPSCoordinates=%s" % arm["gps"],
               "-Keys:LocationAccuracyHorizontal=35.0", path]
        w = run(cmd)
        for line in (w.stdout + w.stderr).splitlines():
            if "Warning" in line:
                print("    ! " + line)
        made.append((arm["id"], path))

    print("arm  file                          bytes   Keys written")
    for aid, path in made:
        r = run(["exiftool", "-j", "-G1", "-n", path])
        d = json.loads(r.stdout)[0]
        keys = sorted(k for k in d if k.startswith("Keys:"))
        print("  %s  %-28s %7d  %s"
              % (aid, os.path.basename(path), os.path.getsize(path),
                 ", ".join(k.split(":")[1] for k in keys)))
    print("\nBoth clips carry six Keys atoms and no UserData, which is the shape")
    print("a real recording has. Import both, then post one and look for the")
    print("other's canary in the run.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
