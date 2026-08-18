#!/usr/bin/env python3
"""N stills, each numbered, to find out where the picker's sweep stops.

    python testfiles/make_roll_sweep.py --count 300

The audit knows the sweep reads every photo in a roll of eight. Whether that
is "the whole library" or "whatever the grid has rendered" is the open
question, and it decides whether roll hygiene is critical or cosmetic.

Each file carries its index twice over, in two independent channels:

  GPS longitude   100.000 + i/1000   numeric, sorts, unambiguous
  Make            CANARY-0000        a string grep finds on its own

Two channels because a single one that fails silently would look exactly like
a bounded sweep. If the two ever disagree, the reading is wrong rather than
the finding surprising.

Capture dates run backwards from a fixed point at one minute apart, so index
order is grid order. That is what separates "read the first forty" from "read
forty of them" -- without it, a bounded result cannot be located.
"""

import argparse
import datetime as dt
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "roll-sweep")

# Far from this phone's real position, far from the stills canaries, and a
# round base so the index is readable straight off the value.
BASE_LON = 100.0
BASE_LAT = 5.0
# Newest first: index 0 is the most recent, so it sits at the top of Recents.
ANCHOR = dt.datetime(2025, 6, 1, 12, 0, 0)


def run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--count", type=int, default=300)
    ap.add_argument("--width", type=int, default=640)
    args = ap.parse_args()
    os.makedirs(OUT, exist_ok=True)

    # one base bitmap, copied: generating 300 through ffmpeg is slow and the
    # pixels are irrelevant to the question
    base = os.path.join(OUT, "_base.jpg")
    r = run(["ffmpeg", "-v", "error", "-y", "-f", "lavfi",
             "-i", "color=c=#33414F:s=%dx%d" % (args.width, int(args.width * 16 / 9)),
             "-frames:v", "1", base])
    if r.returncode != 0:
        sys.exit("ffmpeg failed building the base image:\n" + r.stderr[-400:])
    run(["exiftool", "-overwrite_original", "-q", "-all=", base])

    print("writing %d stills into %s ..." % (args.count, OUT))
    argfile = os.path.join(OUT, "_args.txt")
    made = []
    with open(argfile, "w", encoding="utf-8") as fh:
        for i in range(args.count):
            path = os.path.join(OUT, "sweep-%04d.jpg" % i)
            with open(base, "rb") as src, open(path, "wb") as dst:
                dst.write(src.read())
            when = (ANCHOR - dt.timedelta(minutes=i)).strftime("%Y:%m:%d %H:%M:%S")
            # -@ argfile: one exiftool process for the whole set rather than
            # three hundred, which is the difference between seconds and minutes
            fh.write("-overwrite_original\n-q\n")
            fh.write("-Make=CANARY-%04d\n" % i)
            fh.write("-Model=ROLLSWEEP\n")
            fh.write("-GPSLatitude=%.4f\n-GPSLatitudeRef=N\n" % (BASE_LAT + i / 10000.0))
            fh.write("-GPSLongitude=%.4f\n-GPSLongitudeRef=E\n" % (BASE_LON + i / 1000.0))
            fh.write("-DateTimeOriginal=%s\n" % when)
            fh.write("-CreateDate=%s\n" % when)
            fh.write("%s\n" % path)
            fh.write("-execute\n")
            made.append(path)
    os.remove(base)

    w = run(["exiftool", "-@", argfile])
    warn = [l for l in (w.stdout + w.stderr).splitlines() if "Warning" in l or "Error" in l]
    for l in warn[:5]:
        print("  ! " + l)
    os.remove(argfile)

    # the point of two channels is that they get checked against each other
    bad = []
    probe = run(["exiftool", "-j", "-n", "-Make", "-GPSLongitude", "-DateTimeOriginal"]
                + made)
    data = json.loads(probe.stdout)
    for d in data:
        i = int(os.path.basename(d["SourceFile"])[6:10])
        if d.get("Make") != "CANARY-%04d" % i:
            bad.append((i, "Make", d.get("Make")))
        lon = d.get("GPSLongitude")
        if lon is None or abs(float(lon) - (BASE_LON + i / 1000.0)) > 1e-6:
            bad.append((i, "GPSLongitude", lon))
    print("\n%d files written, %d verified" % (len(made), len(data)))
    if bad:
        print("MISMATCH on %d file(s) -- the two channels disagree, so a bounded"
              % len(bad))
        print("result would not be readable. First few: %r" % bad[:4])
        return 1
    first, last = data[0], data[-1]
    print("index 0    Make %s  lon %s  taken %s"
          % (first.get("Make"), first.get("GPSLongitude"), first.get("DateTimeOriginal")))
    print("index %-4d Make %s  lon %s  taken %s"
          % (len(data) - 1, last.get("Make"), last.get("GPSLongitude"),
             last.get("DateTimeOriginal")))
    print("\nDates run backwards a minute apart, so index order is grid order:")
    print("index 0 sits newest. If only the first N come back, the sweep is")
    print("bounded and N is the bound.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
