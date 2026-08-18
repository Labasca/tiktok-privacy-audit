#!/usr/bin/env python3
"""Which photo fields are welded to the phone, and which move per shot?

    python analyze_stills_variance.py photos/

Point it at a folder of untouched captures from one device. It reports, for
every tag any of them carries, whether the value is constant across the whole
set or varies -- which is the difference between a field a forgery can copy
once and a field it has to generate freshly for every image.

It also checks the couplings. Several EXIF fields are two spellings of one
number, or dates that have to agree with each other. Randomising those
independently produces a file that is wrong by arithmetic rather than wrong by
comparison, and no amount of plausible-looking values fixes it.

Values of identifying fields are counted, never printed: this runs over
personal photographs.
"""

import argparse
import json
import math
import os
import subprocess
import sys
from collections import defaultdict

# Printing these would put coordinates, serials and per-shot UUIDs on screen
# and into any log of this run. The count is the finding; the value is not.
REDACT = ("GPS", "Serial", "Identifier", "ImageUniqueID", "Owner", "Firmware")

# group: what a difference here would mean for a forgery
BUCKETS = [
    ("IFD0", "device identity"),
    ("ExifIFD", "capture settings"),
    ("GPS", "position"),
    ("Apple", "Apple private block"),
    ("ICC_Profile", "colour"),
    ("XMP", "sidecar"),
]


def redacted(key):
    return any(w in key for w in REDACT)


def run_exiftool(paths):
    out = []
    # one call per batch keeps argv short enough on Windows
    for i in range(0, len(paths), 40):
        r = subprocess.run(["exiftool", "-j", "-G1", "-n", "-api",
                            "largefilesupport=1"] + paths[i:i + 40],
                           capture_output=True, text=True)
        try:
            out += json.loads(r.stdout)
        except Exception:                                      # noqa: BLE001
            sys.exit("exiftool produced no JSON:\n" + (r.stderr or "")[-800:])
    return out


def couplings(dumps):
    """Fields that must agree. A mismatch is detectable without a reference.

    Note the units. exiftool -n converts the APEX pair back to linear, so here
    ShutterSpeedValue reads in seconds and ApertureValue as an f-number -- the
    same stored bytes CGImageSource hands back as raw APEX (2.0000 and 1.6960).
    The check has to be written against whichever convention it is reading.
    """
    checks, bad, notes = [], [], []

    def num(d, k):
        try:
            return float(d.get(k))
        except (TypeError, ValueError):
            return None

    for d in dumps:
        name = os.path.basename(d.get("SourceFile", "?"))
        for label, linear, apex in [("shutter", "ExifIFD:ExposureTime",
                                     "ExifIFD:ShutterSpeedValue"),
                                    ("aperture", "ExifIFD:FNumber",
                                     "ExifIFD:ApertureValue")]:
            lin, ap = num(d, linear), num(d, apex)
            if lin is None or ap is None or lin <= 0:
                continue
            checks.append(label)
            if abs(ap - lin) / lin > 0.02:
                bad.append((name, "%s: %s vs %s" % (label, apex.split(":")[1],
                                                    linear.split(":")[1]),
                            "%.6f vs %.6f" % (ap, lin)))
            elif ap == lin:
                # APEX is stored as a rational and does not round-trip exactly,
                # so a genuine file is close but never equal. Writing both from
                # one float is the giveaway.
                notes.append((name, label, "exactly equal — APEX stored as a "
                                           "rational never round-trips exact"))
        dto, gds = d.get("ExifIFD:DateTimeOriginal"), d.get("GPS:GPSDateStamp")
        if dto and gds:
            checks.append("gpsdate")
            if str(dto).split()[0] != str(gds):
                bad.append((name, "gpsdate: GPSDateStamp vs DateTimeOriginal",
                            "disagree"))
        offs = {k: d[k] for k in ("ExifIFD:OffsetTime", "ExifIFD:OffsetTimeOriginal",
                                  "ExifIFD:OffsetTimeDigitized") if k in d}
        if offs:
            checks.append("offset")
            if len(set(offs.values())) > 1:
                bad.append((name, "offset: the three OffsetTime spellings",
                            "disagree"))
        sa = d.get("ExifIFD:SubjectArea")
        w, h = num(d, "ExifIFD:ExifImageWidth"), num(d, "ExifIFD:ExifImageHeight")
        if sa and w and h:
            checks.append("subject")
            xs = [float(x) for x in str(sa).split() if x.replace(".", "").isdigit()]
            if len(xs) >= 2 and (xs[0] > w or xs[1] > h):
                bad.append((name, "subject: SubjectArea outside the frame", str(sa)))
    return checks, bad, notes


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("folder", help="a folder of untouched captures from one phone")
    ap.add_argument("--show-values", action="store_true",
                    help="print values for non-identifying fields that vary")
    args = ap.parse_args()

    exts = (".heic", ".heif", ".jpg", ".jpeg", ".png", ".dng")
    paths = [os.path.join(args.folder, f) for f in sorted(os.listdir(args.folder))
             if f.lower().endswith(exts)]
    if len(paths) < 2:
        sys.exit("need at least two photos to compare; found %d" % len(paths))
    print("reading %d photos ...\n" % len(paths))
    dumps = run_exiftool(paths)

    values = defaultdict(set)
    seen = defaultdict(int)
    for d in dumps:
        for k, v in d.items():
            if k == "SourceFile" or k.split(":")[0] in ("File", "System", "ExifTool",
                                                        "Composite", "ICC-header"):
                continue
            values[k].add(str(v))
            seen[k] += 1

    n = len(dumps)
    print("%-38s %-9s %-7s %s" % ("FIELD", "ON", "DISTINCT", "VERDICT"))
    print("-" * 88)
    tally = defaultdict(lambda: [0, 0])
    for group, meaning in BUCKETS + [("", "other")]:
        keys = sorted(k for k in values
                      if (k.split(":")[0].startswith(group) if group
                          else not any(k.split(":")[0].startswith(g) for g, _ in BUCKETS)))
        if not keys:
            continue
        print("\n== %s (%s)" % (group or "other", meaning))
        for k in keys:
            d = len(values[k])
            const = d == 1
            tally[group][0 if const else 1] += 1
            if const and seen[k] == n:
                verdict = "CONSTANT — copy once from the device"
            elif const:
                verdict = "constant, but only on %d of %d" % (seen[k], n)
            else:
                verdict = "VARIES — must be generated per shot"
            extra = ""
            if args.show_values and not const and not redacted(k) and d <= 4:
                extra = "   " + " | ".join(sorted(values[k])[:4])[:44]
            print("%-38s %-9s %-8d %s%s"
                  % (k, "%d/%d" % (seen[k], n), d, verdict, extra))

    print("\n" + "=" * 88)
    print("SUMMARY")
    for group, meaning in BUCKETS:
        c, v = tally[group]
        if c or v:
            print("  %-14s %2d constant, %2d varying   (%s)" % (group, c, v, meaning))

    checks, bad, notes = couplings(dumps)
    print("\nCOUPLINGS — fields that must agree with each other")
    if not checks:
        print("  none testable on this set")
    for name in ("shutter", "aperture", "gpsdate", "offset", "subject"):
        if name in checks:
            hits = [b for b in bad if b[1].startswith(name)]
            print("  %-9s checked on %2d photo(s), %d mismatch(es)"
                  % (name, checks.count(name), len(hits)))
    for f, what, detail in bad:
        print("    ! %s: %s (%s)" % (f, what, detail))
    for f, label, why in notes:
        print("    ? %s: %s %s" % (f, label, why))
    if not bad and checks:
        print("  every coupling holds on every photo — so a forgery has to hold them too")
    return 0


if __name__ == "__main__":
    sys.exit(main())
