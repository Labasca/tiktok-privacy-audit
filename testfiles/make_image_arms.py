#!/usr/bin/env python3
"""Build the five stills arms for the image half of the audit.

    python testfiles/make_image_arms.py --camera gallery-id/IMG_00XX.HEIC

The camera photo is both an arm in its own right (the ground truth) and the
base for the HEIC canary, because exiftool can write HEIC but not create one
and ffmpeg has no HEIF muxer.

Canary id is 9B2E so a hit can never be confused with the video canary (7F3A)
or with anything the phone itself wrote.
"""

import argparse
import json
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "image-arms")

# One id per stamped arm, not one for the set. All five arms can then sit in
# the library together and a canary hit still names exactly one file -- which
# is what the shared id would have destroyed, the same way the blended video
# runs had to be thrown out.
ID_HEIC = "9B2E"
ID_XMP = "9B4F"
ID_JPEG = "9B60"

# Distinct coordinates per arm too: the GPS block is read far more often than
# make/model, so it needs to carry the same attribution on its own.
GPS = {ID_HEIC: ("11.1111", "22.2222", "33.3"),
       ID_XMP: ("44.4444", "55.5555", "66.6"),
       ID_JPEG: ("77.7777", "88.8888", "99.9")}


def canary(cid):
    lat, lon, alt = GPS[cid]
    return {
        "Make": "CANARYMK-%s" % cid,
        "Model": "CANARYMD-%s" % cid,
        "Software": "CANARYSW-%s" % cid,
        "DateTimeOriginal": "2025:02:03 04:05:06",
        "CreateDate": "2025:02:03 04:05:06",
        "GPSLatitude": lat,
        "GPSLatitudeRef": "N",
        "GPSLongitude": lon,
        "GPSLongitudeRef": "E",
        "GPSAltitude": alt,
    }


def run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True)


def need(tool):
    if not shutil.which(tool):
        sys.exit("error: %s not on PATH" % tool)


def stamp(path, tags, prefix=""):
    """prefix lets the same values go to EXIF/TIFF or to XMP only."""
    cmd = ["exiftool", "-overwrite_original", "-q", "-api", "largefilesupport=1"]
    for k, v in tags.items():
        cmd.append("-%s%s=%s" % (prefix, k, v))
    cmd.append(path)
    r = run(cmd)
    warn = [x for x in (r.stdout + r.stderr).splitlines() if "Warning" in x]
    for w in warn:
        print("    ! " + w)
    return r.returncode == 0


def strip_all(path):
    run(["exiftool", "-overwrite_original", "-q", "-all=", path])


def report(path):
    r = run(["exiftool", "-j", "-G1", "-n", path])
    try:
        d = json.loads(r.stdout)[0]
    except Exception:                                          # noqa: BLE001
        return
    groups = {}
    for k in d:
        g = k.split(":")[0]
        if g in ("File", "System", "ExifTool", "Composite"):
            continue
        groups.setdefault(g, 0)
        groups[g] += 1
    size = os.path.getsize(path)
    print("  %-26s %-6s %7d B   %s" % (os.path.basename(path),
                                       d.get("File:FileType", "?"), size,
                                       ", ".join("%s:%d" % kv for kv in sorted(groups.items()))
                                       or "no metadata groups"))


def main():
    ap = argparse.ArgumentParser(description="Build the five stills arms.")
    ap.add_argument("--camera", required=True,
                    help="a real photo shot on the phone (HEIC preferred)")
    args = ap.parse_args()
    need("exiftool"), need("ffmpeg")
    if not os.path.isfile(args.camera):
        sys.exit("error: no such file: %s" % args.camera)
    os.makedirs(OUT, exist_ok=True)

    ext = os.path.splitext(args.camera)[1].lower()
    if ext not in (".heic", ".heif"):
        print("note: reference is %s, not HEIC. The HEIC arm will be skipped."
              % ext.lstrip("."))

    print("building arms in %s\n" % OUT)

    # --- arm 1: CLEAN. Generated, nothing on it at all.
    clean = os.path.join(OUT, "img-1-clean.jpg")
    r = run(["ffmpeg", "-v", "error", "-y", "-f", "lavfi",
             "-i", "color=c=#C0392B:s=1170x2532", "-frames:v", "1", clean])
    if r.returncode != 0:
        sys.exit("ffmpeg failed building the clean arm:\n" + r.stderr[-600:])
    strip_all(clean)

    # --- arm 2: CAMERA. The ground truth, copied untouched.
    cam = os.path.join(OUT, "img-2-camera" + ext)
    shutil.copy2(args.camera, cam)

    # --- arm 3: CANARY HEIC. Real HEIC container, fake identity.
    heic = None
    if ext in (".heic", ".heif"):
        heic = os.path.join(OUT, "img-3-canary.heic")
        shutil.copy2(args.camera, heic)
        strip_all(heic)
        stamp(heic, canary(ID_HEIC))

    # --- arm 4: CANARY XMP. Same values, XMP only, no EXIF/TIFF.
    xmp = os.path.join(OUT, "img-4-canary-xmp.jpg")
    r = run(["ffmpeg", "-v", "error", "-y", "-f", "lavfi",
             "-i", "color=c=#2E86C1:s=1170x2532", "-frames:v", "1", xmp])
    if r.returncode != 0:
        sys.exit("ffmpeg failed building the xmp arm")
    strip_all(xmp)
    # XMP has no DateTimeOriginal/GPSLatitudeRef; use the XMP-native spellings
    cx = canary(ID_XMP)
    stamp(xmp, {"Make": cx["Make"], "Model": cx["Model"],
                "Software": cx["Software"]}, prefix="XMP-tiff:")
    stamp(xmp, {"DateTimeOriginal": cx["DateTimeOriginal"],
                "GPSLatitude": cx["GPSLatitude"],
                "GPSLongitude": cx["GPSLongitude"],
                "GPSAltitude": cx["GPSAltitude"]}, prefix="XMP-exif:")

    # --- arm 5: CANARY JPEG. Same values as arm 3, JPEG container.
    jpg = os.path.join(OUT, "img-5-canary.jpg")
    r = run(["ffmpeg", "-v", "error", "-y", "-f", "lavfi",
             "-i", "color=c=#D4AC0D:s=1170x2532", "-frames:v", "1", jpg])
    if r.returncode != 0:
        sys.exit("ffmpeg failed building the jpeg arm")
    strip_all(jpg)
    stamp(jpg, canary(ID_JPEG))

    print("arm                        type     bytes   metadata groups written")
    for p in [clean, cam, heic, xmp, jpg]:
        if p:
            report(p)
    print("\ncanary ids: heic %s, xmp %s, jpeg %s -- one per arm, so all five can"
          % (ID_HEIC, ID_XMP, ID_JPEG))
    print("share a library and a hit still names exactly one file.")
    print("arm 4 carries the same SHAPE as arms 3 and 5 but in XMP only: that is")
    print("the stills twin of clip 2 against clip 6.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
