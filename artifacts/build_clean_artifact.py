#!/usr/bin/env python3
"""Build the TikTok metadata audit artifact from run data.

Reads runs/<id>/tags.json (+ session.log, bodies/) and live exiftool dumps of
every clip we posted, collapses the AVFoundation keyspace duplication, and
emits one self-contained HTML page.

Structure follows the brief: lead with the six-clip metadata table, then the
conclusions that fall out of it. Every raw tag row survives as a distinct
(phase, atom, value) fact in the appendix ledger; raw files go in verbatim.
"""

import html
import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "artifacts", "tiktok-audit-clean.html")
AS_OF = "14 August 2026"

# ---------------------------------------------------------------- run inputs
# origin: how the clip came to exist. This is the label the table leads with.
RUNS = [
    dict(id="unique-1-solo", n=1, key="clean", label="CLEAN", cls="is-dim",
         origin="I MADE IT", note="red test card, nothing written on it",
         src="IMG_0021.MOV", src_bytes=9065, export=9691,
         dump=("testfiles/unique-1-clean.mov", "unique-1-clean.mov")),
    dict(id="unique-2-solo", n=2, key="stamped", label="STAMPED", cls="is-warn",
         origin="I MADE IT", note="blue test card, faked as an iPhone — GPS put in XMP",
         src="IMG_0022.MOV", src_bytes=16524, export=13706,
         dump=("testfiles/unique-2-stamped.mov", "unique-2-stamped.mov")),
    dict(id="unique-3-sintel", n=3, key="sintel", label="SINTEL", cls="is-dim",
         origin="I DOWNLOADED IT", note="film trailer off the web, posted as-is",
         src="IMG_0010.MOV", src_bytes=1048174, export=1054614,
         dump=("gallery-id/IMG_0010.MOV", "IMG_0010.MOV")),
    dict(id="unique-4-bunny", n=4, key="bunny", label="BUNNY", cls="is-dim",
         origin="I DOWNLOADED IT", note="Big Buck Bunny, still carrying its original credits",
         src="IMG_0009.MOV", src_bytes=990971, export=1000150,
         dump=("gallery-id/IMG_0009.MOV", "IMG_0009.MOV")),
    dict(id="unique-5-camera", n=5, key="camera", label="CAMERA", cls="is-good",
         origin="I FILMED IT", note="shot on this iPhone X, genuine capture data",
         src="IMG_0026.MOV", src_bytes=4177966, export=4156740,
         dump=("gallery-id/IMG_0026-camera.MOV", "IMG_0026-camera.MOV")),
    dict(id="unique-6-canary-2", n=6, key="canary", label="CANARY", cls="is-new",
         origin="I MADE IT", note="yellow test card, faked with canaries in Keys",
         src="IMG_0027.MOV", src_bytes=17213, export=14311,
         dump=("testfiles/unique-6-canary.mov", "unique-6-canary.mov")),
    dict(id="unique-8-ai-2", n=7, key="ai", label="AI", cls="is-new",
         origin="AI MADE IT", note="generator output, posted exactly as it came",
         src="IMG_0029.MP4", src_bytes=4568650, export=4568201, dump=None),
    dict(id="unique-9-stripped", n=8, key="aistripped", label="AI STRIPPED", cls="is-warn",
         origin="AI MADE IT", note="same clip again, metadata stripped first", blended=True,
         src="IMG_0031.MP4", src_bytes=25949697, export=None, dump=None),
    dict(id="unique-11-nativized-solo", n=9, key="nativized", label="NATIVIZED", cls="is-good",
         origin="I MADE IT PASS", note="the AI clip, restamped to match a real capture",
         src="IMG_0034.MOV", src_bytes=13989061, export=None, dump=None),
    dict(id="unique-10-nativized", n=None, key="nativized_v1", label="NATIVIZED v1",
         cls="is-warn", origin="FIRST TRY", note="same idea, but ffmpeg signed it",
         src="IMG_0034.MOV", src_bytes=13989093, export=None, dump=None,
         blended=True, table=False),
    dict(id="unique-6-publish", n=None, key="publish", label="WIRE", cls="is-bad",
         origin="CAPTURED IT", note="TLS hook on the canary re-post",
         src="export_1786728350292.mov", src_bytes=34375, export=34384, dump=None),
]

# Windows where the operator did not post. Named so the record is complete.
MISSED = [("unique-7-sora", 18), ("unique-8-ai", 18)]

# ------------------------------------------------------------- stills arms
# Five photos, posted one at a time like the clips. Unlike the clips these
# shared a camera roll, which is only sound because each arm carries its own
# canary id -- and that turned out to be the whole finding.
IMAGE_RUNS = [
    dict(id="img-1-clean", n=1, key="iclean", label="CLEAN", cls="is-dim",
         origin="I MADE IT", note="flat red, nothing written on it",
         file="testfiles/image-arms/img-1-clean.jpg", asset="IMG_0039.JPG",
         mark=None, gps=None),
    dict(id="img-2-camera", n=2, key="icamera", label="CAMERA", cls="is-good",
         origin="I SHOT IT", note="real photo off this iPhone X",
         file="testfiles/image-arms/img-2-camera.heic", asset="IMG_0040.HEIC",
         mark="Apple", gps="54.63889666666667", private=True),
    dict(id="img-3-canary-heic", n=3, key="iheic", label="CANARY HEIC", cls="is-new",
         origin="I MADE IT PASS", note="same photo, identity stripped and refaked",
         file="testfiles/image-arms/img-3-canary.heic", asset="IMG_0041.HEIC",
         mark="CANARYMK-9B2E", gps="11.1111", private=True),
    dict(id="img-4-canary-xmp", n=4, key="ixmp", label="CANARY XMP", cls="is-warn",
         origin="I MADE IT", note="flat blue, faked in XMP only — no EXIF at all",
         file="testfiles/image-arms/img-4-canary-xmp.jpg", asset="IMG_0042.JPG",
         mark="CANARYMK-9B4F", gps="44.4444"),
    dict(id="img-5-canary-jpeg", n=5, key="ijpeg", label="CANARY JPEG", cls="is-new",
         origin="I MADE IT", note="flat yellow, same values but written to EXIF",
         file="testfiles/image-arms/img-5-canary.jpg", asset="IMG_0043.JPG",
         mark="CANARYMK-9B60", gps="77.7777"),
]

# Field rows for the stills inventory. Each row names the tags that could carry
# it, EXIF first then the XMP spelling, so a cell can say which container the
# value actually came out of -- the distinction arm 4 exists to test.
IMAGE_FIELDS = [
    ("Which device shot it", "is-bad", [
        ("make", ["IFD0:Make", "XMP-tiff:Make"]),
        ("model", ["IFD0:Model", "XMP-tiff:Model"]),
        ("software / iOS build", ["IFD0:Software", "XMP-tiff:Software"]),
    ]),
    ("Where it was shot", "is-bad", [
        ("GPS latitude", ["GPS:GPSLatitude", "XMP-exif:GPSLatitude"]),
        ("GPS longitude", ["GPS:GPSLongitude", "XMP-exif:GPSLongitude"]),
        ("GPS altitude", ["GPS:GPSAltitude", "XMP-exif:GPSAltitude"]),
        ("compass bearing", ["GPS:GPSImgDirection"]),
        ("position error", ["GPS:GPSHPositioningError"]),
    ]),
    ("When it was shot", "is-warn", [
        ("capture date", ["ExifIFD:DateTimeOriginal", "XMP-exif:DateTimeOriginal"]),
        ("timezone offset", ["ExifIFD:OffsetTimeOriginal"]),
        ("sub-second", ["ExifIFD:SubSecTimeOriginal"]),
    ]),
    ("Which lens and settings", "is-warn", [
        ("lens", ["ExifIFD:LensModel"]),
        ("aperture", ["ExifIFD:FNumber"]),
        ("exposure", ["ExifIFD:ExposureTime"]),
        ("ISO", ["ExifIFD:ISO"]),
    ]),
    ("What the picture itself is", "is-dim", [
        ("container", ["File:FileType"]),
        ("colour profile", ["ICC_Profile:ProfileDescription"]),
    ]),
]

# Plain English for the fields worth naming. Anything absent here still gets a
# row -- the table is built from the data, not from this dict, so it cannot go
# stale or quietly drop a field the app started reading.
IMAGE_GLOSS = {
    "{TIFF} Make": "handset manufacturer",
    "{TIFF} Model": "handset model",
    "{TIFF} Software": "iOS build",
    "{TIFF} HostComputer": "the device that wrote the file — a second identifier",
    "{TIFF} DateTime": "file write time",
    "{TIFF} Orientation": "how the phone was held",
    "{TIFF} XResolution": "stored resolution",
    "{TIFF} YResolution": "stored resolution",
    "{TIFF} ResolutionUnit": "resolution unit",
    "{TIFF} TileWidth": "HEIC tile size — computed on read, not stored",
    "{TIFF} TileLength": "HEIC tile size — computed on read, not stored",
    "{Exif} DateTimeOriginal": "shutter time",
    "{Exif} DateTimeDigitized": "digitised time",
    # identical strings on purpose: three timezone rows and two sub-second rows
    # sort next to each other, and the table prints a description once per run
    "{Exif} OffsetTime": "timezone — places you geographically on its own",
    "{Exif} OffsetTimeOriginal": "timezone — places you geographically on its own",
    "{Exif} OffsetTimeDigitized": "timezone — places you geographically on its own",
    "{Exif} SubsecTimeOriginal": "sub-second — makes the timestamp near-unique",
    "{Exif} SubsecTimeDigitized": "sub-second — makes the timestamp near-unique",
    "{Exif} LensModel": "which of the two rear lenses fired — it changes per shot",
    "{Exif} LensMake": "lens maker",
    "{Exif} LensSpecification": "focal range and max aperture",
    "{Exif} SubjectArea": "where the subject sat in the frame",
    "{Exif} BrightnessValue": "scene brightness — indoors or out",
    "{Exif} Flash": "whether the flash fired",
    "{Exif} ISOSpeedRatings": "sensor gain, tracks available light",
    "{Exif} ExposureTime": "shutter speed",
    "{Exif} FNumber": "aperture",
    "{Exif} ApertureValue": "aperture, log form",
    "{Exif} ShutterSpeedValue": "shutter, log form",
    "{Exif} FocalLength": "focal length",
    "{Exif} FocalLenIn35mmFilm": "focal length, 35mm equivalent",
    "{Exif} MeteringMode": "metering mode",
    "{Exif} WhiteBalance": "white balance",
    "{Exif} ExposureMode": "exposure mode",
    "{Exif} ExposureProgram": "exposure program",
    "{Exif} ExposureBiasValue": "exposure compensation",
    "{Exif} SceneType": "directly photographed, or a scan",
    "{Exif} SensingMethod": "sensor type",
    "{Exif} ColorSpace": "colour space",
    "{Exif} ExifVersion": "EXIF version",
    "{Exif} ComponentsConfiguration": "channel order",
    "{Exif} PixelXDimension": "full-resolution width",
    "{Exif} PixelYDimension": "full-resolution height",
    "{GPS} Latitude": "latitude",
    "{GPS} Longitude": "longitude",
    "{GPS} Altitude": "altitude",
    "{GPS} AltitudeRef": "above or below sea level",
    "{GPS} LatitudeRef": "hemisphere",
    "{GPS} LongitudeRef": "hemisphere",
    "{GPS} ImgDirection": "which way the camera was pointing",
    "{GPS} ImgDirectionRef": "true or magnetic north",
    "{GPS} DestBearing": "bearing to destination",
    "{GPS} DestBearingRef": "bearing reference",
    "{GPS} HPositioningError": "GPS accuracy in metres",
    "{GPS} Speed": "how fast you were moving",
    "{GPS} SpeedRef": "speed units",
    "{GPS} GPSVersion": "GPS tag version",
    # exiftool names two of the three UUIDs in the Apple block; the third it
    # leaves numbered, so neither do we.
    "{MakerApple} 17": "ContentIdentifier — Live Photos only, absent otherwise",
    "{MakerApple} 43": "PhotoIdentifier — unique to every shot, Live or not",
    "{MakerApple} 32": "a third UUID, unnamed",
    "ColorModel": "colour model", "Depth": "bit depth",
    "PixelWidth": "bitmap width", "PixelHeight": "bitmap height",
    "DPIWidth": "DPI", "DPIHeight": "DPI", "HasAlpha": "has transparency",
    "IsIndexed": "indexed palette", "Orientation": "orientation",
    "PrimaryImage": "primary image in the container",
    "ProfileName": "colour profile",
}

# How each CGImageSource dictionary is grouped in the complete table.
IMAGE_BLOCKS = [
    ("{TIFF}", "Device and file identity", "is-bad",
     "Who made the handset, which model, which iOS build."),
    ("{GPS}", "Location", "is-bad",
     "Not just a coordinate: altitude, heading, speed and GPS accuracy too."),
    ("{Exif}", "Time, lens and exposure", "is-warn",
     "The camera's own record of the moment — enough to fingerprint a device "
     "and describe the scene."),
    ("{MakerApple}", "Apple's private block", "is-new",
     "%d mostly undocumented tags Apple writes for itself, read verbatim."),
    ("(top level)", "Bitmap geometry", "is-dim",
     "Computed for every bitmap the app draws, interface chrome included, so "
     "no value here belongs to one photo — which is why Figma appears among "
     "the software strings."),
]

# CGImageSource and exiftool disagree on some spellings. Everything else
# resolves by matching the last path component, and the build reports any field
# that resolves to nothing on every arm, so this list cannot silently rot.
IMAGE_EXIF_ALIAS = {
    "{Exif} DateTimeDigitized": "CreateDate",
    "{Exif} ExposureBiasValue": "ExposureCompensation",
    "{Exif} FocalLenIn35mmFilm": "FocalLengthIn35mmFormat",
    "{Exif} ISOSpeedRatings": "ISO",
    "{Exif} LensSpecification": "LensInfo",
    "{Exif} PixelXDimension": "ExifImageWidth",
    "{Exif} PixelYDimension": "ExifImageHeight",
    "{Exif} SubsecTimeDigitized": "SubSecTimeDigitized",
    "{Exif} SubsecTimeOriginal": "SubSecTimeOriginal",
    "{GPS} GPSVersion": "GPSVersionID",
    "{TIFF} DateTime": "ModifyDate",
}

# Time keys live in {Exif} but read as provenance, so they lead their group.
IMAGE_TIME_KEYS = ("DateTimeOriginal", "DateTimeDigitized", "OffsetTime",
                   "OffsetTimeOriginal", "OffsetTimeDigitized",
                   "SubsecTimeOriginal", "SubsecTimeDigitized")

CHAIN_DUMPS = [
    ("gallery-id/IMG_0027-after-index.MOV", "IMG_0027-after-index.MOV",
     "The canary clip pulled back off the phone after the Photos import. The stamp survived."),
    ("gallery-id/publish_video_local_canary.mp4", "publish_video_local_canary.mp4",
     "TikTok's re-encode, pulled from its Documents folder after the post. The stamp is gone."),
]

PHASES = [
    ("INPUT", "INPUT", "Read off the source file the picker opened."),
    ("video metadata", "COMPOSE", "Re-polled while the compose screen is open."),
    ("video commonMetadata", "COMMON META",
     "AVAsset commonMetadata accessor. Only the AI arm exercised it."),
    ("written into the export", "EXPORT WRITE", "Atoms TikTok wrote into its own export."),
    ("OUTPUT", "OUTPUT", "Read back off the finished export."),
    ("library", "PHASSET", "Photos library properties of the chosen asset."),
    ("track", "TRACK", "Track-level codec."),
    ("file", "FILE", "Filesystem stat on files TikTok touched."),
    ("image", "IMAGE", "CGImage properties. UI chrome and thumbnails, not the video."),
]

PROVENANCE_ATOMS = {
    "mdta/com.apple.quicktime.make", "mdta/com.apple.quicktime.model",
    "mdta/com.apple.quicktime.software", "mdta/com.apple.quicktime.creationdate",
    "mdta/com.apple.quicktime.location.ISO6709",
    "mdta/com.apple.quicktime.location.accuracy.horizontal",
    "udta/%A9mak", "udta/%A9mod", "udta/%A9nam", "udta/%A9cmt",
    "udta/%A9ART", "udta/%A9gen", "udta/%A9des",
}

ATOM_NAMES = {
    "mdta/com.apple.quicktime.make": "make",
    "mdta/com.apple.quicktime.model": "model",
    "mdta/com.apple.quicktime.software": "software / OS",
    "mdta/com.apple.quicktime.creationdate": "creation date",
    "mdta/com.apple.quicktime.location.ISO6709": "GPS coordinate",
    "mdta/com.apple.quicktime.location.accuracy.horizontal": "GPS accuracy",
    "mdta/com.apple.quicktime.artwork": "TikTok product block",
    "udta/%A9mak": "make", "udta/%A9mod": "model", "udta/%A9nam": "title",
    "udta/%A9cmt": "comment", "udta/%A9ART": "artist", "udta/%A9gen": "genre",
    "udta/%A9des": "description", "udta/%A9swr": "muxer",
    "udta/XMP_": "XMP packet", "udta/chpl": "chapter list",
    "id3/TXXX": "id3 user text", "id3/TSSE": "id3 encoder",
}

# The table: what TikTok pulled out of each clip, grouped by what it tells them.
TABLE_GROUPS = [
    ("Which device shot it", "is-bad", [
        ("make", "mdta/com.apple.quicktime.make", "Keys"),
        ("model", "mdta/com.apple.quicktime.model", "Keys"),
        ("software / iOS build", "mdta/com.apple.quicktime.software", "Keys"),
        ("make", "udta/%A9mak", "UserData"),
        ("model", "udta/%A9mod", "UserData"),
    ]),
    ("Where it was shot", "is-bad", [
        ("GPS coordinate", "mdta/com.apple.quicktime.location.ISO6709", "Keys"),
        ("GPS accuracy", "mdta/com.apple.quicktime.location.accuracy.horizontal", "Keys"),
    ]),
    ("When it was shot", "is-warn", [
        ("creation date", "mdta/com.apple.quicktime.creationdate", "Keys"),
    ]),
    ("Where it came from", "is-warn", [
        ("title", "udta/%A9nam", "UserData"),
        ("artist", "udta/%A9ART", "UserData"),
        ("comment", "udta/%A9cmt", "UserData"),
        ("genre", "udta/%A9gen", "UserData"),
        ("description", "udta/%A9des", "UserData"),
    ]),
    ("How it was made", "is-dim", [
        ("muxer", "udta/%A9swr", "UserData"),
        ("XMP packet", "udta/XMP_", "XMP"),
        ("chapter list", "udta/chpl", "UserData"),
    ]),
    ("What the picture itself is", "is-warn", [
        ("video codec", "codec", "Track", "track"),
        ("frame size", "__resolution__", "PHAsset", "library"),
        ("timecode track", "uiso/%A9TIM", "UserData"),
    ]),
    # These come from the export TikTok wrote, not from the source file.
    ("What TikTok stamped back on", "is-new", [
        ("AI label", "mdta/aigc_info", "Keys", "written"),
        ("its own product tag", "mdta/com.apple.quicktime.artwork", "Keys", "written"),
    ]),
]

# What TikTok reads, by what it tells them. Counted from the data at build time.
CENSUS = [
    ("Device identity", "is-bad", "Pill: Identifies the handset",
     "make, model, iOS build — from Keys and legacy UserData both",
     lambda a: a in ("mdta/com.apple.quicktime.make", "mdta/com.apple.quicktime.model",
                     "mdta/com.apple.quicktime.software", "udta/%A9mak", "udta/%A9mod")),
    ("Location", "is-bad", "Pill: Identifies the place",
     "ISO 6709 coordinate and horizontal accuracy, straight off the file",
     lambda a: "location" in a),
    ("Timestamps", "is-warn", "Pill: Identifies the moment",
     "capture date with timezone offset, plus filesystem create and modify dates",
     lambda a: "creationdate" in a or a in ("CreationDate", "ModificationDate")),
    ("Content provenance", "is-warn", "Pill: Identifies the source",
     "title, artist, comment, genre, description — whoever made the file first",
     lambda a: a in ("udta/%A9nam", "udta/%A9ART", "udta/%A9cmt", "udta/%A9gen",
                     "udta/%A9des")),
    ("Photos library facts", "is-dim", "Pill: Not in the file",
     "pixel dimensions and media subtypes, asked of PhotoKit rather than the bytes",
     lambda a: a in ("pixelWidth", "pixelHeight", "mediaSubtypes")),
    ("Container housekeeping", "is-dim", "Pill: Harmless",
     "muxer string, XMP blob, chapter list, codec fourcc",
     lambda a: a in ("udta/%A9swr", "udta/XMP_", "udta/chpl", "codec")),
    ("AI-generated label", "is-new", "Pill: TikTok's verdict",
     "aigc_info, written into the export on the AI clip and on no other arm",
     lambda a: "aigc" in a),
    ("TikTok's own encoder block", "is-dim", "Pill: Theirs, not yours",
     "the TEEditor / Lavf keys it writes into every export and reads back",
     lambda a: a.startswith("itsk/") or "artwork" in a),
    ("Thumbnail and UI chrome", "is-dim", "Pill: Not your video",
     "CGImage properties of interface bitmaps the picker rendered",
     lambda a: a in ("ColorModel", "PixelWidth", "PixelHeight", "Depth", "HasAlpha",
                     "DPIWidth", "DPIHeight", "ProfileName", "Orientation",
                     "PrimaryImage", "IsIndexed", "{JFIF}", "{PNG}", "{TIFF}",
                     "{TIFF} Orientation", "{TIFF} Software")),
]

LEGIT_CMD = """# what a real iPhone X recording carries, reproduced onto any clip
exiftool -overwrite_original \\
  -Keys:Make="Apple" \\
  -Keys:Model="iPhone X" \\
  -Keys:Software="16.7.16" \\
  -Keys:CreationDate="2026:08:14 19:31:34+03:00" \\
  -Keys:GPSCoordinates="54.6389, 24.9351, 161.972" \\
  -Keys:LocationAccuracyHorizontal="35.0" \\
  clip.mov

# the picture has to match the story: iPhone shoots HEVC, not H.264
ffmpeg -i clip.mov -c:v hevc_videotoolbox -tag:v hvc1 \\
  -s 1920x1080 -r 30 -c:a aac out.mov"""


def esc(s):
    return html.escape(str(s), quote=True)


def norm(v):
    return " | ".join(str(x) for x in v) if isinstance(v, list) else str(v)


def fmt_bytes(n):
    return "{:,}".format(int(n)).replace(",", " ")


def atom_name(a):
    if a in ATOM_NAMES:
        return ATOM_NAMES[a]
    if a.startswith("itsk/"):
        return "encoder key %s" % a.split("%00")[-1]
    return a


# ------------------------------------------------------------------ loading

def load_run(rid):
    with open(os.path.join(ROOT, "runs", rid, "tags.json"), encoding="utf-8") as f:
        return json.load(f)


def split_key(key):
    for raw, _, _ in PHASES:
        if key.startswith(raw):
            rest = key[len(raw):].strip()
            m = re.match(r"^(.*?)\s*((?:mdta|udta|itsk|id3|uiso)/.*)$", rest)
            return (raw, m.group(1) or "—", m.group(2)) if m else (raw, "—", rest)
    return "?", "—", key


def collapse(tags):
    """562 raw rows -> distinct (phase, atom, value) facts, keyspaces preserved."""
    facts, order = {}, []
    for key, meta in tags.items():
        phase, keyspace, atom = split_key(key)
        value = norm(meta["value"])
        ident = (phase, atom, value)
        if ident not in facts:
            facts[ident] = dict(phase=phase, atom=atom, value=value, keyspaces=[],
                                reads=0, first=meta.get("first_seen_s"), raw=0)
            order.append(ident)
        f = facts[ident]
        if keyspace not in f["keyspaces"]:
            f["keyspaces"].append(keyspace)
        f["raw"] += 1
        f["reads"] = max(f["reads"] or 0, meta.get("reads") or 0)
        t = meta.get("first_seen_s")
        if t is not None:
            f["first"] = t if f["first"] is None else min(f["first"], t)
    return [facts[i] for i in order]


def exif(relpath):
    path = os.path.join(ROOT, relpath)
    if not os.path.exists(path):
        return None
    try:
        # -G1 not -G0: group 0 lumps Keys and UserData together as "QuickTime",
        # and that distinction is the whole finding.
        raw = subprocess.run(["exiftool", "-j", "-G1", "-n", "-api",
                              "largefilesupport=1", path],
                             capture_output=True, text=True, timeout=120).stdout
        data = json.loads(raw)[0]
    except Exception as e:                                     # noqa: BLE001
        print("  ! exiftool failed on %s: %s" % (relpath, e), file=sys.stderr)
        return None
    for k in list(data):
        if k == "SourceFile" or k.startswith(("System:", "ExifTool:")) \
                or k in ("File:Directory", "File:FileAccessDate", "File:FilePermissions"):
            data.pop(k)
    return data


# Containers actually stored in the file. Composite:* is deliberately absent —
# exiftool synthesises those from Keys:GPSCoordinates, so listing them restates
# one real value five times and crowds out genuine tags.
EXIF_SIGNAL = ("Keys:", "UserData:", "ItemList:", "XMP-", "XMP:")


def is_signal(k):
    return any(k.startswith(p) for p in EXIF_SIGNAL)


def container_of(k):
    g = k.split(":")[0]
    return "XMP" if g.startswith("XMP") else g


# --------------------------------------------------------------------- build

def main():
    runs = {}
    for r in RUNS:
        d = load_run(r["id"])
        d["_facts"] = collapse(d["tags"])
        d["_input"] = {f["atom"]: f for f in d["_facts"] if f["phase"] == "INPUT"}
        d["_comp"] = {f["atom"]: f for f in d["_facts"] if f["phase"] == "video metadata"}
        d["_written"] = {f["atom"]: f for f in d["_facts"]
                         if f["phase"] == "written into the export"}
        d["_track"] = {f["atom"]: f for f in d["_facts"] if f["phase"] == "track"}
        d["_library"] = {f["atom"]: f for f in d["_facts"] if f["phase"] == "library"}
        runs[r["id"]] = d

    raw_total = sum(r["tag_count"] for r in runs.values())
    fact_total = sum(len(r["_facts"]) for r in runs.values())
    expect = {"unique-1-solo": 67, "unique-2-solo": 92, "unique-3-sintel": 78,
              "unique-4-bunny": 94, "unique-5-camera": 85, "unique-6-canary-2": 106,
              "unique-6-publish": 40, "unique-8-ai-2": 86, "unique-9-stripped": 90,
              "unique-10-nativized": 75, "unique-11-nativized-solo": 85}
    for rid, n in expect.items():
        assert runs[rid]["tag_count"] == n, "%s drifted" % rid
    assert raw_total == 898, "raw tag total drifted: %d" % raw_total
    orphans = [(r, f["atom"]) for r in runs for f in runs[r]["_facts"] if f["phase"] == "?"]
    assert not orphans, "facts in an unrecognised phase would vanish from the ledger: %r" % orphans
    unsplit = [(r, f["atom"]) for r in runs for f in runs[r]["_facts"]
               if " " in f["atom"] and "/" in f["atom"]]
    assert not unsplit, "atom still carries its keyspace, unknown container: %r" % unsplit[:5]
    print("runs ok: %d raw tags -> %d distinct facts" % (raw_total, fact_total))

    # stills arms: same rig, one shared roll, one canary id per arm
    iruns = {r["id"]: load_run(r["id"]) for r in IMAGE_RUNS}
    iexpect = {"img-1-clean": 142, "img-2-camera": 147, "img-3-canary-heic": 149,
               "img-4-canary-xmp": 152, "img-5-canary-jpeg": 149}
    for rid, n in iexpect.items():
        assert iruns[rid]["tag_count"] == n, "%s drifted: %d" % (rid, iruns[rid]["tag_count"])
    # the finding rests on every arm carrying a distinct canary; if two ever
    # collide the read table silently starts lying about which file was seen
    marks = [r["mark"] for r in IMAGE_RUNS if r.get("mark")]
    gpss = [r["gps"] for r in IMAGE_RUNS if r.get("gps")]
    assert len(set(marks)) == len(marks), "stills arms share a canary id: %r" % marks
    assert len(set(gpss)) == len(gpss), "stills arms share a coordinate: %r" % gpss
    print("stills ok: %d raw tags across %d arms"
          % (sum(r["tag_count"] for r in iruns.values()), len(iruns)))

    print("dumping denominators with exiftool ...")
    dumps = {r["key"]: exif(r["dump"][0]) for r in RUNS if r["dump"]}
    idumps = {r["key"]: exif(r["file"]) for r in IMAGE_RUNS}
    vdir = os.path.join(ROOT, VARIANCE_DIR)
    vpaths = ([os.path.join(VARIANCE_DIR, f) for f in sorted(os.listdir(vdir))
               if f.lower().endswith((".heic", ".jpg", ".jpeg", ".heif"))]
              if os.path.isdir(vdir) else [])
    var = variance(vpaths)
    print("variance corpus: %s"
          % ("%d photos" % var["n"] if var else "absent, section will say so"))
    missing = [r["label"] for r in IMAGE_RUNS if idumps.get(r["key"]) is None]
    if missing:
        print("  ! stills denominator unavailable for: %s" % ", ".join(missing))
    chain = [(name, note, exif(path)) for path, name, note in CHAIN_DUMPS]

    canary_ids = [f for f in runs["unique-6-canary-2"]["_input"].values()
                  if f["atom"] in PROVENANCE_ATOMS]

    P = []
    w = P.append
    w('<title>Canary in the Camera Roll</title>')
    w(STYLE)
    w('<div class="wrap">')

    # ---------------------------------------------------------------- head
    w('<header class="masthead">')
    w('<p class="eyebrow">TikTok post-path capture · jailbroken iPhone X · %s</p>' % esc(AS_OF))
    w('<h1>Everything TikTok reads when you post</h1>')
    w('<p>We hooked the app with Frida and posted fourteen files, one per session, each with a '
      'deliberately different history. Two separate investigations came out of it &mdash; one '
      'for video, one for photos &mdash; and they do not reach the same conclusion, so they are '
      'kept apart here.</p>')
    w('</header>')

    # ------------------------------------------------------------- the tabs
    ikeys = image_keys(iruns)
    w('<nav class="tabs" role="tablist" aria-label="Which investigation">')
    for pid, name, sub, on in [("pg-video", "Video", "9 clips · 898 reads", True),
                               ("pg-photos", "Photos", "5 stills · %d fields"
                                % sum(len(v) for v in ikeys.values()), False)]:
        w('<button class="tab%s" role="tab" data-page="%s" aria-controls="%s" '
          'aria-selected="%s"><b>%s</b><span>%s</span></button>'
          % (" is-on" if on else "", pid, pid, "true" if on else "false", name, sub))
    w('</nav>')

    # =========================================================== page: video
    w('<div class="page" id="pg-video" role="tabpanel">')
    w('<p class="lede">Nine clips: generated, downloaded, filmed on the phone, injected with '
      'fake metadata, and AI-generated. TikTok read <b>every</b> provenance field each file '
      'carried, invented nothing for the files that had none, and validated nothing on the file '
      'that lied. None of it survived TikTok’s own re-encode &mdash; but on the AI clip it '
      '<b>added</b> a label of its own. And a clip edited outside the app can be made to read '
      'exactly like camera footage.</p>')
    w('<div class="tiles">')
    for cls, big, small in [("", "898", "things it read"),
                            ("is-bad", "10", "identity fields it took"),
                            ("is-warn", "18&times;", "times it re-read your GPS"),
                            ("is-good", "0", "survived the re-encode"),
                            ("is-new", "1", "AI label it added")]:
        w('<div class="tile %s"><b>%s</b><span>%s</span></div>' % (cls, big, small))
    w('</div>')

    # -------------------------------------------------------------- limits
    w('<section><h2>Read this before the table</h2>')
    w('<div class="panel is-warn"><h3>Three limits on what this proves</h3><ul>')
    w('<li><b>It shows what TikTok reads, never what TikTok concludes.</b> Every row is a call '
      'the app made. Nothing here shows a score, a threshold, or a ranking effect. Any claim that '
      'a metadata rewrite moves reach is outside this evidence.</li>')
    w('<li><b>Only clip 6 (CANARY) was traced past the encoder.</b> It is the one arm with a '
      're-encode dump. For the other seven we can say what was '
      '<em>read</em>, not what survived.</li>')
    w('<li><b>The AI label is confirmed. What removes it is not.</b> Clip 7 (AI) got '
      '<code>aigc_info</code> written into its export. Clips 8 (AI STRIPPED) and 9 (NATIVIZED) '
      'carry the same footage and did not &mdash; and that absence is trustworthy, because the '
      'value is recorded even where key names are not. But both of those also went through a '
      'different encoder path (<code>isFastImport</code> 1 against clip 7&rsquo;s 0), so we '
      'changed two things at once and cannot say which one dropped the label.</li>')
    w('<li><b>We never saw the uploaded bytes.</b> The TLS hook captured the CDN request '
      '<em>headers</em> — 1 774 bytes announcing <code>Content-Length: 34384</code> — but '
      'none of that 34 KB body. The re-encode feeding it is measured clean, so the upload almost '
      'certainly is too, but that last step is inference, not observation. A second publish call '
      '(<code>/aweme/v1/aweme/post/</code>) was never seen either: attaching the hook killed the '
      'app both times, ~51s in, right after the success haptic.</li>')
    w('</ul></div></section>')

    # --------------------------------------------------------- THE TABLE
    w(matrix_section(runs))

    # ------------------------------------------------------ what they check
    w(census_section(runs))

    # ------------------------------------------------------------- funnel
    w(funnel_section(canary_ids))

    # ---------------------------------------------------------------- AIGC
    w(aigc_section(runs))

    # ------------------------------------------------------------ playbook
    w(playbook_section(dumps, chain))

    # ------------------------------------------------------- the pass test
    w(passtest_section(runs))

    w('</div>')  # end page: video

    # ========================================================== page: photos
    w('<div class="page" id="pg-photos" role="tabpanel" hidden>')
    w('<p class="lede">Five stills, posted the same way. The video finding was that TikTok takes '
      'everything <em>on the file you post</em>. The photo finding is worse than that, and it '
      'is not the same claim: the picker reads the metadata of <b>every image in the roll</b>, '
      'including the ones you never touch.</p>')
    first_gps = [iruns[c["id"]]["tags"].get("image {GPS} Latitude") for c in IMAGE_RUNS]
    secs = [m["first_seen_s"] for m in first_gps if m and m.get("first_seen_s")]
    w('<div class="tiles">')
    for cls, big, small in [
            ("is-bad", "7 of 7", "unposted photos it still read"),
            ("", str(sum(len(v) for v in ikeys.values())), "fields it read off a photo"),
            ("is-warn", "%.1f s" % min(secs) if secs else "?", "before you chose anything"),
            ("is-new", str(len(ikeys.get("{MakerApple}", []))), "private Apple tags"),
            ("is-bad", "3", "per-shot UUIDs among them")]:
        w('<div class="tile %s"><b>%s</b><span>%s</span></div>' % (cls, big, small))
    w('</div>')
    w(images_section(iruns, idumps, var))
    w(variance_section(var))
    w('</div>')  # end page: photos

    # ------------------------------------------------- method, shared by both
    w(method_section(runs, raw_total, fact_total))

    w('</div>')  # .wrap

    # ----------------------------------------------------------- appendix
    w('<div class="wrap tail"><section><h2>Appendix</h2>')
    w('<p>The complete ledger and the unedited run files. Nothing above depends on reading '
      'any of it.</p>')
    w(ledger_section(runs))
    w(raw_section(runs))
    w('<p class="cap">Generated from <code>runs/&lt;id&gt;/tags.json</code> by '
      '<code>artifacts/build_clean_artifact.py</code>. %d raw tag reads collapsed to %d distinct '
      'facts; every raw row is reachable above.</p>' % (raw_total, fact_total))
    w('</section></div>')
    w(SCRIPT)

    out = "\n".join(P)
    with open(OUT, "w", encoding="utf-8") as f:
        f.write(out)
    print("wrote %s (%.1f KB)" % (OUT, len(out.encode("utf-8")) / 1024))


# --------------------------------------------------------------- components

def decode_blob(v):
    """QuickTime uiso payloads are a 4-byte header then ASCII. Show the text."""
    m = re.search(r"bytes = 0x([0-9a-f ]+)", v)
    if not m or "..." in v:
        return None
    raw = bytes.fromhex(m.group(1).replace(" ", ""))
    body = raw[4:]
    if body and all(32 <= b < 127 for b in body):
        return body.decode("ascii")
    return None


BUCKET = {"written": "_written", "track": "_track", "library": "_library",
          "input": "_input"}

# Which container an atom actually lives in, from its own prefix.
ATOM_CONTAINER = [("mdta/", "Keys", "keys"), ("udta/", "UserData", "userdata"),
                  ("uiso/", "UserData", "userdata"), ("itsk/", "iTunes", "itemlist"),
                  ("id3/", "ID3", "itemlist")]


def atom_badge(atom):
    for pre, name, cls in ATOM_CONTAINER:
        if atom.startswith(pre):
            return name, cls
    return "", ""


def clip_cell(runs, c, atom, src):
    """One clip's value for one atom, however that atom chooses to be awkward."""
    if atom == "__resolution__":
        w_ = runs[c["id"]]["_library"].get("pixelWidth")
        h_ = runs[c["id"]]["_library"].get("pixelHeight")
        f = ({"value": "%s x %s" % (w_["value"], h_["value"]), "reads": w_["reads"]}
             if w_ and h_ else None)
    else:
        f = runs[c["id"]][BUCKET.get(src, "_input")].get(atom)
    if not f:
        return '<td class="off">&mdash;</td>'
    if f["value"].startswith("{length ="):
        txt = decode_blob(f["value"])
        if txt:
            return '<td class="on">%s<i>decoded from the atom</i></td>' % esc(txt)
        nb = re.search(r"length = (\d+)", f["value"]).group(1)
        return '<td class="blob">blob<i>%s B, unparsed</i></td>' % fmt_bytes(nb)
    comp = runs[c["id"]]["_comp"].get(atom)
    rd = ('<i>read %d&times;</i>' % comp["reads"]) if comp else ''
    murky = c.get("blended") and src != "written"
    if murky:
        rd = '<i>from the picker walk, not the posted file</i>'
    return ('<td class="on%s">%s%s</td>'
            % (" murky" if murky else "", esc(f["value"][:40]), rd))


def leftover_groups(runs, cols):
    """Every atom the curated groups above do not already name.

    The point of the table is that TikTok takes everything, so a table showing
    a chosen twenty of fifty-two undercuts its own argument.
    """
    # keyed on (atom, phase): the same four-character code read off the source
    # and written into the export are two different facts, and collapsing them
    # would silently drop a whole group
    named = {(f[1], f[3] if len(f) > 3 else "input")
             for _g, _c, fields in TABLE_GROUPS for f in fields}
    out = []
    for src, gname, gcls, note in [
            ("input", "Everything else it read off the file", "is-warn",
             "Not selected for the story above — the rest of what the picker walked."),
            ("written", "Everything else it wrote into its export", "is-new",
             "TikTok's own encoder block, read back off the file it produced."),
            ("library", "Asked of the Photos library, not the file", "is-dim",
             "Properties of the asset, which the bytes never carried."),
            ("track", "Track level", "is-dim", "Codec of the video track.")]:
        atoms = set()
        for c in cols:
            atoms |= set(runs[c["id"]][BUCKET[src]])
        rest = sorted(a for a in atoms if (a, src) not in named)
        if not rest:
            continue
        out.append((gname, gcls, note,
                    [(atom_name(a), a, atom_badge(a)[0], src) for a in rest]))
        named |= {(a, src) for a in rest}
    return out


def matrix_section(runs):
    cols = [r for r in RUNS if r["key"] != "publish" and r.get("table", True)]
    o = []
    a = o.append
    a('<section><h2>What they got from each clip</h2>')
    a('<p>One clip per emptied camera roll, one Frida session each, so no value below is '
      'contaminated by a neighbouring file. A dash means the field was not on that file — and '
      'TikTok did not invent it. The first seven groups are the ones that carry the argument; '
      'the rest of what it touched follows underneath, so the table is the whole set rather '
      'than a selection from it.</p>')
    a('<div class="mtx-wrap wide"><table class="mtx"><thead>')
    a('<tr><th class="cnr" rowspan="2">Field</th><th class="cnr in" rowspan="2">In</th>')
    for c in cols:
        a('<th class="%s"><em>%s</em><b>%d</b> %s%s</th>'
          % (c["cls"], esc(c["origin"]), c["n"], esc(c["label"]),
             '<u class="blend">blended</u>' if c.get("blended") else ''))
    a('</tr><tr>')
    for c in cols:
        a('<th class="sub">%s</th>' % esc(c["note"]))
    a('</tr></thead><tbody>')
    for gname, gcls, fields in TABLE_GROUPS:
        a('<tr class="grp %s"><td colspan="%d">%s</td></tr>' % (gcls, len(cols) + 2, esc(gname)))
        for field in fields:
            label, atom, ctr = field[0], field[1], field[2]
            src = field[3] if len(field) > 3 else "input"
            a('<tr><td class="fld">%s</td><td class="in"><span class="ct %s">%s</span></td>'
              % (esc(label), ctr.lower(), ctr))
            for c in cols:
                a(clip_cell(runs, c, atom, src))
            a('</tr>')

    # completeness: the atoms the curated groups above do not name
    for gname, gcls, note, fields in leftover_groups(runs, cols):
        a('<tr class="grp %s"><td colspan="%d">%s &nbsp;<span class="gd">%s</span>'
          '</td></tr>' % (gcls, len(cols) + 2, esc(gname), esc(note)))
        for label, atom, ctr, src in fields:
            a('<tr><td class="fld">%s</td><td class="in">%s</td>'
              % (esc(label),
                 ('<span class="ct %s">%s</span>' % (atom_badge(atom)[1], ctr))
                 if ctr else ""))
            for c in cols:
                a(clip_cell(runs, c, atom, src))
            a('</tr>')
    # closing summary rows
    a('<tr class="grp is-new"><td colspan="%d">Outcome</td></tr>' % (len(cols) + 2))
    a('<tr><td class="fld">identity fields taken</td><td class="in"></td>')
    for c in cols:
        if c.get("blended"):
            a('<td class="off">n/a</td>')
            continue
        n = len([f for f in runs[c["id"]]["_input"].values()
                 if f["atom"] in PROVENANCE_ATOMS])
        a('<td class="%s">%s</td>' % ("cnt" if n else "off", n if n else "&mdash;"))
    a('</tr>')
    a('<tr><td class="fld">survived the re-encode</td><td class="in"></td>')
    for c in cols:
        a('<td class="%s">%s</td>'
          % ("zero" if c["key"] == "canary" else "off",
             "0 of 10" if c["key"] == "canary" else "not traced"))
    a('</tr>')
    a('</tbody></table></div>')
    a('<div class="keyline">')
    for cls, txt in [("is-good", "Recorded on the phone — the real thing"),
                     ("is-new", "Injected by us — fake values, read verbatim"),
                     ("is-warn", "Injected, but GPS written to XMP — never parsed"),
                     ("is-dim", "Generated or downloaded — nothing to take")]:
        a('<span class="%s"><i></i>%s</span>' % (cls, txt))
    a('</div>')
    a('<p class="cap"><b>Clip 8 (AI STRIPPED) is blended.</b> Its Recents still held four clips, so the picker '
      'deep-walked all of them and its INPUT column mixes files &mdash; including a leftover '
      'TikTok export, which is why a TEEditor JSON string shows up under device software. Only '
      'its <em>written</em> row is attributable to the clip that was posted. Every other column '
      'had exactly one item in Recents.</p>')
    a('<p class="cap"><b>On the AI-label row,</b> a dash is real evidence. Most exports report '
      'their fields as numbered keys rather than names, but the rig records the <em>value</em> '
      'either way &mdash; and the string <code>aigc_label_type</code> appears in exactly one '
      'export across all nine clips.</p>')
    a('<p class="cap"><b>Two rows that look like findings and are not.</b> The audio encoder '
      'string (<code>id3/TSSE</code>) tracks the backing-music file TikTok loads rather than '
      'your video, so clips sharing a track share the value. The <code>itsk</code> block is '
      'TikTok&rsquo;s own encoder writing to itself. Both are listed because the table claims '
      'to be complete, not because they say anything about the clip you posted.</p>')
    a('<p class="cap"><b>Still deliberately out:</b> thumbnail properties, which are interface '
      'bitmaps rather than your video, and filesystem dates, which cover TikTok&rsquo;s own '
      'drafts and exports as well as your file. Both are in the ledger.</p>')
    a('<p class="cap">Read clip 2 (STAMPED) against clip 6 (CANARY). Both were faked by hand. Clip 2 put its GPS in an '
      'XMP packet and TikTok read that packet as an opaque blob, parsing no coordinate. Clip 6 '
      'put the same kind of value in a QuickTime key and it came back 18 times. Same rig, one '
      'container apart.</p>')
    a('</section>')
    return "\n".join(o)


def census_section(runs):
    solo = [r for r in RUNS if r["key"] != "publish"]
    tally = []
    for name, cls, pill, desc, match in CENSUS:
        facts, reads = 0, 0
        for r in solo:
            for f in runs[r["id"]]["_facts"]:
                if match(f["atom"]):
                    facts += 1
                    reads += f["reads"] or 0
        tally.append((name, cls, pill.replace("Pill: ", ""), desc, facts, reads))
    mx = max(t[5] for t in tally) or 1
    # order by what it exposes, not by volume: the loudest reads are the least
    # interesting ones, and sorting on reads buries the identity fields.
    sev = {"is-bad": 0, "is-new": 1, "is-warn": 2, "is-dim": 3}
    o = []
    a = o.append
    a('<section><h2>What they check for, and what it tells them</h2>')
    a('<p>Every distinct thing read across the six sessions, grouped by what it reveals. The bar '
      'is how often it was read, not how many fields there are — TikTok re-polls the whole '
      'metadata set continuously while you sit on the compose screen.</p>')
    a('<div class="census">')
    a('<div class="cen cen-h"><span>What it reads</span><span>How hard it looks</span>'
      '<span class="ct">reads</span><span>Tells them</span></div>')
    for name, cls, pill, desc, facts, reads in sorted(
            tally, key=lambda t: (sev.get(t[1], 3), -t[5])):
        a('<div class="cen %s"><div class="nm">%s<small>%s</small></div>'
          '<div class="bar"><i style="width:%d%%"></i></div>'
          '<div class="ct">%s</div><span class="pill">%s</span></div>'
          % (cls, esc(name), esc(desc), max(2, int(100 * reads / mx)),
             fmt_bytes(reads), esc(pill)))
    a('</div>')
    a('<p class="cap">Ordered by what it gives away, not by how loud it is. Note the bars: the '
      'four blocks that identify you are the <em>quietest</em> things TikTok reads &mdash; '
      'thumbnails and library dimensions dominate the volume and are identical whoever posts. '
      'A few hundred quiet reads are the whole exposure.</p>')
    a('</section>')
    return "\n".join(o)


def funnel_section(canary_ids):
    n = len(canary_ids)
    o = []
    a = o.append
    a('<section><h2>Where it goes, and where it dies</h2>')
    a('<p>Traced on clip 6 (CANARY), the only arm with dumps downstream of the picker. Three of '
      'the four stages are measured. The fourth is where the instrumentation ran out.</p>')
    a('<div class="flow">')
    for i, (cls, big, lab, sub) in enumerate([
            ("is-new", str(n), "on the file", "identity fields written with exiftool, still "
                                              "all present after the Photos import"),
            ("is-new", str(n), "read by TikTok", "every one, 2&times; at the picker then "
                                                 "18&times; on compose"),
            ("is-bad", "0", "survive the re-encode", "measured on the pulled file: only "
                                                     "TEEditor / Lavf57.71.100 remain"),
            ("is-dim", "?", "on the wire", "never captured &mdash; we logged the request "
                                           "headers, not the 34 KB body")]):
        if i:
            a('<div class="arw">&#8594;</div>')
        a('<div class="stg %s"><b>%s</b><span>%s</span><em>%s</em></div>'
          % (cls, big, lab, sub))
    a('</div>')
    a('<div class="rows">')
    a('<div class="row is-bad"><b>Exposure is on-device</b><span>The picker and the encoder '
      'read the file in full. That is where your camera location and device identity are '
      'exposed — to the app, on the handset, before anything is sent.<span>Measured '
      'directly, on all six clips.</span></span><span class="end">Confirmed</span></div>')
    a('<div class="row is-bad"><b>The re-encode drops all of it</b><span>The file TikTok built '
      'for upload, pulled back off the phone, holds none of the ten fields. What it holds '
      'instead is TikTok&rsquo;s own block.<span><code>Hw</code>, <code>Bitrate</code>, '
      '<code>Copyright</code>, <code>Software</code> (a TEEditor JSON blob), <code>Source</code>, '
      '<code>Encoder=Lavf57.71.100</code> — nine keys, none of them yours.</span></span>'
      '<span class="end">Confirmed</span></div>')
    a('<div class="row is-warn"><b>The upload itself is unmeasured</b><span>The TLS hook logged '
      'the CDN request headers and stopped. We have the declared '
      '<code>Content-Length: 34384</code> but not one byte of that payload, so the wire capture '
      'cannot say what it contained.<span>The re-encode feeding it is clean, which makes a clean '
      'upload very likely — but that is inference, not observation. A separate '
      '<code>aweme_v1</code> JSON call was never seen at all.</span></span>'
      '<span class="end">Open</span></div>')
    a('</div></section>')
    return "\n".join(o)


def aigc_section(runs):
    """The one thing TikTok ADDS rather than strips."""
    ai = runs["unique-8-ai-2"]
    strip = runs["unique-9-stripped"]
    lab = ai["_written"].get("mdta/aigc_info")
    o = []
    a = o.append
    a('<section><h2>The one thing TikTok adds: an AI label</h2>')
    a('<p>Every field so far was something TikTok <em>took</em>. Clip 7 (AI) is the opposite. It is an '
      'AI-generator export carrying no C2PA, no Sora or OpenAI string, nothing that announces what '
      'made it &mdash; and TikTok still wrote a label into the file it produced.</p>')
    a('<div class="rows">')
    a('<div class="row is-new"><b>aigc_info</b><span>Written into the export at %.1fs, read back '
      '%d&times;. The value is <code>%s</code>.<span>It appears in no other arm. A string search '
      'across all eight sessions finds <code>aigc_label_type</code> only here and in the '
      'follow-up that re-read this same file.</span></span>'
      '<span class="end">Confirmed</span></div>'
      % (lab["first"] or 0, lab["reads"], esc(lab["value"])))
    a('<div class="row is-warn"><b>Nothing in the source declared it</b><span>The clip carried '
      '<code>Lavf58.76.100</code> and nothing else. No C2PA manifest, no provenance sidecar, no '
      'generator name.<span>So the label was not copied forward from the file. TikTok decided it '
      'some other way &mdash; from the pixels, from the upload context, or from something we '
      'cannot see on the handset.</span></span><span class="end">Unexplained</span></div>')
    a('<div class="row is-dim"><b>The Sora demo sat beside it</b><span>A public OpenAI Sora clip '
      '(<code>IMG_0028</code>, 29.7 MB) was in the same camera roll and got picker-walked, but it '
      'was not the posted file.<span>Worth noting for a different reason: its XMP carries an After '
      'Effects project path from an OpenAI shared drive. Real provenance leaks are usually this '
      'boring.</span></span><span class="end">Context</span></div>')
    a('</div>')
    a('<div class="compare">')
    a('<div class="panel is-new"><h3>Clip 7 (AI) &mdash; posted as it came</h3><div class="fld sm">')
    for k in sorted(ai["_written"]):
        f = ai["_written"][k]
        nm = k.split("/", 1)[1]
        a('<div><b>%s</b><code>%s</code></div>' % (esc(nm), esc(f["value"][:52])))
    a('</div></div>')
    a('<div class="panel is-warn"><h3>Clip 8 (AI STRIPPED) &mdash; wiped, re-posted</h3><div class="fld sm">')
    a('<div><b>No AI label, and a second variable</b>The <code>aigc_label_type</code> value '
      'appears nowhere in this export, and the rig records values even for keys it cannot name '
      '&mdash; so the label really was not written. But this export also came through a different '
      'encoder path: <code>isFastImport</code> was <code>1</code> here against <code>0</code> on '
      'clip 7, and its fields arrive numbered rather than named. Two things changed at once.</div>')
    for k in sorted(strip["_written"]):
        f = strip["_written"][k]
        nm = k.split("/", 1)[1]
        if nm.startswith("%00"):
            nm = "field " + str(int(nm[-2:], 16))
        a('<div><b>%s</b><code>%s</code></div>' % (esc(nm), esc(f["value"][:52])))
    a('</div></div>')
    a('</div>')
    a('<p class="cap">Both panels are the block TikTok wrote into its own export. Clip 7 named '
      'its fields; clip 8 numbered them. Either way the values are captured, and '
      '<code>aigc_label_type</code> is in only one of them. What stays open is <em>why</em>: the '
      'clip that got labelled is also the only one TikTok fully re-encoded, so stripping the file '
      'and taking a different encoder path are still confounded.</p>')
    a('</section>')
    return chr(10).join(o)


def passtest_section(runs):
    """Arms 5 and 9: can a file edited elsewhere read as a native capture?"""
    cam = runs["unique-5-camera"]
    nat = runs["unique-11-nativized-solo"]
    v1 = runs["unique-10-nativized"]

    def atoms(d, phase):
        return {f["atom"]: f for f in d["_facts"] if f["phase"] == phase
                and (f["atom"].startswith("mdta/") or f["atom"].startswith("udta/"))}

    ci, ni = atoms(cam, "INPUT"), atoms(nat, "INPUT")
    cc, nc = atoms(cam, "video metadata"), atoms(nat, "video metadata")
    only = sorted(set(ci) ^ set(ni))
    v1_extra = sorted(set(atoms(v1, "INPUT")) - set(ci))

    o = []
    a = o.append
    a('<section><h2>Can a clip edited somewhere else pass as a native capture?</h2>')
    a('<p>The in-app editor is limited, so the practical question is whether a clip cut in real '
      'software can be restamped to read the way camera footage reads. Arm 9 is that test: the AI '
      'clip from arm 7, re-encoded and stamped from a genuine capture taken on the same phone '
      'minutes earlier, posted into an emptied camera roll so every read is attributable.</p>')
    a('<div class="tiles">')
    for cls, big, small in [("is-good", "%d" % len(ni), "atoms read, same as a real capture"),
                            ("is-good", str(len(only)), "atoms on one arm but not the other"),
                            ("is-good", "hvc1", "codec, matching"),
                            ("is-warn", str(len(v1_extra)), "tell on the first attempt")]:
        a('<div class="tile %s"><b>%s</b><span>%s</span></div>' % (cls, big, small))
    a('</div>')

    a('<div class="mtx-wrap"><table class="mtx"><thead><tr>'
      '<th class="cnr">Field</th>'
      '<th class="is-good"><em>I FILMED IT</em><b>5</b> CAMERA</th>'
      '<th class="is-good"><em>I MADE IT PASS</em><b>9</b> NATIVIZED</th>'
      '<th class="cnr">Picker</th><th class="cnr">Compose</th></tr></thead><tbody>')
    for at in sorted(set(ci) | set(ni),
                     key=lambda x: (0 if x.startswith("mdta") else 1, x)):
        c, n = ci.get(at), ni.get(at)
        cell = lambda f: ('<td class="on">%s</td>' % esc(f["value"][:34])) if f             else '<td class="off">&mdash;</td>'
        rd = "%s / %s" % (c["reads"] if c else "—", n["reads"] if n else "—")
        cx, nx = cc.get(at), nc.get(at)
        rc = "%s / %s" % (cx["reads"] if cx else "—", nx["reads"] if nx else "—")
        a('<tr><td class="fld">%s</td>%s%s<td class="off">%s</td><td class="off">%s</td></tr>'
          % (esc(atom_name(at)), cell(c), cell(n), rd, rc))
    a('</tbody></table></div>')
    a('<p class="cap">Read counts are <b>camera / nativized</b>. Both arms were solo windows, so '
      'nothing else in the library could contribute a value.</p>')

    a('<div class="rows">')
    a('<div class="row is-good"><b>It passes</b><span>Every atom the real capture yielded, the '
      'restamped clip yielded too, at the same two-phase cadence: twice on the picker walk, then '
      're-polled through the compose screen. Codec <code>hvc1</code> on both, and PhotoKit reports '
      '1080&times;1920 for both.<span>Both runs even landed on the same total, 85 tags.</span>'
      '</span><span class="end">Confirmed</span></div>')
    if v1_extra:
        a('<div class="row is-warn"><b>The first attempt did not</b><span>An earlier build left '
          'ffmpeg&rsquo;s own signature on the file &mdash; <code>%s</code> &mdash; and TikTok read '
          'it. A file claiming to be an iPhone capture while carrying an ffmpeg muxer string '
          'contradicts itself.<span>A real capture has no <code>UserData</code> atoms at all, so '
          'the fix is to strip anything the reference does not carry rather than only writing what '
          'it does.</span></span><span class="end">Fixed</span></div>'
          % esc(", ".join(v1_extra)))
    a('<div class="row is-dim"><b>Two things still differ</b><span>A real portrait capture stores '
      'the picture landscape with a &minus;90 rotation matrix, and carries three '
      '<code>mebx</code> timed-metadata tracks. An edit bakes the rotation in and has neither.'
      '<span>Displayed size is identical, and across every arm here TikTok was never observed '
      'reading track structure or the rotation matrix.</span></span>'
      '<span class="end">Unread</span></div>')
    a('<div class="row is-warn"><b>This says nothing about reach</b><span>It shows the file reads '
      'the same. Whether that changes distribution is not measurable with this rig and was not '
      'measured.<span>What it does do is remove metadata as a variable.</span></span>'
      '<span class="end">Out of scope</span></div>')
    a('</div>')
    a('<p class="cap">Reproduced by <code>nativize.py</code> in the repo: it copies every field '
      'from a real capture, re-encodes to <code>hvc1</code> at the reference&rsquo;s size and rate, '
      'strips anything the reference lacks, then diffs the result against it.</p>')
    a('</section>')
    return chr(10).join(o)



def playbook_section(dumps, chain):
    o = []
    a = o.append
    a('<section><h2>How to make a clip look like a real iPhone recording</h2>')
    a('<p>Clip 5 (CAMERA) is the reference implementation: a genuine iPhone X capture, so whatever it '
      'carries is by definition what a legitimate file looks like. Clip 6 (CANARY) proves TikTok checks '
      'none of it for plausibility — arbitrary strings came back verbatim. So the job is to '
      'match the shape, not to be convincing.</p>')

    a('<div class="compare">')
    a('<div class="panel is-good"><h3>What a real iPhone X file carries</h3><div class="fld">')
    cam = dumps.get("camera") or {}
    for k, why in [("Keys:Make", "always the string Apple"),
                   ("Keys:Model", "the marketing name, not the identifier"),
                   ("Keys:Software", "the iOS build the clip was shot on"),
                   ("Keys:CreationDate", "local time with a real UTC offset"),
                   ("Keys:GPSCoordinates", "lat, lon, altitude — where you filmed"),
                   ("Keys:LocationAccuracyHorizontal", "metres of GPS uncertainty")]:
        a('<div><b>%s</b>%s<code>%s</code></div>'
          % (esc(k.split(":")[1]), esc(why), esc(str(cam.get(k, "—"))[:44])))
    a('</div></div>')
    a('<div class="panel is-warn"><h3>What gives a fake away anyway</h3><div class="fld">')
    for t, d in [("Codec", "iPhone shoots HEVC (<code>hvc1</code>). A stamped ffmpeg clip is "
                           "usually H.264 (<code>avc1</code>) and the mismatch is visible in the "
                           "same read."),
                 ("Track layout", "The real capture carries five tracks — video, audio and three "
                                  "timed-metadata tracks. exiftool cannot add those."),
                 ("Photos sourceType", "Every file you import reads as user-library, whatever its "
                                       "atoms say. Only a clip actually recorded on the device is "
                                       "a camera original."),
                 ("Resolution and rate", "1920&times;1080 at 30fps for this model. A 720&times;1280 "
                                         "testcard with an Apple stamp contradicts itself.")]:
        a('<div><b>%s</b>%s</div>' % (esc(t), d))
    a('</div></div>')
    a('</div>')

    a('<div class="brief"><div class="brief-hd"><span>the stamp</span>'
      '<button class="copy" type="button" data-copy="cmd1">Copy</button></div>'
      '<pre id="cmd1">%s</pre></div>' % esc(LEGIT_CMD))

    a('<div class="rows">')
    a('<div class="row is-new"><b>Use Keys, never XMP</b><span>QuickTime <code>Keys:</code> is '
      'the container TikTok parses. XMP is read as an opaque blob and no value is extracted from '
      'it.<span>Clip 2 (STAMPED) wrote GPS to XMP only and TikTok never produced a coordinate. Clip 6 (CANARY) wrote '
      'it to Keys and got read 18 times.</span></span><span class="end">The whole trick</span></div>')
    a('<div class="row is-new"><b>GPSCoordinates, not GPSLatitude</b><span>exiftool has no '
      '<code>Keys:LocationISO6709</code>. <code>Keys:GPSCoordinates</code> is the tag that lands '
      'as the mdta ISO 6709 atom the app actually reads.</span>'
      '<span class="end">Easy to miss</span></div>')
    a('<div class="row is-warn"><b>Re-check after the Photos import</b><span>Photos rewrites '
      'imported files. Clip 2 (STAMPED) went in at 16 524 B and came back stripped to about 9 459 B, '
      'which silently invalidates your stamp.<span>Pull the file back off the device and re-dump '
      'before you trust it. The canary survived intact, which is why clip 6 is '
      'usable.</span></span><span class="end">Verify</span></div>')
    a('<div class="row is-dim"><b>Values need not be real</b><span>TikTok range-checked nothing. '
      '<code>CANARYMK-7F3A</code> and a GPS reading of 11.1111, 22.2222 were both accepted and '
      'read back unchanged.</span><span class="end">Proven</span></div>')
    a('</div>')

    a('<p class="cap">Left: the clip after Photos imported it &mdash; the stamp is intact, so '
      'Photos is not what destroyed it. Right: what TikTok built for upload. Same clip, one '
      'encoder apart.</p>')
    a('<div class="two">')
    for name, note, dump in chain:
        if not dump:
            continue
        sig = {k: v for k, v in dump.items() if is_signal(k)}
        cls = "is-good" if "after-index" in name else "is-bad"
        a('<div class="panel %s"><h3>%s <em class="hcnt">%d tags</em></h3>'
          '<p class="pn">%s</p>' % (cls, esc(name), len(sig), esc(note)))
        a('<div class="fld sm">')
        # grouped by the container they live in: the Keys / UserData / XMP split
        # is the finding, so it has to be legible here. No truncation.
        for grp in ("Keys", "UserData", "ItemList", "XMP"):
            gk = sorted(k for k in sig if container_of(k) == grp)
            if not gk:
                continue
            a('<div class="grph"><span class="ct %s">%s</span></div>'
              % (grp.lower(), grp))
            for k in gk:
                a('<div><b>%s</b><code>%s</code></div>'
                  % (esc(k.split(":", 1)[1]), esc(str(sig[k])[:56])))
        if not sig:
            a('<div class="gone"><b>Nothing identity-bearing left</b>All ten fields are gone. '
              'What the file carries instead is TikTok&rsquo;s own encoder block, above.</div>')
        a('</div></div>')
    a('</div>')
    a('</section>')
    return "\n".join(o)


def ivals(tags, key):
    """A tag value is a bare string when one was seen and a list when several."""
    m = tags.get(key)
    if not m:
        return []
    v = m["value"]
    return [str(x) for x in (v if isinstance(v, list) else [v])]


def exif_field(dump, short):
    """What one photo actually carries for a field TikTok read.

    The run files pool values per tag key with no file handle attached, so the
    only way to say which photo held which value is to go back to the files
    themselves. Returns None when that photo does not carry the field at all.
    """
    block, _, name = short.partition("} ")
    block = block.lstrip("{")
    if not name or block == "MakerApple" or dump is None:
        return None
    name = IMAGE_EXIF_ALIAS.get(short, name)
    if block == "GPS" and not name.startswith("GPS"):
        name = "GPS" + name
    for k, v in dump.items():
        if k.split(":")[-1] == name:
            return v
    return None


def apple_field(dump, key, iruns):
    """What a photo holds in Apple's numbered block.

    These tags have no names to match on and some are binary blobs, so exact
    lookup is not possible. It does not need to be: exactly one arm carries an
    Apple block at all, so every maker-note value the rig saw came off that
    file and the others genuinely have nothing. Showing a dash for a blob we
    simply failed to match would claim the opposite.
    """
    if dump is None or not any(k.startswith("Apple:") for k in dump):
        return None
    for run in iruns.values():
        vals = ivals(run["tags"], key)
        if vals:
            return " · ".join(vals)
    return None


def image_keys(iruns):
    """Every image field any stills run saw, grouped by CGImageSource dict.

    Built from the runs rather than a hand-kept list: a curated table silently
    goes stale the moment the app reads something new, and a table claiming to
    be complete has to actually be complete.
    """
    lead = {"{TIFF}": ["Make", "Model", "Software", "HostComputer", "DateTime"],
            "{GPS}": ["Latitude", "Longitude", "Altitude"],
            "{Exif}": list(IMAGE_TIME_KEYS)}
    out = {}
    seen = set()
    for run in iruns.values():
        seen |= {k for k in run["tags"] if k.startswith("image")}
    for key in seen:
        short = key[len("image "):]
        m = re.match(r"^(\{[^}]+\})(?:\s+(.*))?$", short)
        if m and not m.group(2):
            continue                    # the bare "(block, opened below)" row
        block = m.group(1) if m else "(top level)"
        out.setdefault(block, []).append((key, short))
    for block, rows in out.items():
        first = lead.get(block, [])

        def rank(item):
            name = item[1].split("} ")[-1]
            if block == "{MakerApple}":
                return (0, int(name) if name.isdigit() else 9999, name)
            return (first.index(name) if name in first else len(first), 0, name)
        rows.sort(key=rank)
    return out


# Three real captures, deliberately varied: same spot wide then 2x tele
# (which isolates the lens), then indoors with flash in portrait. Enough to
# move every field that moves.
VARIANCE_DIR = "testfiles/variance"

# Printing these would put coordinates and per-shot UUIDs on the page. The
# fact that they vary is the finding; the values are not.
VARIANCE_REDACT = ("GPS", "Identifier", "Serial", "AccelerationVector",
                   "RunTimeValue", "SubjectArea")

# What a forgery has to do about each group, which is the point of the table.
VARIANCE_GROUPS = [
    ("IFD0", "Device identity", "is-bad"),
    ("ExifIFD", "Camera settings", "is-warn"),
    ("GPS", "Position", "is-bad"),
    ("Apple", "Apple private block", "is-new"),
    ("ICC_Profile", "Colour profile", "is-dim"),
]


# The three captures, in the order they were taken. Labels rather than file
# names: what the shot was is the thing that explains why a value moved.
VARIANCE_SHOTS = [("1\u00d7 wide", "outdoors, wide lens, landscape"),
                  ("2\u00d7 tele", "same spot seconds later, telephoto"),
                  ("flash", "indoors, flash fired, portrait")]


def variance(paths):
    """Which fields hold still across shots from one phone, and which move."""
    dumps = []
    for path in paths:
        d = exif(path)
        if d:
            dumps.append(d)
    if len(dumps) < 2:
        return None
    seen, vals = {}, {}
    for d in dumps:
        for k, v in d.items():
            g = k.split(":")[0]
            if g in ("File", "Composite", "ICC-header", "Meta", "QuickTime", "XMP-x"):
                continue
            seen[k] = seen.get(k, 0) + 1
            vals.setdefault(k, set()).add(str(v))
    labels = [VARIANCE_SHOTS[i] if i < len(VARIANCE_SHOTS)
              else ("shot %d" % (i + 1), "") for i in range(len(dumps))]
    return dict(n=len(dumps), seen=seen, vals=vals, dumps=dumps, labels=labels)


def variance_section(var):
    """What the corpus said that a per-field column cannot say.

    The constant-or-varying verdict now lives in the main table, one column
    per field. What is left here is the part that is about relationships
    between fields, which no single row can carry.
    """
    o = []
    a = o.append
    a('<section><h2>Fields that cannot be filled in independently</h2>')
    if not var:
        a('<p class="cap">Not built: the corpus of real captures is not in the repository, '
          'being personal photographs.</p></section>')
        return "\n".join(o)
    a('<p>Knowing which fields move is not enough to write one. Several are two spellings of a '
      'single quantity, or dates that have to agree, or counters that have to keep counting. '
      'Get one of those wrong and the file is inconsistent <em>with itself</em> &mdash; wrong by '
      'arithmetic, visible without any reference file to compare against.</p>')
    a('<div class="panel is-warn"><ul>')
    for head, body in [
        ("ShutterSpeedValue and ApertureValue are the other two spellings of ExposureTime "
         "and FNumber.",
         "Stored as APEX, the same quantities in log form. They must agree &mdash; and, because "
         "APEX is a rational that does not round-trip exactly, they must agree "
         "<em>inexactly</em>. On a real capture the pair reads 0.25 against 0.249994. Writing "
         "both from one float gives exact equality, which no genuine file has."),
        ("GPSDateStamp has to be the same day as DateTimeOriginal.",
         "Two dates in two different blocks describing one moment. Likewise the three "
         "OffsetTime spellings, which all have to carry the same timezone."),
        ("RunTimeValue is a nanosecond counter since the phone last booted.",
         "It moves every shot while RunTimeEpoch, RunTimeScale and RunTimeFlags hold still, so "
         "across a set of photos it has to increase monotonically and by roughly the gaps "
         "between the timestamps being claimed."),
        ("AccelerationVector is the accelerometer reading at the moment of capture.",
         "It has to be consistent with the Orientation on the same file. A portrait photo whose "
         "gravity vector says landscape is contradicting itself."),
        ("The lens is a bundle, not a field.",
         "The two rear cameras report <code>4mm f/1.8</code> and <code>6mm f/2.4</code>, so "
         "LensModel, FNumber, FocalLength and ApertureValue move together. A file pairing a "
         "4&nbsp;mm focal length with f/2.4 describes a camera that does not exist."),
        ("The frame is always landscape.",
         "ExifImageWidth and ExifImageHeight never move: every capture is stored "
         "4032&times;3024 and a portrait photo is expressed purely as "
         "<code>Orientation&nbsp;6</code> &mdash; the same trick a real recording uses when it "
         "stores video landscape with a rotation matrix."),
    ]:
        a('<li><b>%s</b> %s</li>' % (head, body))
    a('</ul></div>')
    a('<p class="cap">All of these held on all three captures, so a forgery has to hold them '
      'too. The check is in <code>analyze_stills_variance.py</code>. Values of identifying '
      'fields are never printed &mdash; that a coordinate or a UUID varies is the finding, what '
      'it says is not &mdash; and the photographs themselves stay out of the repository.</p>')
    a('</section>')
    return "\n".join(o)


# Apple's numbered tags carry no names, so only the two exiftool can name line
# up against the variance corpus. The rest get a group-level count instead.
APPLE_NUMBERED = {"{MakerApple} 17": "Apple:ContentIdentifier",
                  "{MakerApple} 43": "Apple:PhotoIdentifier"}

# CGImageSource dictionary -> the exiftool group holding the same tags
VARIANCE_BLOCK = {"TIFF": "IFD0", "Exif": "ExifIFD", "GPS": "GPS",
                  "MakerApple": "Apple"}


def variance_key(var, short):
    """The corpus key for a field the rig read, or None if they do not line up."""
    if not var:
        return None
    if short in APPLE_NUMBERED:
        k = APPLE_NUMBERED[short]
        return k if k in var["vals"] else None
    block, _, name = short.partition("} ")
    grp = VARIANCE_BLOCK.get(block.lstrip("{"))
    if not grp or not name or grp == "Apple":
        return None
    name = IMAGE_EXIF_ALIAS.get(short, name)
    if grp == "GPS" and not name.startswith("GPS"):
        name = "GPS" + name
    k = "%s:%s" % (grp, name)
    return k if k in var["vals"] else None


# A UUID printed in full is an identifier and nothing else -- that it differs
# is the whole finding. Every other value earns its place by explaining why.
VARIANCE_REDACT = ("Identifier",)


def variance_cells(var, short):
    """One cell per real capture, then the verdict."""
    n = var["n"] if var else 0
    k = variance_key(var, short)
    if k is None:
        return '<td class="off">&mdash;</td>' * (n + 1)
    out = []
    for d in var["dumps"]:
        v = d.get(k)
        if v is None:
            out.append('<td class="off">&mdash;</td>')
        elif any(w in k for w in VARIANCE_REDACT):
            out.append('<td class="on murky">set<i>value withheld</i></td>')
        else:
            # the lens strings differ only in their last nine characters, so a
            # tight truncation here would hide the one thing the row is for
            t = str(v)
            out.append('<td class="on rc">%s</td>'
                       % esc(t[:40] + ("…" if len(t) > 40 else "")))
    spread = len(var["vals"][k])
    out.append('<td class="zero">copy once</td>' if spread == 1
               else '<td class="cnt">per shot<i>%d of %d differ</i></td>' % (spread, n))
    return "".join(out)


def variance_group(var, block):
    """How a whole dictionary behaved, where rows cannot be lined up one by one."""
    grp = VARIANCE_BLOCK.get(block.strip("{}"))
    if not var or not grp:
        return ""
    keys = [k for k in var["vals"] if k.split(":")[0] == grp]
    if not keys:
        return ""
    const = len([k for k in keys if len(var["vals"][k]) == 1])
    return " · across %d real captures: %d hold still, %d move" % (
        var["n"], const, len(keys) - const)


def images_section(iruns, idumps, var):
    o = []
    a = o.append
    cols = IMAGE_RUNS
    a('<section><h2>Why these five could share one camera roll</h2>')
    a('<p>A photo costs a posting window rather than a library rebuild, so unlike the clips all '
      'five could sit in the camera roll at once &mdash; each carrying <b>its own canary id</b>, '
      'so a hit still names exactly one file. That single decision is what exposed the finding '
      'below; had they shared an id, as they were first built, every hit would have looked like '
      'the file just posted and there would have been nothing to see.</p>')

    # ------------------------------------------------- finding 1, the big one
    a('<div class="panel is-bad"><h3>It reads every photo in the picker, not the one you pick</h3>')
    a('<p>Each session posted exactly one of the five. Read a row left to right: what went out, '
      'and whose identity TikTok took while it was happening.</p>')
    a('<div class="mtx-wrap wide"><table class="mtx"><thead><tr>')
    a('<th class="cnr">The photo you posted</th>'
      '<th class="cnr">What was written on it</th>'
      '<th class="cnr">Other photos it read anyway<span class="gd">'
      ' &mdash; out of the 4 in the roll carrying any identity at all</span></th>'
      '<th class="cnr">Which ones</th>'
      '<th class="cnr">Posted file, confirmed</th></tr></thead><tbody>')
    identity_arms = [r for r in IMAGE_RUNS if r.get("mark")]
    for c in cols:
        t = iruns[c["id"]]["tags"]
        makes, lats = set(ivals(t, "image {TIFF} Make")), set(ivals(t, "image {GPS} Latitude"))
        others = [o for o in identity_arms
                  if o["key"] != c["key"] and (o["mark"] in makes or o["gps"] in lats)]
        d = idumps.get(c["key"]) or {}
        if not c.get("mark"):
            carried = '<span class="off">nothing at all</span>'
        else:
            # the ellipsis is markup, so it goes on after escaping, not before
            gps = esc(c["gps"][:10]) + ("&hellip;" if c["key"] == "icamera" else "")
            model = d.get("IFD0:Model") or d.get("XMP-tiff:Model") or ""
            carried = ('%s<i>%s%s</i>'
                       % (esc(c["mark"]),
                          (esc(str(model)) + " &middot; ") if model else "", gps))
        chips = " ".join('<span class="ct %s">%d %s</span>'
                         % ("keys" if o["key"] != "icamera" else "xmp", o["n"], esc(o["label"]))
                         for o in others)
        uti = ivals(t, "resource uniformTypeIdentifier")
        a('<tr><td class="fld sess %s"><b>%d</b> %s<i>%s</i></td>'
          '<td class="on">%s</td>'
          '<td class="cnt big">%d<i>of %d</i></td>'
          '<td class="chips">%s</td>'
          '<td class="on">%s</td></tr>'
          % (c["cls"], c["n"], esc(c["label"]), esc(c["note"]), carried,
             len(others), len(identity_arms), chips, esc(uti[0] if uti else "—")))
    a('</tbody></table></div>')
    a('<p class="cap"><b>Read the first row again.</b> The file posted that session was a flat '
      'red rectangle with no EXIF, no XMP and no GPS &mdash; nothing to take. TikTok came away '
      'with the make, model, iOS build, capture date and full coordinates of <em>four other '
      'photos</em>, your real one among them, about 6.7&nbsp;seconds after launch and before '
      'anything had been selected.</p>')
    a('<p class="cap">The last column is the control: it is the type of the file actually handed '
      'to the encoder, and it matches the intended photo in all five sessions &mdash; so the '
      'harvest is not a mix-up about which one was posted.</p>')

    # the saturated grid, kept as proof but out of the way: every cell is a hit,
    # which is the point and also why it reads as a wall rather than a finding
    a('<details class="ldg"><summary><b>The full grid</b> '
      '<em>every photo against every session &mdash; all 40 cells are hits</em></summary>')
    a('<div class="mtx-wrap"><table class="mtx"><thead><tr>')
    a('<th class="cnr">Whose metadata appeared</th><th class="cnr in">Its unique value</th>')
    for c in cols:
        a('<th class="%s"><em>posted</em><b>%d</b></th>' % (c["cls"], c["n"]))
    a('</tr></thead><tbody>')
    for gname, field, key in [("Device identity", "mark", "image {TIFF} Make"),
                              ("Location", "gps", "image {GPS} Latitude")]:
        a('<tr class="grp is-bad"><td colspan="%d">%s</td></tr>' % (len(cols) + 2, gname))
        for src in identity_arms:
            val = src[field]
            a('<tr><td class="fld">%d &middot; %s</td>'
              '<td class="in"><span class="ct keys">%s</span></td>'
              % (src["n"], esc(src["label"]), esc(val)))
            for c in cols:
                hit = val in ivals(iruns[c["id"]]["tags"], key)
                a('<td class="%s">%s</td>' % ("on" if hit else "off",
                                              "read" if hit else "&mdash;"))
            a('</tr>')
    a('</tbody></table></div></details>')
    a('</div>')

    # ------------------------------------------------- finding 2, XMP parsed
    a('<div class="panel is-warn"><h3>On photos, XMP <em>is</em> parsed — the opposite of video</h3>')
    a('<p>Photo 4 carries <b>no EXIF, no IFD0, no GPS block at all</b>. Its make and coordinates '
      'exist only inside an XMP packet. TikTok read them anyway, because ImageIO folds XMP into '
      'the same <code>{TIFF}</code> and <code>{GPS}</code> dictionaries it fills from EXIF. '
      'AVFoundation does not do this for video, which is why clip 2&rsquo;s XMP stayed an opaque '
      'blob. The video playbook rule does not carry over.</p>')
    a('<div class="mtx-wrap"><table class="mtx compact">'
      '<thead><tr><th class="cnr">Same values, one container apart</th>'
      '<th>clip 2 &middot; video</th><th>photo 4 &middot; still</th></tr></thead><tbody>')
    for lbl, vid, still in [
            ("make / model in XMP", '<span class="off">blob, 3 062 B, never parsed</span>',
             '<span class="on">CANARYMK-9B4F</span>'),
            ("GPS in XMP", '<span class="off">no coordinate ever surfaced</span>',
             '<span class="on">44.4444 / 55.5555</span>')]:
        a('<tr><td class="fld">%s</td><td>%s</td><td>%s</td></tr>' % (lbl, vid, still))
    a('</tbody></table></div></div>')

    # ---------------------------------- one table: the files and every field
    keys, gloss_missing, unmapped = image_keys(iruns), [], []
    total = sum(len(v) for v in keys.values())
    a('</section><section><h2>Every field it read, and what each photo said</h2>')
    a('<p>What the five files are, then the complete list of what TikTok pulled off them &mdash; '
      '<b>%d distinct fields</b> across the five dictionaries <code>CGImageSource</code> hands '
      'back, generated from the run files so it cannot go out of date. Each column is <b>the '
      'value that photo actually carries</b>, read back off the file with exiftool; a dash means '
      'it does not have the field at all. Photos 2 and 3 are the same picture: 3 is that photo '
      'with its identity stripped off and a fake one written back on.</p>' % total)
    a('<p>The last column turns the list into a specification. Three genuine captures off the '
      'same phone &mdash; one spot at 1&times; then 2&times; to isolate the lens, then indoors '
      'with flash in portrait &mdash; say which fields are welded to the device and can be '
      'copied once, and which move every time and have to be generated afresh.</p>')
    a('<div class="mtx-wrap wide"><table class="mtx"><thead><tr>')
    a('<th class="cnr">Field</th>')
    for c in cols:
        a('<th class="%s"><b>%d</b> %s</th>' % (c["cls"], c["n"], esc(c["label"])))
    for label, why in (var["labels"] if var else []):
        a('<th class="is-good"><b>%s</b><span class="gd">%s</span></th>'
          % (esc(label), esc(why)))
    a('<th class="cnr">Verdict<span class="gd"> across the three</span></th>')
    a('<th class="cnr">Times read<span class="gd"> range across the five sessions</span>'
      '</th></tr></thead><tbody>')

    # what the files are, as the opening group rather than a second table with
    # the same five columns above it
    a('<tr class="grp is-dim"><td colspan="%d">The file itself &nbsp;<span class="gd">'
      'Before anything was read off it.</span></td></tr>' % (len(cols) + 2 + (var["n"] + 1 if var else 1)))
    fileset = [
        ("container", "", lambda d: d.get("File:FileType")),
        ("stored size", "pixels as written, before any rotation",
         lambda d: ("%s x %s" % (d["File:ImageWidth"], d["File:ImageHeight"]))
         if "File:ImageWidth" in d else None),
        ("colour profile", "", lambda d: d.get("ICC_Profile:ProfileDescription")),
        ("identity written in", "which container holds the make and GPS",
         lambda d: "XMP" if "XMP-tiff:Make" in d
         else ("EXIF / TIFF" if "IFD0:Make" in d else None)),
        ("Apple maker note", "",
         lambda d: ("%d tags" % len([k for k in d if k.startswith("Apple:")]))
         if any(k.startswith("Apple:") for k in d) else None),
    ]
    for label, note, fn in fileset:
        a('<tr><td class="fld fx"><b>%s</b>%s</td>'
          % (esc(label), ('<i>%s</i>' % esc(note)) if note else ""))
        for c in cols:
            d = idumps.get(c["key"])
            v = fn(d) if d else None
            a('<td class="on">%s</td>' % esc(str(v)) if v is not None
              else '<td class="off">&mdash;</td>')
        a('<td class="off">&mdash;</td>' * (var["n"] + 2 if var else 2) + '</tr>')
    a('<tr><td class="fld fx"><b>survived PhotoKit import</b>'
      '<i>imported through the API an app actually uses, then pulled back and diffed</i></td>')
    for c in cols:
        a('<td class="zero">byte-identical</td>')
    a('<td class="off">&mdash;</td>' * (var["n"] + 2 if var else 2) + '</tr>')

    for block, gname, gcls, gdesc in IMAGE_BLOCKS:
        rows = keys.get(block, [])
        if not rows:
            continue
        a('<tr class="grp %s"><td colspan="%d">%s &nbsp;<span class="gd">%s%s</span></td></tr>'
          % (gcls, len(cols) + 2 + (var["n"] + 1 if var else 1), esc(gname),
             esc(gdesc % len(rows) if "%d" in gdesc else gdesc),
             variance_group(var, block)))
        prev = None
        for key, short in rows:
            g = IMAGE_GLOSS.get(short, "")
            if not g and block != "{MakerApple}":
                gloss_missing.append(short)
            # a description that just repeated the row above was noise; the
            # blank reads as a ditto and the pairs sort next to each other
            desc = "" if g == prev else g
            prev = g
            a('<tr><td class="fld fx"><b>%s</b>%s</td>'
              % (esc(short), ('<i>%s</i>' % esc(desc)) if desc else ""))
            if block == "(top level)":
                pooled = sorted({v for c in cols for v in ivals(iruns[c["id"]]["tags"], key)})
                txt = " \u00b7 ".join(pooled)
                a('<td class="on murky" colspan="%d">%s</td>'
                  % (len(cols), esc(txt[:74] + ("…" if len(txt) > 74 else ""))))
            else:
                found = False
                for c in cols:
                    d = idumps.get(c["key"])
                    v = (apple_field(d, key, iruns) if block == "{MakerApple}"
                         else exif_field(d, short))
                    if v is None:
                        a('<td class="off">&mdash;</td>')
                        continue
                    found = True
                    txt = str(v)
                    a('<td class="on">%s</td>'
                      % esc(txt[:30] + ("\u2026" if len(txt) > 30 else "")))
                if not found and block != "{MakerApple}":
                    unmapped.append(short)
            a(variance_cells(var, short))
            reads = [m.get("reads") or 0 for m in
                     (iruns[c["id"]]["tags"].get(key) for c in cols) if m]
            a('<td class="cnt">%s&times;</td>'
              % ("%d&ndash;%d" % (min(reads), max(reads))
                 if reads and min(reads) != max(reads) else (reads[0] if reads else 0)))
            a('</tr>')
    a('<tr class="grp is-dim"><td colspan="%d">Timing</td></tr>' % (len(cols) + 2 + (var["n"] + 1 if var else 1)))
    a('<tr><td class="fld fx"><b>first GPS read</b><i>seconds after launch, before anything '
      'was selected</i></td>')
    for c in cols:
        m = iruns[c["id"]]["tags"].get("image {GPS} Latitude")
        t = m.get("first_seen_s") if m else None
        a('<td class="%s">%s</td>' % ("on" if t else "off",
                                      ("%.1f s" % t) if t else "&mdash;"))
    a('<td class="off">&mdash;</td>' * (var["n"] + 2 if var else 2) + '</tr>')
    a('</tbody></table></div>')
    if gloss_missing:
        print("  ! stills fields with no plain-English gloss: %s"
              % ", ".join(sorted(set(gloss_missing))))
    if unmapped:
        print("  ! stills fields that resolved to no value on any arm: %s"
              % ", ".join(sorted(set(unmapped))))
    a('<p class="cap"><b>Photo 2 is the only column with a full house</b>, because it is the '
      'only genuine capture. Lens, exposure, sub-second timing, compass bearing and the Apple '
      'block are things a camera writes and a forgery has to reproduce &mdash; and photo 3, '
      'built from that very image, has the entire camera-settings group empty. That gap is the '
      'tell.</p>')
    a('<p class="cap"><b>The three UUIDs in the Apple block are the sharpest thing here.</b> A '
      'coordinate can be faked and a timestamp moved, but <code>ContentIdentifier</code> and '
      '<code>PhotoIdentifier</code> exist to be unique to one shot. Copying a real maker note '
      'onto other files &mdash; the obvious way to make a photo look camera-shot &mdash; stamps '
      'every one of them with the same supposedly-unique id.</p>')

    # ------------------------------------------------------------------ limits
    a('<div class="panel is-dim"><h3>What the stills runs do not show</h3><ul>')
    a('<li><b>No upload body was captured on any of the five.</b> Between three and seven '
      'request bodies per run, all of it launch telemetry &mdash; nothing from the post itself. '
      'What reaches the CDN for a photo is unmeasured, exactly as it is for the clips.</li>')
    a('<li><b>Reads are attributed by value, not by file handle.</b> The rig records values per '
      'tag key with no note of which file they came from, so the claim that a non-selected photo '
      'was read rests on its unique canary appearing in the session. Sound here because every '
      'arm differs &mdash; but inference from the value set, not a per-file trace. It is also '
      'why the values above are read back off the files rather than taken from the capture.</li>')
    a('<li><b>The roll held eight photos, not five hundred.</b> Three later sessions ran '
      'against a bigger library &mdash; eight images, seven of them carrying GPS &mdash; and '
      'took all seven every time, so the sweep is not capped at five. Whether it reaches an '
      'entire library or only what the grid renders is still open; settling it needs a roll of '
      'a few hundred and one more posting window.</li>')
    a('<li><b>Photos 2 and 3 are not in the repository.</b> They are a real capture and a '
      'restamped copy of it: personal pixels, home GPS, and maker-note UUIDs.</li>')
    a('</ul></div>')
    a('</section>')
    return "\n".join(o)


def method_section(runs, raw_total, fact_total):
    o = []
    a = o.append
    a('<section><h2>How it was measured</h2>')
    a('<div class="two">')
    a('<div class="panel is-dim"><h3>The rule that keeps it clean</h3><div class="fld">')
    a('<div><b>One clip per emptied camera roll</b>Opening the picker makes TikTok stat and '
      'deep-walk every visible asset, so a library with five clips produces one log holding all '
      'five clips\' metadata with no way to split it. Every session below had exactly one '
      'item.</div>')
    a('<div><b>Read-only, spawn not attach</b>The observer hooks reads and never injects to post. '
      'Posting is done by hand on the device.</div>')
    a('<div><b>562 rows are 423 facts</b>AVFoundation exposes the same atom under six format '
      'identifiers, so one value on the file logs up to six times. The ledger collapses on '
      '(phase, atom, value) and keeps the keyspaces. Nothing is discarded.</div>')
    a('</div></div>')
    a('<div class="panel is-dim"><h3>Device</h3><div class="fld sm">')
    for k, v in [("Handset", "iPhone X (iPhone10,3), iOS 16.7.16"),
                 ("Jailbreak", "palera1n rootless, Frida 17.16.4"),
                 ("Account", "burner, Europe/Vilnius"),
                 ("Location permission", "not determined — never granted"),
                 ("IDFA", "all zeros"),
                 ("iCloud Photos", "disabled on this phone")]:
        a('<div><b>%s</b>%s</div>' % (esc(k), esc(v)))
    a('</div></div>')
    a('</div>')
    a('<div class="census"><div class="cen cen-h sess"><span>Session</span><span>Clip</span>'
      '<span class="ct">reads</span><span>Ended</span></div>')
    for r in RUNS:
        d = runs[r["id"]]
        died = d["run"].get("died_reason", "")
        cls = "is-bad" if died == "process-terminated" else "is-dim"
        a('<div class="cen %s sess"><div class="nm"><code>%s</code>'
          '<small>%s · pid %s · %ss observed</small></div>'
          '<div class="nm2">%s <small>%s</small></div><div class="ct">%d</div>'
          '<span class="pill">%s</span></div>'
          % (cls, esc(r["id"]), esc(d["run"].get("window", "")), d["run"].get("pid"),
             d["run"].get("observed_s"),
             ("%s %s" % (r["n"], r["label"])) if r["n"] else esc(r["label"]),
             esc(r["origin"]), d["tag_count"],
             "killed" if died == "process-terminated" else "clean"))
    a('</div>')
    a('<p class="cap">Two further windows are not listed because the operator did not post in '
      'them: <code>%s</code>. They sit in the repo and hold %d tags of launch chrome between '
      'them, with no INPUT walk.</p>' % ("</code>, <code>".join(m[0] for m in MISSED),
                                        sum(m[1] for m in MISSED)))
    a('</section>')
    return "\n".join(o)


def ledger_section(runs):
    o = []
    a = o.append
    a('<details class="ap"><summary><b>Full tag ledger</b> '
      '<em>all %d facts, %d sessions</em></summary>'
      % (sum(len(runs[r["id"]]["_facts"]) for r in RUNS), len(RUNS)))
    a('<p class="cap">Grouped by phase. Identity-bearing rows are marked; the rest is UI chrome, '
      'encoder blocks and filesystem stat, kept because it is part of the record.</p>')
    for r in RUNS:
        d = runs[r["id"]]
        facts = d["_facts"]
        a('<details class="ldg"><summary><b>%s</b> <em>%s · %d raw &rarr; %d distinct</em>'
          '</summary>'
          % (esc(r["id"]), ("clip %d %s" % (r["n"], r["label"])) if r["n"] else r["label"],
             d["tag_count"], len(facts)))
        for raw_ph, disp, blurb in PHASES:
            rows = [f for f in facts if f["phase"] == raw_ph]
            if not rows:
                continue
            a('<p class="phase"><span class="ptag">%s</span>%s <em>%d</em></p>'
              % (esc(disp), esc(blurb), len(rows)))
            a('<div class="mtx-wrap"><table class="dt"><thead><tr><th>Atom / property</th>'
              '<th>Value</th><th>Seen via</th><th class="n">Reads</th><th class="n">t</th>'
              '</tr></thead><tbody>')
            for f in rows:
                nm = atom_name(f["atom"])
                lbl = ('<code>%s</code>' % esc(f["atom"])) if f["atom"] == nm else \
                      ('<code>%s</code><small>%s</small>' % (esc(f["atom"]), esc(nm)))
                a('<tr%s><td>%s</td><td><code class="v">%s</code></td><td class="ks">%s</td>'
                  '<td class="n">%s</td><td class="n">%s</td></tr>'
                  % (' class="idr"' if f["atom"] in PROVENANCE_ATOMS else '', lbl,
                     esc(f["value"][:150]), esc(" · ".join(f["keyspaces"])),
                     ("%d" % f["reads"]) if f["reads"] else "—",
                     ("%.1fs" % f["first"]) if f["first"] is not None else "—"))
            a('</tbody></table></div>')
        if d.get("bodies"):
            a('<p class="phase"><span class="ptag">BODIES</span>HTTP request bodies written to '
              'disk <em>%d</em></p>' % len(d["bodies"]))
            a('<div class="mtx-wrap"><table class="dt"><tbody>')
            for b in d["bodies"]:
                a('<tr><td><code>%s</code></td><td><code class="v">%s</code></td>'
                  '<td class="n">%s</td></tr>'
                  % (esc(b["file"][:70]), esc(b["from"][:200]), fmt_bytes(b["bytes"])))
            a('</tbody></table></div>')
        a('</details>')
    a('</details>')
    return "\n".join(o)


def raw_section(runs):
    o = []
    a = o.append
    a('<details class="ap"><summary><b>Raw run files</b> <em>unedited tags.json and session.log'
      '</em></summary>')
    for r in RUNS:
        d = runs[r["id"]]
        a('<details class="ldg"><summary><b>%s</b> <em>raw files</em></summary>' % esc(r["id"]))
        payload = {k: v for k, v in d.items() if not k.startswith("_")}
        js = json.dumps(payload, indent=1, ensure_ascii=False)
        a('<details class="ldg"><summary><b>tags.json</b> <em>%s characters</em></summary>'
          '<pre class="raw">%s</pre></details>' % (fmt_bytes(len(js)), esc(js)))
        logp = os.path.join(ROOT, "runs", r["id"], "session.log")
        if os.path.exists(logp):
            with open(logp, encoding="utf-8", errors="replace") as f:
                log = f.read()
            a('<details class="ldg"><summary><b>session.log</b> <em>%s characters</em></summary>'
              '<pre class="raw">%s</pre></details>' % (fmt_bytes(len(log)), esc(log)))
        a('</details>')
    a('</details>')
    return "\n".join(o)


# ----------------------------------------------------------------- assets

STYLE = """<style>
:root {
  color-scheme: dark;
  --bg:#0B1017; --panel:#131A23; --sunk:#0F161E; --line:#212C38;
  --ink:#E4EBF2; --mid:#93A3B5; --dim:#5F6F81;
  --good:#3FD09C; --warn:#E0B455; --bad:#F0857F; --cool:#6FAEF5; --who:#C39BF0;
}
* { box-sizing: border-box; }
body { margin:0; background:var(--bg); color:var(--ink);
  font:15px/1.55 "Geist","Segoe UI Variable Text",-apple-system,BlinkMacSystemFont,system-ui,sans-serif;
  font-variant-numeric:tabular-nums; -webkit-font-smoothing:antialiased; }
.wrap { max-width:1180px; margin:0 auto; padding:44px clamp(14px,5vw,40px) 0; }
.mtx-wrap.wide { width:min(97vw,1640px); max-width:none; margin-left:50%;
  transform:translateX(-50%); }
.wrap.tail { padding-bottom:100px; padding-top:0; }
h1,h2 { margin:0; letter-spacing:-.02em; text-wrap:balance; }
h1 { font-size:clamp(27px,5vw,36px); line-height:1.08; }
h2 { font-size:19px; }
p { margin:0; color:var(--mid); max-width:70ch; }
b { color:var(--ink); font-weight:600; }
em { font-style:normal; }
code { font-size:.88em; color:var(--cool); font-family:ui-monospace,Consolas,monospace; }
section { margin-top:52px; display:flex; flex-direction:column; gap:14px; }
.eyebrow { color:var(--dim); font-size:11px; font-weight:650; letter-spacing:.16em;
  text-transform:uppercase; }
/* two investigations, two pages. They reached different conclusions, so the
   switch is a real divider rather than a convenience. */
.tabs { position:sticky; top:0; z-index:30; display:flex; gap:8px; flex-wrap:wrap;
  margin:26px 0 22px; padding:12px 0; background:var(--bg);
  border-bottom:1px solid var(--line); }
.tab { display:flex; flex-direction:column; align-items:flex-start; gap:3px;
  padding:11px 20px; border:1px solid var(--line); border-radius:11px;
  background:var(--panel); color:var(--dim); cursor:pointer; font:inherit;
  text-align:left; transition:color .12s, border-color .12s, background .12s; }
.tab b { font-size:15px; font-weight:700; letter-spacing:-.01em; }
.tab span { font-family:ui-monospace,Consolas,monospace; font-size:10px;
  letter-spacing:.08em; text-transform:uppercase; color:var(--dim); }
.tab:hover { color:var(--ink); border-color:var(--mid); }
.tab.is-on { color:var(--ink); background:var(--sunk); border-color:var(--cool);
  box-shadow:inset 0 -2px 0 var(--cool); }
.tab.is-on span { color:var(--cool); }
.tab:focus-visible { outline:2px solid var(--cool); outline-offset:2px; }
.page[hidden] { display:none; }
.lede { font-size:16.5px; line-height:1.62; color:var(--mid); max-width:72ch; }
.lede b { color:var(--ink); }
@media (prefers-reduced-motion: reduce) { .tab { transition:none; } }
.masthead { display:flex; flex-direction:column; gap:12px; }
.cap { font-size:12.5px; color:var(--dim); max-width:78ch; }
a { color:var(--cool); }
:focus-visible { outline:2px solid var(--cool); outline-offset:3px; }

.is-good{--accent:var(--good);--edge:#1D4234;} .is-new{--accent:var(--cool);--edge:#24466E;}
.is-warn{--accent:var(--warn);--edge:#4A3A14;} .is-bad{--accent:var(--bad);--edge:#4A2020;}
.is-dim{--accent:var(--dim);--edge:var(--line);}

/* stat tiles */
.tiles { display:grid; grid-template-columns:repeat(auto-fit,minmax(146px,1fr)); gap:1px;
  background:var(--line); border:1px solid var(--line); border-radius:10px; overflow:hidden; }
.tile { background:var(--panel); padding:13px 15px; }
.tile b { display:block; font-size:21px; font-weight:600; letter-spacing:-.02em;
  color:var(--accent,var(--ink)); }
.tile span { color:var(--dim); font-size:11px; letter-spacing:.06em; text-transform:uppercase; }

/* panels */
.panel { background:var(--sunk); border:1px solid var(--line); border-radius:10px;
  overflow:hidden; }
.panel > h3 { display:flex; align-items:baseline; gap:10px; margin:0; padding:10px 15px;
  background:var(--panel); border-bottom:1px solid var(--line); font-size:11px; font-weight:650;
  letter-spacing:.09em; text-transform:uppercase; color:var(--accent,var(--dim)); }
.panel > ul { padding:13px 16px 13px 32px; margin:0; font-size:13px; color:var(--mid);
  line-height:1.6; }
.panel > ul li + li { margin-top:7px; }
.panel > .pn { padding:11px 15px 0; font-size:12.5px; color:var(--dim); }
.compare, .two { display:grid; grid-template-columns:1fr 1fr; gap:10px; align-items:start; }
.fld div { padding:10px 15px; border-top:1px solid var(--line); font-size:12.5px;
  color:var(--mid); }
.fld div:first-child { border-top:0; }
.fld div b { display:block; color:var(--ink); font-weight:600; margin-bottom:2px; font-size:13px; }
.fld div code { display:block; margin-top:4px; }
.fld.sm div { padding:8px 15px; font-size:12px; }
.fld .grph { padding:9px 15px 5px; border-top:1px solid var(--line); }
.fld div:first-child.grph { border-top:0; }
.fld .grph + div { border-top:0; padding-top:2px; }
.fld .gone { color:var(--good); }
.panel > h3 .hcnt { margin-left:auto; color:var(--dim); font-weight:400; letter-spacing:0;
  text-transform:none; font-size:11px; }
.ct.userdata { color:var(--who); border-color:#3D2A57; }
.ct.itemlist { color:var(--mid); }

/* rows */
.rows { border:1px solid var(--line); border-radius:10px; overflow:hidden; }
.row { display:grid; grid-template-columns:184px 1fr 108px; gap:14px; padding:12px 15px;
  background:var(--panel); border-top:1px solid var(--line); font-size:13.5px;
  align-items:baseline; }
.row:first-child { border-top:0; }
.row > b { color:var(--accent,var(--ink)); font-weight:600; }
.row > span { color:var(--mid); }
.row > span span { display:block; color:var(--dim); font-size:12.5px; margin-top:4px; }
.row .end { color:var(--accent,var(--dim)); font-size:10.5px; letter-spacing:.07em;
  text-transform:uppercase; font-weight:650; text-align:right; }

/* THE TABLE */
.mtx-wrap { border:1px solid var(--line); border-radius:10px; overflow:auto; }
.mtx { border-collapse:collapse; width:100%; font-size:12.5px; min-width:860px; }
.mtx th, .mtx td { border-left:1px solid var(--line); padding:8px 10px; text-align:left;
  vertical-align:top; }
.mtx th:first-child, .mtx td:first-child { border-left:0; }
.mtx thead th { background:var(--panel); border-bottom:1px solid var(--line);
  color:var(--accent,var(--ink)); font-size:12.5px; font-weight:600; white-space:nowrap; }
.mtx thead th b { display:block; font-size:16px; color:var(--accent,var(--ink));
  letter-spacing:-.02em; }
.mtx thead th em { display:block; margin-bottom:5px; font-size:10px; letter-spacing:.1em;
  text-transform:uppercase; color:var(--accent,var(--dim)); font-weight:650; }

.mtx thead th.sub { font:400 11px/1.4 inherit; color:var(--dim); white-space:normal;
  min-width:100px; padding-top:0; padding-bottom:9px; background:var(--panel); }
.mtx thead th.cnr { background:var(--sunk); color:var(--dim); font-size:10.5px;
  letter-spacing:.08em; text-transform:uppercase; vertical-align:bottom; }
.mtx tbody td { background:var(--panel); border-top:1px solid var(--line); }
.mtx tr.grp td { background:var(--sunk); color:var(--accent,var(--dim)); font-size:10.5px;
  font-weight:650; letter-spacing:.09em; text-transform:uppercase; padding:7px 11px; }
.mtx .fld { color:var(--ink); white-space:nowrap; }
.mtx .in { width:1%; }
.mtx td.off { color:#3A4654; text-align:center; }
.mtx td.on { color:var(--ink); font-family:ui-monospace,Consolas,monospace; font-size:11.5px;
  word-break:break-word; background:rgba(63,208,156,.05); }
.mtx td.on i, .mtx td.blob i { display:block; font-style:normal; margin-top:3px; font-size:10px;
  letter-spacing:.04em; text-transform:uppercase; color:var(--dim);
  font-family:"Geist",system-ui,sans-serif; }
.mtx td.blob { color:var(--warn); background:rgba(224,180,85,.06); font-size:11.5px; }
.mtx td.cnt { color:var(--bad); font-weight:600; font-size:15px; }
.mtx td.on.murky { background:rgba(224,180,85,.06); color:var(--mid); }
.mtx thead th u.blend { display:block; margin-top:4px; text-decoration:none; font-size:9.5px;
  letter-spacing:.07em; text-transform:uppercase; font-weight:650; color:var(--warn); }
.mtx td.zero { color:var(--good); font-weight:600; }
/* a two-column comparison has nothing to line up, so it must not inherit the
   matrix min-width and force its container to scroll */
.mtx.compact { min-width:0; }
.mtx.compact td.fld { white-space:normal; }
/* one row per posting session: identity cell, headline count, chip list */
.mtx td.sess { white-space:normal; min-width:15ch; }
.mtx td.sess b { font-size:17px; margin-right:6px; color:var(--accent,var(--ink)); }
.mtx td.sess i, .mtx td.cnt.big i { display:block; font-style:normal; margin-top:4px;
  font-size:10px; font-weight:400; color:var(--dim); line-height:1.35; }
.mtx td.cnt.big { font-size:30px; line-height:1; text-align:center; width:1%;
  white-space:nowrap; font-variant-numeric:tabular-nums; }
.mtx td.chips { white-space:normal; min-width:17ch; }
/* real-capture values: wide enough that the two lens strings stay distinct */
.mtx td.rc { white-space:normal; max-width:24ch; }
.mtx td.chips .ct { display:inline-block; margin:0 4px 4px 0; }
/* field name and its description share one cell, so the table loses a column */
.mtx td.fx { white-space:normal; min-width:19ch; max-width:34ch; }
.mtx td.fx b { font-weight:600; }
.mtx td.fx i { display:block; margin-top:3px; font-style:normal; font-size:10.5px;
  color:var(--mid); line-height:1.4; }
.mtx .gd { color:var(--dim); text-transform:none; letter-spacing:0; font-weight:400; }
.mtx thead th.cnr .gd { display:block; margin-top:3px; }
.ct { font-size:9.5px; letter-spacing:.07em; text-transform:uppercase; font-weight:650;
  padding:3px 6px; border-radius:4px; background:var(--sunk); color:var(--dim);
  border:1px solid var(--line); white-space:nowrap; }
.ct.keys { color:var(--cool); border-color:#24466E; }
.ct.xmp { color:var(--warn); border-color:#4A3A14; }
.keyline { display:flex; flex-wrap:wrap; gap:8px 20px; font-size:12px; color:var(--dim); }
.keyline span { display:flex; align-items:center; gap:7px; }
.keyline i { width:9px; height:9px; border-radius:3px; background:var(--accent,var(--dim));
  flex:none; }

/* census */
.census { border:1px solid var(--line); border-radius:10px; overflow:hidden; }
.cen { display:grid; grid-template-columns:1fr 148px 62px 116px; gap:14px; align-items:center;
  padding:9px 15px; background:var(--panel); border-top:1px solid var(--line); font-size:13.5px; }
.cen:first-child { border-top:0; }
.cen-h { background:var(--sunk); font-size:10.5px; letter-spacing:.08em; text-transform:uppercase;
  color:var(--dim); font-weight:650; }
.cen .nm { color:var(--ink); min-width:0; }
.cen .nm small, .cen .nm2 small { display:block; color:var(--dim); font-size:11.5px;
  line-height:1.45; margin-top:1px; }
.cen .nm2 { color:var(--ink); font-size:12.5px; }
.bar { height:6px; border-radius:3px; background:var(--line); overflow:hidden; }
.bar i { display:block; height:100%; background:var(--accent,var(--dim)); border-radius:3px; }
.cen .ct { text-align:right; color:var(--mid); font-size:12.5px; background:none; border:0;
  padding:0; letter-spacing:0; text-transform:none; font-weight:400; }
.pill { justify-self:start; font-size:10px; letter-spacing:.07em; text-transform:uppercase;
  font-weight:650; padding:3px 8px; border-radius:999px; white-space:nowrap;
  color:var(--accent,var(--dim)); border:1px solid var(--edge,var(--line)); background:var(--sunk); }
.cen.sess { grid-template-columns:1fr 190px 62px 90px; }

/* flow */
.flow { display:grid; grid-template-columns:1fr 26px 1fr 26px 1fr 26px 1fr; gap:4px;
  align-items:center; }
.flow .arw { display:flex; justify-content:center; color:var(--dim); font-size:16px; }
.stg { background:var(--sunk); border:1px solid var(--edge,var(--line)); border-radius:10px;
  padding:14px 15px 15px; }
.stg b { display:block; font-size:30px; font-weight:600; letter-spacing:-.03em;
  color:var(--accent,var(--ink)); line-height:1; }
.stg span { display:block; margin-top:6px; font-size:13px; color:var(--ink); font-weight:600; }
.stg em { display:block; margin-top:3px; font-size:11.5px; color:var(--dim); line-height:1.4; }

/* command */
.brief { background:var(--sunk); border:1px solid #24466E; border-radius:10px; overflow:hidden; }
.brief-hd { display:flex; align-items:center; justify-content:space-between; gap:12px;
  padding:8px 13px; background:var(--panel); border-bottom:1px solid var(--line);
  font-size:10.5px; font-weight:650; letter-spacing:.09em; text-transform:uppercase;
  color:var(--dim); }
.copy { font:650 10.5px/1 "Geist",system-ui,sans-serif; letter-spacing:.07em;
  text-transform:uppercase; padding:6px 11px; cursor:pointer; color:var(--cool);
  background:var(--sunk); border:1px solid #24466E; border-radius:6px; }
.copy:hover { color:var(--ink); border-color:var(--cool); }
.copy.done { color:var(--good); border-color:#1D4234; }
.brief pre { margin:0; padding:14px 16px; font:12.5px/1.7 ui-monospace,Consolas,monospace;
  color:var(--mid); white-space:pre; overflow-x:auto; }

/* appendix */
details { border:1px solid var(--line); border-radius:10px; background:var(--panel); }
.ap { margin-top:12px; }
summary { cursor:pointer; padding:11px 15px; font-size:13.5px; color:var(--ink);
  list-style:none; display:flex; align-items:baseline; gap:9px; flex-wrap:wrap; }
summary::-webkit-details-marker { display:none; }
summary::before { content:"\\25B8"; color:var(--dim); font-size:11px; }
details[open] > summary::before { content:"\\25BE"; }
summary em { color:var(--dim); font-size:12px; }
details > *:not(summary) { margin:0 15px 13px; }
details > details { margin:0 15px 10px; background:var(--sunk); }
.phase { display:flex; align-items:baseline; gap:9px; flex-wrap:wrap; margin-top:16px !important;
  font-size:12.5px; color:var(--dim); }
.ptag { font:650 10px/1 ui-monospace,Consolas,monospace; letter-spacing:.09em; padding:4px 7px;
  background:var(--panel); border:1px solid var(--line); border-radius:4px; color:var(--mid); }
.dt { border-collapse:collapse; width:100%; font-size:11.5px; min-width:640px; }
.dt th { background:var(--sunk); text-align:left; padding:7px 10px; font-size:10px;
  letter-spacing:.08em; text-transform:uppercase; color:var(--dim); font-weight:650;
  border-bottom:1px solid var(--line); white-space:nowrap; }
.dt td { padding:6px 10px; border-top:1px solid var(--line); vertical-align:top;
  color:var(--mid); }
.dt td code { color:var(--mid); }
.dt td code.v { color:var(--ink); }
.dt tr.idr td code { color:var(--cool); }
.dt tr.idr td:first-child { box-shadow:inset 2px 0 0 var(--cool); }
.dt small { display:block; color:var(--dim); font-size:10.5px; margin-top:2px; }
.dt .n { text-align:right; white-space:nowrap; }
.dt .ks { color:var(--dim); font-size:10.5px; }
.raw { max-height:28em; overflow:auto; padding:12px; background:var(--bg);
  border:1px solid var(--line); border-radius:8px; font:11px/1.5 ui-monospace,Consolas,monospace;
  white-space:pre-wrap; word-break:break-word; color:var(--mid); }

@media (max-width:900px) { .flow { grid-template-columns:1fr; }
  .flow .arw { transform:rotate(90deg); } }
@media (max-width:780px) { .compare, .two { grid-template-columns:1fr; }
  .cen, .cen.sess { grid-template-columns:1fr auto; }
  .cen .bar, .cen-h span:nth-child(2) { display:none; } }
@media (max-width:640px) { .row { grid-template-columns:1fr; gap:4px; }
  .row .end { text-align:left; } }
@media (prefers-reduced-motion:reduce) { * { animation:none !important; transition:none !important; } }
</style>"""

SCRIPT = """<script>
(function(){
  var tabs = [].slice.call(document.querySelectorAll('.tab'));
  var pages = [].slice.call(document.querySelectorAll('.page'));
  if (!tabs.length || !pages.length) return;
  function show(id, remember){
    pages.forEach(function(p){ p.hidden = (p.id !== id); });
    tabs.forEach(function(t){
      var on = t.getAttribute('data-page') === id;
      t.classList.toggle('is-on', on);
      t.setAttribute('aria-selected', on ? 'true' : 'false');
    });
    // a deep link should land on the right page, but switching pages must not
    // add a history entry for every click
    if (remember && history.replaceState) history.replaceState(null, '', '#' + id);
  }
  tabs.forEach(function(t, i){
    t.addEventListener('click', function(){
      show(t.getAttribute('data-page'), true);
      window.scrollTo(0, 0);
    });
    t.addEventListener('keydown', function(e){
      var d = e.key === 'ArrowRight' ? 1 : e.key === 'ArrowLeft' ? -1 : 0;
      if (!d) return;
      e.preventDefault();
      var n = tabs[(i + d + tabs.length) % tabs.length];
      n.focus(); show(n.getAttribute('data-page'), true);
    });
  });
  var want = (location.hash || '').replace('#', '');
  show(pages.some(function(p){ return p.id === want; }) ? want : pages[0].id, false);
})();
document.querySelectorAll('.copy').forEach(function(btn){
  btn.addEventListener('click', function(){
    var pre = document.getElementById(btn.getAttribute('data-copy'));
    if (!pre) return;
    var done = function(){
      btn.textContent = 'Copied'; btn.classList.add('done');
      setTimeout(function(){ btn.textContent='Copy'; btn.classList.remove('done'); }, 1600);
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(pre.innerText).then(done, function(){});
    } else {
      var ta=document.createElement('textarea'); ta.value=pre.innerText;
      document.body.appendChild(ta); ta.select();
      try { document.execCommand('copy'); done(); } catch(e) {}
      document.body.removeChild(ta);
    }
  });
});
</script>"""


if __name__ == "__main__":
    main()
