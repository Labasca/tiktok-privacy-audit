#!/usr/bin/env python3
"""
compare_runs.py  -  diff the tag inventory across several posting runs.

One run tells you what was in one file. The question the stamping work actually
asks is comparative: which fields does a native capture carry that a scraped or
generated one does not, which of them survive TikTok's re-encode, and does a
stamped file end up indistinguishable from the real thing.

That is a matrix, not a report, so this reads the tags.json each run writes and
prints one row per tag with one column per run.

    ./compare_runs.py runs/01-native/tags.json runs/04-scraped-stamped/tags.json
    ./compare_runs.py runs/*/tags.json --only INPUT
    ./compare_runs.py runs/*/tags.json --diff-only --csv matrix.csv

Column names come from the containing directory, so keep one run per directory
and name the directories after the arm.

With --normalize it will also diff a dump_tags.py file dump against a rig run,
which is the coverage check: exiftool is the denominator, the rig the numerator.

    ./dump_tags.py runs/01-native/source.mov
    ./compare_runs.py runs/01-native/source.tags.json runs/01-native/tags.json \
        --normalize --diff-only

Two families do not normalise and are expected to show as mismatched:

  - MakerApple. CoreGraphics numbers these keys ({MakerApple} 17) where exiftool
    names them (Apple:RunTime). Mapping one to the other needs a table of Apple
    maker-note tag IDs that this does not carry, so compare them by hand.
  - Track fields. 'Track1:CompressorName' is a name string and 'track codec' is
    a FourCC. Related, not the same value.

READ-ONLY. This touches nothing but the JSON files you point it at.
"""
import sys, os, json, csv, argparse

# tags whose disagreement between two arms is the finding, as opposed to the
# ones that differ on every file for uninteresting reasons (sizes, timestamps
# of the run itself, per-file identifiers).
NOISE = ("file size", "file CreationDate", "file ModificationDate")

MISSING = "-"

# --------------------------------------------------------------------------
# canonical names
#
# The rig and exiftool describe the same field with different words. The rig
# reads CoreGraphics, which calls the block "{TIFF}" and the field "Make".
# exiftool reads the file directly and calls the same thing "IFD0:Make". Diffing
# those two raw produces a table where every row is missing on one side, which
# reads as total disagreement and means nothing.
#
# Normalising to "block.field" is what makes a coverage fraction computable:
# exiftool supplies the denominator, the rig supplies the numerator, and a tag
# in the first but not the second is either untouched by TikTok or unhooked by
# us. This is only correct for comparing a FILE against what was read out of it,
# so it stays opt-in behind --normalize and run-vs-run diffs stay exact.
# --------------------------------------------------------------------------

# exiftool -G1 family, and the CoreGraphics block it corresponds to
GROUP_TO_BLOCK = {
    "IFD0": "tiff", "IFD1": "tiff", "EXIF": "exif", "ExifIFD": "exif",
    "GPS": "gps", "Apple": "makerapple", "MakerNotes": "makerapple",
    "QuickTime": "quicktime", "Keys": "quicktime", "UserData": "quicktime",
    "ItemList": "quicktime", "IPTC": "iptc", "ICC_Profile": "icc",
    "ICC-header": "icc", "PNG": "png", "JFIF": "jfif", "File": "file",
    "Photoshop": "photoshop", "C2PA": "c2pa", "JUMBF": "c2pa",
}

# the rig's own container words, stripped before the block is read
RIG_CONTAINERS = ("INPUT", "OUTPUT", "UPLOADED", "SOURCE", "image", "video",
                  "XMP", "track", "library", "resource", "file",
                  "written into the export")

# CoreGraphics block spelling to canonical block
CG_BLOCK = {"{TIFF}": "tiff", "{Exif}": "exif", "{GPS}": "gps",
            "{MakerApple}": "makerapple", "{IPTC}": "iptc", "{XMP}": "xmp",
            "{PNG}": "png", "{JFIF}": "jfif", "{ExifAux}": "exifaux",
            "{Photoshop}": "photoshop", "{HEICS}": "heics", "{DNG}": "dng"}


# The same concept under two names. Only fields where both tools genuinely mean
# the same thing, never a guess: a wrong synonym silently merges two rows and
# invents agreement that is not there.
SYNONYM = {
    "file.imagewidth": "image.pixelwidth",
    "file.imageheight": "image.pixelheight",
    "exif.pixelxdimension": "image.pixelwidth",
    "exif.pixelydimension": "image.pixelheight",
    "quicktime.creationdate": "quicktime.creationdate",
    "quicktime.gpscoordinates": "quicktime.locationiso6709",
}


def _tidy(tag):
    """exiftool drops punctuation from key names ('LivePhotoAuto') where the
    QuickTime identifier keeps it ('live-photo.auto'). Same field, so neither
    spelling should decide whether the two tools are seen to agree."""
    return "".join(ch for ch in tag.lower() if ch.isalnum())


def canon(key):
    """Reduce either tool's name for a field to one 'block.field' string."""
    k = key.strip()

    # exiftool: "Group:Tag"
    if ":" in k and " " not in k.split(":", 1)[0]:
        group, tag = k.split(":", 1)
        if group.startswith("XMP-"):
            return "xmp." + group[4:].lower() + "." + tag.lower()
        if group.startswith("Track"):
            return "track." + tag.lower()
        block = GROUP_TO_BLOCK.get(group, group.lower())
        tag = _tidy(tag)
        # exiftool prefixes every GPS tag with GPS, CoreGraphics does not
        if block == "gps" and tag.startswith("gps"):
            tag = tag[3:]
        return SYNONYM.get(block + "." + tag, block + "." + tag)

    # rig: "<container> <rest>", where rest is a CG block, a QuickTime
    # identifier, or a bare top-level field
    container = None
    for cont in RIG_CONTAINERS:
        if k == cont:
            return cont.lower()
        if k.startswith(cont + " "):
            container = cont
            k = k[len(cont) + 1:].strip()
            break
    # the rig labels the AV containers it walked, e.g. "commonMetadata mdta/..."
    for noise in ("commonMetadata", "metadata", "common", "format"):
        if k.startswith(noise + " "):
            k = k[len(noise) + 1:].strip()

    # QuickTime identifiers: "mdta/com.apple.quicktime.make", "udta/©mak"
    if "/" in k.split(" ")[0]:
        ident = k.split(" ")[0]
        tail = ident.split("/", 1)[1]
        if tail.startswith("com.apple.quicktime."):
            tail = tail[len("com.apple.quicktime."):]
        n = "quicktime." + _tidy(tail)
        return SYNONYM.get(n, n)

    parts = k.split(" ", 1)
    if parts[0] in CG_BLOCK and len(parts) == 2:
        block = CG_BLOCK[parts[0]]
        tag = _tidy(parts[1])
        if block == "gps" and tag.startswith("gps"):
            tag = tag[3:]
        return SYNONYM.get(block + "." + tag, block + "." + tag)
    if parts[0] in CG_BLOCK:
        return CG_BLOCK[parts[0]]
    # "photoshop:DateCreated" under the XMP container
    if ":" in k:
        pfx, t = k.split(":", 1)
        return "xmp." + _tidy(pfx) + "." + _tidy(t)
    # A bare field. Blocks like track, library and resource are containers in
    # their own right, so the field belongs to them and not to the image.
    block = container.lower() if container in ("track", "library", "resource",
                                               "file") else "image"
    n = block + "." + _tidy(k)
    return SYNONYM.get(n, n)


def load(path, normalize=False):
    with open(path, encoding="utf-8") as f:
        d = json.load(f)
    tags = {}
    for k, v in (d.get("tags") or {}).items():
        val = v.get("value") if isinstance(v, dict) else v
        if isinstance(val, list):
            val = ", ".join(str(x) for x in val)
        val = "(present)" if val in (None, "") else str(val)
        name = canon(k) if normalize else k
        # two raw keys can normalise onto one name (the same field read out of
        # the input file and live during the post). Keep the first value and
        # note the collapse rather than letting the later one silently win.
        if name in tags and tags[name] != val:
            tags[name] = tags[name] + " | " + val
        else:
            tags[name] = val
    return tags, d


def arm_name(path):
    """The run's label is its directory, falling back to the filename. A flat
    pile of tags.json files all called the same thing is the one input shape
    this cannot make sense of, so say so rather than printing 'tags' six
    times."""
    d = os.path.basename(os.path.dirname(os.path.abspath(path)))
    if d and d not in (".", "/"):
        return d
    return os.path.splitext(os.path.basename(path))[0]


def clip(s, n):
    # ASCII only. A Windows console in the default codepage turns a unicode
    # ellipsis into a replacement glyph, which reads as corrupted data in a
    # table whose whole job is to be compared by eye.
    s = str(s)
    return s if len(s) <= n else s[: max(1, n - 2)] + ".."


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("runs", nargs="+", help="tags.json files, one per arm")
    ap.add_argument("--only", help="restrict to one container (INPUT, OUTPUT, "
                                   "UPLOADED, video, image, library, XMP)")
    ap.add_argument("--diff-only", action="store_true",
                    help="hide tags that are identical across every arm")
    ap.add_argument("--normalize", action="store_true",
                    help="reduce both tools' names to one 'block.field' form. "
                         "Use this to compare a dump_tags.py file dump against "
                         "a rig run. Run-vs-run diffs do not need it.")
    ap.add_argument("--width", type=int, default=26, help="column width")
    ap.add_argument("--csv", help="also write the matrix to a CSV file")
    args = ap.parse_args()

    arms, metas = [], []
    for p in args.runs:
        if not os.path.exists(p):
            sys.exit("no such file: %s" % p)
        tags, meta = load(p, args.normalize)
        arms.append((arm_name(p), tags))
        metas.append(meta)

    names = [a for a, _ in arms]
    if len(set(names)) != len(names):
        print("WARNING: two runs resolved to the same column name. Put each run "
              "in its own directory named after the arm.\n", file=sys.stderr)

    keys = set()
    for _, t in arms:
        keys |= set(t)
    if args.only:
        pre = args.only
        keys = {k for k in keys if k == pre or k.startswith(pre + " ")}
    keys = sorted(keys)

    rows = []
    for k in keys:
        vals = [t.get(k, MISSING) for _, t in arms]
        same = len(set(vals)) == 1
        if args.diff_only and same:
            continue
        rows.append((k, vals, same))

    if not rows:
        print("No tags to show. Either the runs are identical or --only "
              "matched nothing.")
        return

    kw = min(52, max(len(k) for k, _, _ in rows) + 1)
    cw = args.width
    # the marker gets its own gutter column. Overlaying it on the first
    # character of the tag name corrupts exactly the text being compared.
    head = "  %-*s" % (kw, "tag") + "".join(" %-*s" % (cw, clip(n, cw)) for n in names)
    print(head)
    print("-" * len(head))

    shown_bucket = None
    for k, vals, same in rows:
        # group by container, which is the first word raw and the first dotted
        # segment once normalised. Splitting on space in normalised mode buckets
        # every row on its own and turns the table into double-spaced noise.
        bucket = k.split(".")[0] if args.normalize else k.split(" ")[0]
        if bucket != shown_bucket:
            print()
            shown_bucket = bucket
        print("%s %-*s" % (" " if same else "*", kw, clip(k, kw))
              + "".join(" %-*s" % (cw, clip(v, cw)) for v in vals))

    # the summary that answers the actual question
    print()
    if len(arms) >= 2:
        base_name, base = arms[0]
        for name, t in arms[1:]:
            missing = sorted(k for k in base if k not in t and
                             not any(n in k for n in NOISE))
            added = sorted(k for k in t if k not in base and
                           not any(n in k for n in NOISE))
            changed = sorted(k for k in base
                             if k in t and base[k] != t[k]
                             and not any(n in k for n in NOISE))
            print("%s vs %s: %d tags missing, %d extra, %d different"
                  % (name, base_name, len(missing), len(added), len(changed)))
            for k in missing[:12]:
                print("    missing: %s (%s had %s)" % (k, base_name, clip(base[k], 40)))
            if len(missing) > 12:
                print("    ... and %d more missing" % (len(missing) - 12))
            for k in changed[:12]:
                print("    differs: %s  %s -> %s"
                      % (k, clip(base[k], 28), clip(t[k], 28)))
            if len(changed) > 12:
                print("    ... and %d more different" % (len(changed) - 12))
            print()
    print("* marks a tag that is not identical across every arm.")
    print("A tag present in the native arm and missing elsewhere is a field the "
          "stamper has to write.")

    if args.csv:
        with open(args.csv, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["tag"] + names)
            for k, vals, _ in rows:
                w.writerow([k] + vals)
        print("\nwrote %s" % args.csv)


if __name__ == "__main__":
    main()
