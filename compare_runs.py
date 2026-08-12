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
    # exiftool shortened this one; CoreGraphics still uses the EXIF 2.2 name
    "exif.iso": "exif.isospeedratings",
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

    # metadataForFormat_ names the format itself, so the row arrives as
    # "com.apple.quicktime.mdta mdta/com.apple.quicktime.make". Without this the
    # format name is treated as part of the field and the two halves are
    # concatenated into an unreadable key that matches nothing on either side.
    if " " in k:
        head, rest = k.split(" ", 1)
        # a format label is a reverse-DNS name and never contains a slash; the
        # field that follows it is either a slash-qualified identifier or a
        # plain name. Either way the label belongs to the container, not the key.
        if "/" not in head and ("/" in rest or "." in head):
            k = rest.strip()

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


# The containers that describe a WHOLE FILE, as opposed to the live reads that
# describe what the app pulled out of one. Normalising strips the container off
# the front of a key, which is what lets exiftool and the rig agree on a name -
# and which also makes every one of these collapse onto the same key.
FILE_CONTAINERS = ("SOURCE", "INPUT", "OUTPUT", "UPLOADED")


def raw_container(key):
    """The container a rig key belongs to, before normalising erases it."""
    for cont in RIG_CONTAINERS:
        if key == cont or key.startswith(cont + " "):
            return cont
    return None


def load(path, normalize=False, container=None):
    """container:
         None    - no filtering (the right thing for run-vs-run diffs)
         'live'  - only what the app read during the post, no file dumps
         a name  - only that container

    Filtering has to happen BEFORE normalising. INPUT, OUTPUT and UPLOADED all
    reduce to the same names by design, so normalising first would merge three
    descriptions of three different files into one column and hide the exact
    thing a stamping test is looking for, which is a field that was in the
    input and is not in the upload."""
    with open(path, encoding="utf-8") as f:
        d = json.load(f)
    raw = d.get("tags") or {}
    # An exiftool dump has no rig containers at all: it IS one file, described
    # once. Filtering it by container would empty it and silently turn the
    # coverage check into a comparison against nothing.
    has_file_dumps = any(raw_container(k) in FILE_CONTAINERS for k in raw)
    tags, collapsed = {}, []
    for k, v in raw.items():
        cont = raw_container(k)
        if has_file_dumps and container == "live":
            if cont in FILE_CONTAINERS:
                continue
        elif has_file_dumps and container is not None:
            if cont != container:
                continue
        val = v.get("value") if isinstance(v, dict) else v
        if isinstance(val, list):
            val = ", ".join(str(x) for x in val)
        val = "(present)" if val in (None, "") else str(val)
        name = canon(k) if normalize else k
        # Two raw keys can still normalise onto one name even inside a single
        # container, because the same field appears in several AV metadata
        # formats. Identical values are the normal case and merge silently; a
        # genuine disagreement is recorded and reported rather than hidden.
        if name in tags and tags[name] != val:
            collapsed.append(name)
            tags[name] = tags[name] + " | " + val
        else:
            tags[name] = val
    return tags, d, sorted(set(collapsed))


def available_containers(path):
    with open(path, encoding="utf-8") as f:
        d = json.load(f)
    return {raw_container(k) for k in (d.get("tags") or {})} - {None}


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
    ap.add_argument("--container",
                    help="which file the rig's rows should describe: INPUT, "
                         "OUTPUT, UPLOADED, SOURCE, or 'live' for what the app "
                         "read rather than a file dump. Defaults to INPUT under "
                         "--normalize, and to no filter otherwise.")
    ap.add_argument("--width", type=int, default=26, help="column width")
    ap.add_argument("--csv", help="also write the matrix to a CSV file")
    args = ap.parse_args()

    for p in args.runs:
        if not os.path.exists(p):
            sys.exit("no such file: %s" % p)

    # Normalising erases the container, so without a filter INPUT, OUTPUT and
    # UPLOADED would pile into one column and a field dropped by the re-encode
    # would still read as present. Pick one, and say which one out loud.
    container = args.container
    if container is None and args.normalize:
        present = set()
        for p in args.runs:
            present |= available_containers(p)
        for pref in ("INPUT", "SOURCE"):
            if pref in present:
                container = pref
                break
        else:
            container = "live"
        print("--normalize: comparing the %s view. Other containers are hidden "
              "because normalising merges them.\n"
              "             Override with --container OUTPUT / UPLOADED / live.\n"
              % container)

    # A container nobody has is the worst possible input: every rig row is
    # filtered away, every value reads as absent, and the summary reports a
    # catastrophic coverage failure that is really just a typo in a flag.
    if container is not None and container != "live":
        present = set()
        for p in args.runs:
            present |= available_containers(p)
        if present and container not in present:
            sys.exit("no run here has a %r container. Available: %s\n"
                     "(or pass --container live for what the app read rather "
                     "than a file dump)"
                     % (container, ", ".join(sorted(present)) or "none"))

    arms, metas, collapses = [], [], []
    for p in args.runs:
        tags, meta, collapsed = load(p, args.normalize, container)
        arms.append((arm_name(p), tags))
        metas.append(meta)
        if collapsed:
            collapses.append((arm_name(p), collapsed))

    for name, keys_ in collapses:
        print("NOTE: in %s, %d name(s) came from more than one raw tag with "
              "different values, shown joined by '|': %s"
              % (name, len(keys_), ", ".join(keys_[:6])), file=sys.stderr)

    names = [a for a, _ in arms]
    if len(set(names)) != len(names):
        print("WARNING: two runs resolved to the same column name. Put each run "
              "in its own directory named after the arm.\n", file=sys.stderr)

    if all(not t for _, t in arms):
        sys.exit("Every arm is empty after filtering to container %r. "
                 "Available: %s" % (container,
                                    ", ".join(sorted(available_containers(args.runs[0]))) or "none"))

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
