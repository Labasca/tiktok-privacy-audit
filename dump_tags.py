#!/usr/bin/env python3
"""
dump_tags.py  -  the DENOMINATOR for a coverage check.

The rig reports which tags crossed into TikTok. On its own that number means
nothing, because "5 tags observed" is excellent if the file held 5 and useless
if it held 47. This reads the file directly with exiftool and writes the same
flat shape tags.json uses, so the two can be compared by the same tool:

    ./dump_tags.py runs/01-native/source.mov          # writes source.tags.json
    ./compare_runs.py runs/01-native/source.tags.json runs/01-native/tags.json

Any tag exiftool finds that the rig never names is either a tag TikTok did not
touch or a hook we do not have, and after the sub-dictionary walk landed those
two are finally distinguishable.

Run this on every test file BEFORE posting it. Once the file is uploaded and
re-encoded the original tags are gone, and a denominator recovered afterwards
is a guess.

Requires exiftool on PATH. READ-ONLY: this never modifies the files it reads.
"""
import sys, os, json, subprocess, shutil, argparse

# exiftool groups every tag as "Family1:TagName". These are the families that
# carry provenance. The rest (File, Composite, ExifTool) are either derived by
# exiftool itself or describe the bytes on disk rather than the capture, and
# including them makes every diff noisy with facts that cannot be stamped.
KEEP_GROUPS = {
    "EXIF", "GPS", "IFD0", "IFD1", "ExifIFD", "MakerNotes", "Apple",
    "QuickTime", "Keys", "UserData", "ItemList", "Track1", "Track2", "Track3",
    "XMP", "XMP-x", "XMP-xmp", "XMP-dc", "XMP-photoshop", "XMP-crs",
    "IPTC", "ICC_Profile", "ICC-header", "PNG", "JFIF", "HEIC", "C2PA",
    "JUMBF", "Photoshop",
}

# Two families worth keeping even though they are not capture metadata, because
# a stamping test needs them: File tells you the container and dimensions, and a
# C2PA manifest is the thing the strip step has to remove.
ALWAYS = ("File:FileType", "File:FileTypeExtension", "File:MIMEType",
          "File:ImageWidth", "File:ImageHeight", "File:FileSize")


def run_exiftool(path, all_groups=False):
    if not shutil.which("exiftool"):
        sys.exit("exiftool is not on PATH.\n"
                 "  macOS:   brew install exiftool\n"
                 "  Debian:  apt install libimage-exiftool-perl\n"
                 "  Windows: winget install OliverBetz.ExifTool")
    # -G1 gives the specific group, -a keeps duplicate tags, -s uses tag names
    # rather than descriptions, -j is JSON, -n keeps numbers unformatted so a
    # coordinate compares as a number instead of a prettified string.
    cmd = ["exiftool", "-a", "-G1", "-s", "-j", "-n", path]
    out = subprocess.run(cmd, capture_output=True, text=True)
    if out.returncode != 0 and not out.stdout.strip():
        sys.exit("exiftool failed on %s:\n%s" % (path, out.stderr.strip()))
    data = json.loads(out.stdout)
    return data[0] if data else {}


def collect(path, all_groups=False):
    raw = run_exiftool(path)
    tags = {}
    for k, v in raw.items():
        if k in ("SourceFile",):
            continue
        group = k.split(":", 1)[0] if ":" in k else ""
        if not all_groups and group not in KEEP_GROUPS and k not in ALWAYS:
            continue
        if isinstance(v, (dict, list)):
            v = json.dumps(v, ensure_ascii=False)
        s = str(v)
        # binary payloads print as a placeholder. Their size is the only part
        # that is both stable and comparable.
        if s.startswith("(Binary data"):
            s = "(" + s.split(",")[0].replace("(Binary data ", "") + " bytes of data)"
        if len(s) > 72:
            s = s[:69] + "..."
        tags[k] = {"value": s, "reads": None, "first_seen_s": None}
    return tags


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("files", nargs="+", help="media files to dump")
    ap.add_argument("--all", action="store_true",
                    help="keep every exiftool group, not just the provenance ones")
    ap.add_argument("-o", "--out",
                    help="output path (default: <file>.tags.json beside each input)")
    args = ap.parse_args()

    if args.out and len(args.files) > 1:
        sys.exit("--out takes one input file at a time.")

    for path in args.files:
        if not os.path.exists(path):
            sys.exit("no such file: %s" % path)
        tags = collect(path, args.all)
        out = args.out or (os.path.splitext(path)[0] + ".tags.json")
        data = {
            "run": {"source": os.path.abspath(path), "tool": "exiftool",
                    "bytes": os.path.getsize(path)},
            "marks": [], "files": {"SOURCE": [os.path.basename(path)]},
            "bodies": [],
            "tag_count": len(tags),
            "tags": {k: tags[k] for k in sorted(tags)},
        }
        with open(out, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        print("%s  ->  %s  (%d tags)" % (path, out, len(tags)))

    print("\nNow diff the file against what the rig saw:")
    print("  ./compare_runs.py <file>.tags.json runs/<arm>/tags.json --diff-only")


if __name__ == "__main__":
    main()
