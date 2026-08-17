#!/usr/bin/env python3
"""Make an edited clip carry the same provenance a native iPhone capture does.

Workflow this is for: you film on the phone, edit somewhere better than the
in-app editor, and the export comes back as a bare ffmpeg/NLE file with every
capture field gone. This puts them back.

    python nativize.py --reference IMG_0026.MOV --input edited.mp4 --output ready.mov

The reference is any real capture off the same phone; every field is copied
from it, so the output is consistent by construction rather than by guesswork.
Without a reference, pass --make/--model/--software/--gps/--date yourself.

Scope note: this matches the fields the audit actually observed TikTok read
(runs/*/tags.json). It cannot make Photos report the file as a camera
original -- PHAsset.sourceType is set by Photos on import, and no file content
changes it.
"""

import argparse
import json
import os
import shutil
import subprocess
import sys

# What the audit observed TikTok read off the source file, in the containers
# it read them from. Anything outside this list was never seen being read.
KEYS = [
    "Keys:Make",
    "Keys:Model",
    "Keys:Software",
    "Keys:CreationDate",
    "Keys:GPSCoordinates",
    "Keys:LocationAccuracyHorizontal",
]
# Legacy UserData copies. TikTok reads these when a file carries them, but a
# genuine iPhone capture does NOT -- only our hand-stamped test clips did. So
# they are mirrored from the reference and never added on top of it: writing
# them onto an otherwise-native file is itself a tell.
USERDATA = [("UserData:Make", "Keys:Make"), ("UserData:Model", "Keys:Model")]

HEVC_ENCODERS = ["hevc_videotoolbox", "hevc_nvenc", "hevc_qsv", "hevc_amf", "libx265"]


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def need(tool):
    if not shutil.which(tool):
        sys.exit("error: %s is not on PATH. Install it and try again." % tool)


def probe_tags(path):
    r = run(["exiftool", "-j", "-G1", "-n", "-api", "largefilesupport=1", path])
    if r.returncode != 0 or not r.stdout.strip():
        sys.exit("error: exiftool could not read %s" % path)
    return json.loads(r.stdout)[0]


def probe_video(path):
    r = run(["ffprobe", "-v", "error", "-select_streams", "v:0",
             "-show_entries", "stream=width,height,r_frame_rate,codec_tag_string",
             "-show_entries", "stream_side_data=rotation", "-of", "json", path])
    if r.returncode != 0:
        sys.exit("error: ffprobe could not read %s" % path)
    st = json.loads(r.stdout)["streams"][0]
    num, den = (st.get("r_frame_rate") or "30/1").split("/")
    fps = float(num) / float(den or 1)
    rot = 0
    for sd in st.get("side_data_list") or []:
        if "rotation" in sd:
            rot = int(sd["rotation"])
    w, h = st["width"], st["height"]
    # A real iPhone stores portrait footage as landscape plus a rotation matrix.
    # Display size is what PhotoKit reports and what the viewer sees, so that is
    # the honest thing to compare on.
    dw, dh = (h, w) if abs(rot) % 180 == 90 else (w, h)
    return dict(width=w, height=h, fps=fps, tag=st.get("codec_tag_string"),
                rotation=rot, disp_w=dw, disp_h=dh)


def encoder_works(enc):
    """Being listed is not the same as being usable -- drivers lie."""
    r = run(["ffmpeg", "-v", "error", "-f", "lavfi", "-i", "color=c=black:s=256x256:d=0.1",
             "-c:v", enc, "-f", "null", "-"])
    return r.returncode == 0


def pick_encoder(explicit=None):
    if explicit:
        if not encoder_works(explicit):
            sys.exit("error: %s is present but will not run on this machine" % explicit)
        return explicit
    have = run(["ffmpeg", "-v", "error", "-encoders"]).stdout
    for enc in HEVC_ENCODERS:
        if enc in have and encoder_works(enc):
            return enc
    sys.exit("error: no working HEVC encoder in this ffmpeg build")


def build_stamp(args):
    """Resolve the field values, from --reference and/or explicit flags."""
    stamp, src = {}, {}
    if args.reference:
        ref = probe_tags(args.reference)
        for k in KEYS:
            if ref.get(k) not in (None, ""):
                stamp[k] = ref[k]
                src[k] = "reference"
    for flag, key in [("make", "Keys:Make"), ("model", "Keys:Model"),
                      ("software", "Keys:Software"), ("date", "Keys:CreationDate"),
                      ("gps", "Keys:GPSCoordinates"),
                      ("accuracy", "Keys:LocationAccuracyHorizontal")]:
        v = getattr(args, flag)
        if v:
            stamp[key] = v
            src[key] = "flag"
    ref_tags = probe_tags(args.reference) if args.reference else None
    for ud, kk in USERDATA:
        if kk not in stamp:
            continue
        if ref_tags is not None:
            # mirror the reference exactly, absence included
            if ref_tags.get(ud) in (None, ""):
                continue
        elif not args.legacy_userdata:
            continue
        stamp[ud] = stamp[kk]
        src[ud] = src[kk]
    # exiftool reads GPSCoordinates back space-separated but only accepts it
    # comma-separated on write, failing with a warning rather than an error.
    g = stamp.get("Keys:GPSCoordinates")
    if g and "," not in str(g):
        stamp["Keys:GPSCoordinates"] = ", ".join(str(g).split())
    return stamp, src


COMPARE_FIELDS = [
    "Keys:Make", "Keys:Model", "Keys:Software", "Keys:CreationDate",
    "Keys:GPSCoordinates", "Keys:LocationAccuracyHorizontal",
    "UserData:Make", "UserData:Model", "UserData:Title", "UserData:Comment",
    "QuickTime:MajorBrand",
]


def compare(candidate, reference):
    """Diff two files on exactly what the audit saw TikTok read. Nothing else."""
    for f in (candidate, reference):
        if not os.path.isfile(f):
            sys.exit("error: no such file: %s" % f)
    c, r = probe_tags(candidate), probe_tags(reference)
    cv, rv = probe_video(candidate), probe_video(reference)
    # every metadata tag either file carries, not a shortlist: a whitelist
    # hid ffmpeg's UserData:SoftwareVersion signature on the first build
    groups = ("Keys", "UserData", "ItemList", "XMP")
    keys = sorted({k for d in (c, r) for k in d
                   if k.split(":")[0].startswith(groups)})
    print("%-34s %-28s %-28s" % ("field", "reference", "candidate"))
    print("-" * 94)
    same = True
    for k in (keys or COMPARE_FIELDS):
        rvv, cvv = r.get(k), c.get(k)
        hit = str(rvv) == str(cvv)
        same &= hit
        print("%-34s %-28s %-28s %s"
              % (k, str(rvv if rvv is not None else "-")[:26],
                 str(cvv if cvv is not None else "-")[:26], "" if hit else "<-- differs"))
    print()
    for label, rr, cc, counts in [
            ("video codec", rv["tag"], cv["tag"], True),
            ("frame size (as displayed)", "%dx%d" % (rv["disp_w"], rv["disp_h"]),
             "%dx%d" % (cv["disp_w"], cv["disp_h"]), True),
            ("frame rate", "%.3f" % rv["fps"], "%.3f" % cv["fps"], True),
            ("stored size", "%dx%d" % (rv["width"], rv["height"]),
             "%dx%d" % (cv["width"], cv["height"]), False),
            ("rotation matrix", "%d" % rv["rotation"], "%d" % cv["rotation"], False)]:
        hit = rr == cc
        if counts:
            same &= hit
        note = "" if hit else ("<-- differs" if counts else "<-- differs (not read by TikTok)")
        print("%-34s %-28s %-28s %s" % (label, rr, cc, note))
    print()
    print("MATCH -- indistinguishable on every field the audit saw read"
          if same else "DIFFERS -- see the rows marked above")
    return 0 if same else 1


def main():
    ap = argparse.ArgumentParser(
        description="Give an edited clip the provenance of a native iPhone capture.")
    ap.add_argument("--input", help="the edited clip")
    ap.add_argument("--output", help="file to write (.mov)")
    ap.add_argument("--check", metavar="FILE",
                    help="compare FILE against --reference on the fields the audit "
                         "saw TikTok read, and exit. Produces nothing.")
    ap.add_argument("--reference", help="a real capture off the same phone to copy from")
    ap.add_argument("--make"), ap.add_argument("--model"), ap.add_argument("--software")
    ap.add_argument("--date", help='e.g. "2026:08:14 19:31:34+03:00"')
    ap.add_argument("--gps", help='e.g. "54.6389, 24.9351, 161.972"')
    ap.add_argument("--accuracy", help="horizontal accuracy in metres, e.g. 35.0")
    ap.add_argument("--encoder", help="force an HEVC encoder")
    ap.add_argument("--crf", default="20", help="quality, lower is better (default 20)")
    ap.add_argument("--keep-size", action="store_true",
                    help="keep the edit's own resolution instead of the reference's")
    ap.add_argument("--legacy-userdata", action="store_true",
                    help="also write UserData:Make/Model (a real capture has neither)")
    ap.add_argument("--graft-tracks", action="store_true",
                    help="copy the reference's timed-metadata tracks. NOT recommended: "
                         "ffmpeg cannot write mebx sample entries, so the tracks land "
                         "tagged stts, which no real file has. The audit never saw TikTok "
                         "read track structure at all, so this adds a new anomaly to fix "
                         "something that was never measured being checked.")
    args = ap.parse_args()

    need("ffmpeg"), need("ffprobe"), need("exiftool")
    if args.check:
        if not args.reference:
            sys.exit("error: --check needs --reference to compare against")
        return compare(args.check, args.reference)
    if not args.input or not args.output:
        sys.exit("error: --input and --output are required (or use --check)")
    if not os.path.isfile(args.input):
        sys.exit("error: no such file: %s" % args.input)
    if args.reference and not os.path.isfile(args.reference):
        sys.exit("error: no such reference: %s" % args.reference)

    stamp, src = build_stamp(args)
    if not stamp:
        sys.exit("error: nothing to write. Pass --reference or the field flags.")

    vin = probe_video(args.input)
    vref = probe_video(args.reference) if args.reference else None
    if vref and not args.keep_size:
        w, h, fps = vref["disp_w"], vref["disp_h"], vref["fps"]
        # a portrait edit against a landscape reference (or the reverse) should
        # keep its own orientation; only borrow the long/short edge pairing
        if (vin["disp_w"] > vin["disp_h"]) != (w > h):
            w, h = h, w
    else:
        w, h, fps = vin["disp_w"], vin["disp_h"], vin["fps"]

    enc = pick_encoder(args.encoder)
    print("encoder      %s" % enc)
    print("picture      %dx%d @ %.3f fps  ->  hvc1" % (w, h, fps))

    cmd = ["ffmpeg", "-v", "error", "-y", "-i", args.input]
    if args.graft_tracks and args.reference:
        cmd += ["-i", args.reference]
    cmd += ["-map", "0:v:0", "-map", "0:a:0?"]
    if args.graft_tracks and args.reference:
        cmd += ["-map", "1:d?"]
    cmd += ["-c:v", enc, "-tag:v", "hvc1",
            "-vf", "scale=%d:%d" % (w, h), "-r", "%.6f" % fps,
            "-pix_fmt", "yuv420p", "-c:a", "aac", "-b:a", "128k"]
    if enc == "libx265":
        cmd += ["-crf", args.crf, "-preset", "medium", "-x265-params", "log-level=error"]
    if args.graft_tracks and args.reference:
        cmd += ["-c:d", "copy"]
    # AVFoundation names its tracks this way; ffmpeg and most NLEs do not.
    cmd += ["-metadata:s:v:0", "handler_name=Core Media Video",
            "-metadata:s:a:0", "handler_name=Core Media Audio",
            "-f", "mov", args.output]

    r = run(cmd)
    if r.returncode != 0:
        sys.exit("ffmpeg failed:\n" + (r.stderr or "")[-2000:])

    ex = ["exiftool", "-overwrite_original", "-q", "-api", "largefilesupport=1"]
    for k, v in stamp.items():
        ex.append("-%s=%s" % (k, v))
    ex.append(args.output)
    r = run(ex)
    if r.returncode != 0:
        sys.exit("exiftool failed:\n" + (r.stderr or ""))

    # ffmpeg signs its own output (UserData:SoftwareVersion = Lavf...), and a
    # genuine capture carries no UserData at all. Anything the reference does
    # not have is itself a tell, so drop it.
    if args.reference:
        ref_all = probe_tags(args.reference)
        out_all = probe_tags(args.output)
        extra = [k for k in out_all
                 if k.split(":")[0] in ("Keys", "UserData", "ItemList")
                 and k not in ref_all]
        if extra:
            rm = ["exiftool", "-overwrite_original", "-q",
                  "-api", "largefilesupport=1"]
            rm += ["-%s=" % k for k in extra]
            rm.append(args.output)
            rr = run(rm)
            if rr.returncode != 0:
                sys.exit("exiftool strip failed: " + (rr.stderr or ""))
            print("stripped (absent from the reference): %s" % ", ".join(extra))
    warn = [x for x in (r.stdout + r.stderr).splitlines() if "Warning" in x]
    if warn:
        print("exiftool warnings:")
        for x in warn:
            print("  " + x)

    # ---- verify what we claim to have written is actually on the file
    got = probe_tags(args.output)
    gv = probe_video(args.output)
    print("\n%-34s %-26s %s" % ("field", "written", "source"))
    ok = True
    for k in sorted(stamp):
        have = got.get(k)
        match = have is not None and str(have).strip() == str(stamp[k]).strip()
        # exiftool normalises GPS and dates on write; compare loosely for those
        if not match and have is not None:
            match = str(stamp[k]).replace(",", "").split()[:2] == \
                    str(have).replace(",", "").split()[:2]
        ok &= match
        print("%-34s %-26s %s%s" % (k, str(have)[:26], src.get(k, ""),
                                    "" if match else "   <-- MISMATCH"))
    print("\ncodec        %s%s" % (gv["tag"], "" if gv["tag"] == "hvc1" else "   <-- not hvc1"))
    print("picture      %dx%d @ %.3f fps" % (gv["width"], gv["height"], gv["fps"]))
    ok &= gv["tag"] == "hvc1"
    print("\n%s -> %s" % ("OK" if ok else "PROBLEM", args.output))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
