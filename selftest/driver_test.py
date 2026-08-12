#!/usr/bin/env python3
"""
driver_test.py  -  replay a recorded batch through the real driver.

The driver's job is not to collect data, it is to decide what data MEANS: which
rows are provenance, which are flagged, how a tag is bucketed, what lands in the
diffable sidecar. None of that needs a phone, and all of it is wrong in ways
that only show up after a post has already been spent.

So this feeds selftest/batch.json - produced by observe_test.js from the real
observe.js source - through the real make_message_handler, the real Recorder,
the real report renderer and the real sidecar writers. Two halves of the rig,
one shared fixture.

Not run directly as a rule. selftest.py drives it, twice, under two run names,
because run isolation is only observable across two runs.

    python selftest/driver_test.py <run-name>
"""
import sys, os, io, json, types, base64

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

RUN_NAME = sys.argv[1] if len(sys.argv) > 1 else "selftest"
# --strip replays the same batch with every geotag and identity field removed,
# which is the "native, stripped" arm of the six-arm test. It exists so the
# comparison tooling has two runs that genuinely differ, rather than being
# checked against a copy of itself.
STRIP = "--strip" in sys.argv
STRIP_MARKERS = ("GPS", "location.ISO6709", "content.identifier",
                 "Latitude", "Longitude", "creationdate")

# --- import the driver without a phone -------------------------------------
# frida is the only import that needs a device to be useful, and it is not
# installed on a machine that is only ever going to read JSON. The stub carries
# the exception classes main() catches by name, so the import resolves and
# nothing about the code under test is altered.
if "frida" not in sys.modules:
    frida = types.ModuleType("frida")

    class _Err(Exception):
        pass

    for _n in ("ProcessNotFoundError", "TransportError", "InvalidOperationError",
               "ProcessNotRespondingError", "ServerNotRunningError"):
        setattr(frida, _n, type(_n, (_Err,), {}))
    frida.get_usb_device = lambda **kw: (_ for _ in ()).throw(
        RuntimeError("selftest must never open a device"))
    sys.modules["frida"] = frida

# run_observe reads both of these AT IMPORT: argv[0] decides the duration and
# the env var decides where artifacts land. Set them before the import or the
# module picks up this script's own arguments.
os.environ["TIKTOK_AUDIT_RUN"] = RUN_NAME
_argv = sys.argv
sys.argv = ["run_observe.py", "40"]
sys.path.insert(0, ROOT)
import run_observe as R           # noqa: E402
sys.argv = _argv

# --- assertions -------------------------------------------------------------
passed = 0
failures = []


def ok(cond, what):
    global passed
    if cond:
        passed += 1
        return True
    failures.append(what)
    return False


def eq(actual, expected, what):
    return ok(actual == expected,
              "%s  (got %r, wanted %r)" % (what, actual, expected))


# --- replay -----------------------------------------------------------------
_batch = os.path.join(HERE, "batch.json")
if not os.path.exists(_batch):
    # Deliberately not committed: a stale fixture would keep passing after
    # observe.js changed, which is the one failure this suite exists to catch.
    sys.exit("selftest/batch.json is missing. It is produced from the live "
             "observe.js source by:\n    node selftest/observe_test.js\n"
             "or just run:  python selftest.py")
with open(_batch, encoding="utf-8") as f:
    fixture = json.load(f)

console = R.Console(R.LOG_PATH)
rec = R.Recorder(console)
errors, probe_log, probe_calls = [], [], {}
last_beat, armed = [0.0], [False]
handler = R.make_message_handler(rec, console, errors, last_beat, armed,
                                 probe_log, probe_calls)

# the console prints the live stream as rows arrive, which is not what is being
# tested here and would bury the result. Captured, then asserted on.
_stdout = sys.stdout
sys.stdout = io.StringIO()
try:
    for payload in fixture["batches"]:
        if STRIP:
            payload = dict(payload)
            payload["b"] = [r for r in payload.get("b") or []
                            if not (r[0] in ("MEDIA_TAG", "MEDIA_FILE")
                                    and any(m in (r[1] or "") for m in STRIP_MARKERS))]
        handler({"type": "send", "payload": payload}, None)
    rec.flush()
    stream = sys.stdout.getvalue()

    meta = {"duration_s": 40, "observed_s": 40.0, "attached": False,
            "probes": [], "probe_calls": {}, "probe_passes": 0}
    sys.stdout = io.StringIO()
    R.report(rec, console, meta)
    rendered = sys.stdout.getvalue()
finally:
    sys.stdout = _stdout

R.dump_json(rec, meta)

# --- the message handler ----------------------------------------------------
ok(armed[0], "the handler armed on the first message")
eq(errors, [], "no errors were raised while replaying a clean batch")
ok(len(rec.items) > 0, "rows were recorded")

# MARK is a boundary, not a finding: it must not become a row
ok(("MARK", "post-1") not in rec.items, "a mark did not become a report row")
ok(any(m[0] == "post-1" for m in rec.marks), "the mark was recorded as a boundary")
ok("mark: post-1" in stream, "the mark is visible in the live stream as it happens")

# --- category routing -------------------------------------------------------
prov = [r for r in rec.items.values() if r["cat"] == "PROVENANCE"]
ok(len(prov) > 20, "MEDIA_TAG and MEDIA_FILE route to the PROVENANCE section "
                   "(got %d rows)" % len(prov))
ok(all(r["src"] in ("MEDIA_TAG", "MEDIA_FILE") for r in prov),
   "nothing unrelated leaked into PROVENANCE")

media = [r for r in rec.items.values() if r["cat"] == "MEDIA"]
ok(len(media) > 0, "the narrative MEDIA rows still exist alongside the inventory")


def row(src, key):
    return rec.items.get((src, key))


# --- flagging ---------------------------------------------------------------
# a tag that places the person or names the device is the point of the section
_identifying = ["image {TIFF} Make", "library sourceType"]
if not STRIP:
    _identifying += ["video metadata mdta/com.apple.quicktime.location.ISO6709",
                     "image {GPS} LatitudeRef"]
for key in _identifying:
    r = row("MEDIA_TAG", key)
    ok(r is not None and r["tier"] == R.FLAG, "identifying tag is flagged: %s" % key)

if STRIP:
    # the stripped arm exists to be diffed against the native one, so the
    # fields it is supposed to be missing had better actually be missing
    ok(row("MEDIA_TAG", "image {GPS} LatitudeRef") is None,
       "the stripped arm really has no GPS tag")
    ok(row("MEDIA_TAG", "video metadata mdta/com.apple.quicktime.location.ISO6709") is None,
       "the stripped arm really has no QuickTime geotag")
    ok(row("MEDIA_TAG", "image {TIFF} Make") is not None,
       "the stripped arm still carries the fields that were not stripped")

# exposure settings are evidence, not exposure, and must not be flagged or the
# section turns into a wall of red that nobody reads
r = row("MEDIA_TAG", "image {Exif} ISOSpeedRatings")
ok(r is not None and r["tier"] != R.FLAG, "an exposure setting is not flagged")
r = row("MEDIA_TAG", "image PixelWidth")
ok(r is not None and r["tier"] != R.FLAG, "a pixel dimension is not flagged")

# --- values survive ---------------------------------------------------------
# every other section keeps key names only. This one has to keep values, or a
# stamping diff has nothing to compare.
r = row("MEDIA_TAG", "video metadata mdta/com.apple.quicktime.model")
ok(r is not None and "iPhone X" in r["values"], "a tag value reached the recorder")
r = row("MEDIA_TAG", "library mediaSubtypes")
ok(r is not None and "LIVE PHOTO" in r["values"], "the Live Photo flag reached the recorder")

# --- the rendered report ----------------------------------------------------
ok("EVERY TAG ON THE POST PATH" in rendered, "the PROVENANCE panel is rendered")
ok("iPhone X" in rendered, "a tag value is printed in the report")
for heading in ("INPUT", "OUTPUT", "UPLOADED"):
    ok(heading in rendered, "the %s container is a heading in the report" % heading)
ok("written into the export" in rendered,
   "what TikTok wrote into its own export is a heading of its own")
ok("compare_runs.py" in rendered,
   "the report tells the operator how to diff this run against another")
# both ends were captured in the fixture, so the report must say so rather than
# printing the single-ended warning
ok("Both ends were captured" in rendered, "the both-ends guidance is shown")
ok("Only one end was captured" not in rendered, "the single-end warning is not shown")

# --- the diffable sidecar ---------------------------------------------------
with open(R.TAGS_PATH, encoding="utf-8") as f:
    tags = json.load(f)

ok(tags["tag_count"] > 20, "tags.json carries the inventory (%d tags)" % tags["tag_count"])
_keys = list(tags["tags"])
_first_unsorted = next((i for i in range(len(_keys) - 1) if _keys[i] > _keys[i + 1]), None)
ok(_first_unsorted is None,
   "tags.json is sorted, so diffs are stable"
   + ("" if _first_unsorted is None
      else "  (%r precedes %r)" % (_keys[_first_unsorted], _keys[_first_unsorted + 1])))
ok("video metadata mdta/com.apple.quicktime.make" in tags["tags"],
   "a QuickTime tag is in the sidecar")
eq(tags["tags"]["video metadata mdta/com.apple.quicktime.make"]["value"], "Apple",
   "the sidecar keeps the value, not just the name")
ok(any(m["label"] == "post-1" for m in tags["marks"]), "marks are in the sidecar")
ok("INPUT" in tags["files"] and "UPLOADED" in tags["files"],
   "both ends of the post are listed in the sidecar")
ok(all(isinstance(v.get("reads"), int) for v in tags["tags"].values()),
   "every tag carries a read count")

# --- request bodies ---------------------------------------------------------
ok(len(rec.blob_index) >= 1, "a request body was written to disk")
body_files = os.listdir(R.BODY_DIR) if os.path.isdir(R.BODY_DIR) else []
ok(len(body_files) == len(rec.blob_index), "every indexed body exists on disk")

publish = next((b for b in rec.blob_index if "aweme_v1_aweme_post" in b[0]), None)
ok(publish is not None, "the publish body was written with a recognisable name")
if publish:
    with open(os.path.join(R.BODY_DIR, publish[0]), "rb") as f:
        raw = f.read()
    decoded = json.loads(raw.decode("utf-8"))
    eq(decoded.get("upload_source"), "camera_roll",
       "the body on disk decodes back to the original JSON")
    eq(len(raw), publish[2], "the recorded byte count matches the file")

# a body name becomes a filename, so it must never carry a path separator out
ok(all("/" not in b[0] and "\\" not in b[0] for b in rec.blob_index),
   "body filenames are sanitised")

# --- run isolation ----------------------------------------------------------
ok(os.path.abspath(R.TAGS_PATH).replace("\\", "/").endswith(
       "runs/%s/tags.json" % RUN_NAME),
   "artifacts landed in runs/%s/ (got %s)" % (RUN_NAME, R.TAGS_PATH))
ok(os.path.isdir(R.BODY_DIR), "the per-run bodies directory was created")

# --- audit.json still works -------------------------------------------------
with open(R.JSON_PATH, encoding="utf-8") as f:
    audit = json.load(f)
ok(audit["distinct"] == len(rec.items), "audit.json agrees with the recorder")
ok(any(e["category"] == "PROVENANCE" for e in audit["events"]),
   "provenance rows are in audit.json too")

# ----------------------------------------------------------------------------
print("")
print("  driver     %d checks passed, %d failed   [run=%s]"
      % (passed, len(failures), RUN_NAME))
if failures:
    print("")
    for f in failures:
        print("  FAIL  " + f)
    sys.exit(1)
sys.exit(0)
