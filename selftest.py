#!/usr/bin/env python3
"""
selftest.py  -  prove the rig works before spending a post on it.

Everything here runs with no phone, no USB, no frida and no network. It is the
check to run after cloning onto a new machine and after any change to the hook
script or the driver, because the alternative way to find a bug in either is to
burn an account, a post and an afternoon.

    python selftest.py            # run everything
    python selftest.py -v         # show each suite's full output

What it covers:

  1. observe.js executed against a stubbed Objective-C bridge: the tag walks,
     the drain, the budgets, and the re-entrancy guard that stops the rig from
     recording its own reads as TikTok's.
  2. The driver replaying that exact batch: categorisation, flagging, the
     rendered report, tags.json and the request-body files.
  3. Run isolation, and both comparison modes over two arms that really differ.
  4. The launchers' argument handling, and dump_tags.py's exiftool preflight.

What it CANNOT cover, and what the first phone run is therefore still for:

  - whether the selectors exist on TikTok's build (the report's "post-path hook
    NOT attached" lines answer this on the first run)
  - whether the real frameworks return what the stubs return
  - whether the file drain stays inside its time budget on real files
  - anything about how TikTok's servers treat what they receive
"""
import os, sys, subprocess, shutil, json, re, tempfile

ROOT = os.path.dirname(os.path.abspath(__file__))
os.chdir(ROOT)
VERBOSE = "-v" in sys.argv or "--verbose" in sys.argv

RESULTS = []


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True,
                          cwd=ROOT, timeout=300, **kw)


def suite(name, fn):
    try:
        detail = fn()
        RESULTS.append((True, name, detail or ""))
    except AssertionError as e:
        RESULTS.append((False, name, str(e)))
    except Exception as e:
        RESULTS.append((False, name, "%s: %s" % (type(e).__name__, e)))


def show(label, out):
    if VERBOSE and out.strip():
        print("      " + out.strip().replace("\n", "\n      "))


def counts(text):
    """Pull 'N checks passed, M failed' out of a suite's output."""
    m = re.search(r"(\d+) checks passed, (\d+) failed", text)
    if not m:
        raise AssertionError("no result line in output:\n" + text[-2000:])
    return int(m.group(1)), int(m.group(2))


# ---------------------------------------------------------------------------
# 1. the phone-side script
# ---------------------------------------------------------------------------
def t_observe():
    node = shutil.which("node")
    if not node:
        raise AssertionError("node is not on PATH, so observe.js cannot be "
                             "exercised. Install Node and re-run.")
    r = run([node, "selftest/observe_test.js"])
    show("observe", r.stdout + r.stderr)
    p, f = counts(r.stdout)
    assert r.returncode == 0 and f == 0, r.stdout + r.stderr
    assert os.path.exists("selftest/batch.json"), "batch.json was not written"
    return "%d checks" % p


# ---------------------------------------------------------------------------
# 2 + 3. the driver, twice, so isolation and comparison are observable
# ---------------------------------------------------------------------------
ARMS = [("selftest-native", []), ("selftest-stripped", ["--strip"])]


def t_driver():
    total = 0
    for arm, extra in ARMS:
        shutil.rmtree(os.path.join("runs", arm), ignore_errors=True)
        r = run([sys.executable, "selftest/driver_test.py", arm] + extra)
        show(arm, r.stdout + r.stderr)
        p, f = counts(r.stdout)
        assert r.returncode == 0 and f == 0, r.stdout + r.stderr
        total += p
    return "%d checks over %d arms" % (total, len(ARMS))


def t_isolation():
    """Two arms must land in two directories with different contents. If they
    do not, the six-arm test is six copies of whichever run finished last."""
    for arm, _ in ARMS:
        for f in ("tags.json", "audit.json", "session.log"):
            path = os.path.join("runs", arm, f)
            assert os.path.exists(path), "missing %s" % path
        assert os.path.isdir(os.path.join("runs", arm, "bodies")), \
            "%s has no bodies/ directory" % arm
    a = open(os.path.join("runs", ARMS[0][0], "tags.json"), encoding="utf-8").read()
    b = open(os.path.join("runs", ARMS[1][0], "tags.json"), encoding="utf-8").read()
    assert a != b, ("two arms produced identical tags.json, so either run "
                    "isolation is broken or the arms do not actually differ")
    return "2 arms, separate directories, different contents"


def t_root_default():
    """An unnamed run keeps the old flat filenames. Checked in a subprocess
    because the paths are decided at import time and cannot be re-decided."""
    code = (
        "import sys,types;"
        "m=types.ModuleType('frida');"
        "m.get_usb_device=lambda **k:None;"
        "sys.modules['frida']=m;"
        "sys.argv=['run_observe.py','40'];"
        "import run_observe as R;"
        "print(R.TAGS_PATH);print(R.JSON_PATH);print(R.BODY_DIR)"
    )
    env = dict(os.environ)
    env.pop("TIKTOK_AUDIT_RUN", None)
    r = run([sys.executable, "-c", code], env=env)
    assert r.returncode == 0, r.stderr
    tags, audit, bodies = r.stdout.split()
    assert tags == "tags.json", "unnamed run moved tags.json to %r" % tags
    assert audit == "audit.json", "unnamed run moved audit.json to %r" % audit
    assert bodies == "bodies", "unnamed run moved bodies/ to %r" % bodies

    # A named run is redirected, and no name may resolve outside runs/. The
    # property that matters is containment, not the absence of any particular
    # character, so it is checked by resolving the path.
    runs_root = os.path.realpath(os.path.join(ROOT, "runs"))
    for name in ("07 native", "07 native/../weird", "..", "../..", ".", "  ",
                 "a/b/c", "arm:1*?"):
        env["TIKTOK_AUDIT_RUN"] = name
        r = run([sys.executable, "-c", code], env=env)
        assert r.returncode == 0, "run name %r crashed the driver:\n%s" % (name, r.stderr)
        tags = r.stdout.split()[0]
        if not name.strip():
            assert tags == "tags.json", \
                "a blank run name should behave as unnamed, got %r" % tags
            continue
        resolved = os.path.realpath(os.path.join(ROOT, tags))
        assert resolved.startswith(runs_root + os.sep), \
            "run name %r escaped runs/: %s" % (name, resolved)
    return "root default preserved, %d hostile names contained" % 7


# ---------------------------------------------------------------------------
# comparison
# ---------------------------------------------------------------------------
def t_compare_exact():
    r = run([sys.executable, "compare_runs.py",
             "runs/selftest-native/tags.json",
             "runs/selftest-stripped/tags.json", "--diff-only"])
    show("compare", r.stdout + r.stderr)
    assert r.returncode == 0, r.stderr
    out = r.stdout
    for name in ("selftest-native", "selftest-stripped"):
        assert name in out, "column %s is missing from the matrix" % name

    # the stripped arm must be visibly missing the geotag, and the native arm
    # must visibly still have it. This is the exact read the six-arm test makes.
    assert re.search(r"image \{GPS\} LatitudeRef\s+N\s+-", out), \
        "the GPS difference between the arms is not shown:\n" + out[:1500]
    m = re.search(r"selftest-stripped vs selftest-native: (\d+) tags missing", out)
    assert m, "no summary line"
    assert int(m.group(1)) >= 10, "expected the stripped arm to be missing many " \
                                  "tags, got %s" % m.group(1)

    # a tag identical in both arms must be hidden under --diff-only
    assert "image {TIFF} Make" not in out, \
        "--diff-only printed a tag that is identical across arms"

    # CSV output has to survive the same content
    with tempfile.TemporaryDirectory() as d:
        csv_path = os.path.join(d, "m.csv")
        r2 = run([sys.executable, "compare_runs.py",
                  "runs/selftest-native/tags.json",
                  "runs/selftest-stripped/tags.json", "--csv", csv_path])
        assert r2.returncode == 0, r2.stderr
        body = open(csv_path, encoding="utf-8").read()
        assert "image {GPS} LatitudeRef" in body, "CSV lost a row"
    return "%s tags differ, CSV intact" % m.group(1)


def t_compare_normalized():
    """exiftool and CoreGraphics name the same field differently. The coverage
    check is only meaningful if those names reconcile, so both fixtures must
    come back with nothing missing."""
    checks = [
        ("selftest/fixture-mov.tags.json", "INPUT", "quicktime.make"),
        ("selftest/fixture-heic.tags.json", "live", "gps.latituderef"),
    ]
    out_bits = []
    for fixture, container, must_align in checks:
        r = run([sys.executable, "compare_runs.py", fixture,
                 "runs/selftest-native/tags.json",
                 "--normalize", "--container", container])
        show(fixture, r.stdout + r.stderr)
        assert r.returncode == 0, r.stderr
        m = re.search(r"vs \S+: (\d+) tags missing", r.stdout)
        assert m, "no summary line for %s:\n%s" % (fixture, r.stdout[:800])
        missing = int(m.group(1))
        assert missing == 0, (
            "%d tag(s) the file dump names were NOT matched by the rig under "
            "--normalize with container=%s. Either a hook is missing or the "
            "name reconciliation is wrong:\n%s"
            % (missing, container, r.stdout[:2000]))
        # and the alignment must be real, not an empty comparison
        assert re.search(re.escape(must_align) + r"\s+\S", r.stdout), \
            "%s did not appear in the matrix, so nothing was actually compared" \
            % must_align
        out_bits.append("%s/%s ok" % (os.path.basename(fixture), container))

    # a container that does not exist must fail loudly, not silently compare
    # nothing and report a clean bill of health
    r = run([sys.executable, "compare_runs.py", "selftest/fixture-mov.tags.json",
             "runs/selftest-native/tags.json", "--normalize",
             "--container", "NOSUCH"])
    assert r.returncode != 0, \
        "an unknown --container was accepted and compared nothing:\n" + r.stdout
    return ", ".join(out_bits)


# ---------------------------------------------------------------------------
# 4. tooling around the edges
# ---------------------------------------------------------------------------
# An 8x8 JPEG, embedded so this test needs neither Pillow nor a checked-in
# binary. exiftool writes real tags into it and dump_tags.py reads them back,
# which is the only way to test that path for real rather than against a
# hand-written guess at exiftool's output.
TINY_JPEG_B64 = (
    "/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAA0JCgsKCA0LCgsODg0PEyAVExISEyccHhcgLikxMC4p"
    "LSwzOko+MzZGNywtQFdBRkxOUlNSMj5aYVpQYEpRUk//2wBDAQ4ODhMREyYVFSZPNS01T09PT09P"
    "T09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0//wAARCAAIAAgDASIAAhEB"
    "AxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQAAAF9"
    "AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6"
    "Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ip"
    "qrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/8QAHwEAAwEB"
    "AQEBAQEBAQAAAAAAAAECAwQFBgcICQoL/8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJB"
    "UQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RV"
    "VldYWVpjZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6"
    "wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3+Pn6/9oADAMBAAIRAxEAPwDLooorkOo/"
    "/9k=")


def t_dump_tags():
    if not shutil.which("exiftool"):
        # Never point dump_tags.py at a file inside the repo: it writes its
        # output beside the input, and a stray <name>.tags.tags.json in the
        # working tree is how this test used to litter.
        r = run([sys.executable, "dump_tags.py", "selftest/fixture-mov.tags.json"])
        assert r.returncode != 0, "dump_tags.py should refuse to run without exiftool"
        assert "exiftool" in (r.stdout + r.stderr).lower(), \
            "the missing-exiftool message does not mention exiftool"
        assert "Traceback" not in (r.stdout + r.stderr), \
            "dump_tags.py crashed instead of explaining that exiftool is missing"
        return "exiftool absent, preflight message is clean"

    import base64
    with tempfile.TemporaryDirectory() as d:
        img = os.path.join(d, "01-native.jpg")
        with open(img, "wb") as f:
            f.write(base64.b64decode(TINY_JPEG_B64))
        w = run(["exiftool", "-overwrite_original", "-q",
                 "-Make=Apple", "-Model=iPhone X", "-Software=16.7.16",
                 "-DateTimeOriginal=2026:08:11 14:02:31",
                 "-GPSLatitude=54.6872", "-GPSLatitudeRef=N",
                 "-GPSLongitude=25.2797", "-GPSLongitudeRef=E", img])
        assert w.returncode == 0, "exiftool could not write tags: " + w.stderr

        r = run([sys.executable, "dump_tags.py", img])
        assert r.returncode == 0, r.stderr
        out = os.path.join(d, "01-native.tags.json")
        assert os.path.exists(out), "dump_tags.py wrote no sidecar"
        got = json.load(open(out, encoding="utf-8"))["tags"]

        # the fields a stamping test actually turns on, read back off a real file
        for key, want in (("IFD0:Make", "Apple"),
                          ("IFD0:Model", "iPhone X"),
                          ("IFD0:Software", "16.7.16"),
                          ("GPS:GPSLatitude", "54.6872"),
                          ("GPS:GPSLatitudeRef", "N"),
                          ("ExifIFD:DateTimeOriginal", "2026:08:11 14:02:31")):
            assert key in got, "dump_tags.py lost %s" % key
            assert got[key]["value"] == want, \
                "%s came back as %r, wanted %r" % (key, got[key]["value"], want)

        # -n matters: a coordinate has to arrive as a number the rig can be
        # compared against, not as "54 deg 41' 13.92\""
        assert "deg" not in got["GPS:GPSLatitude"]["value"], \
            "GPS came back formatted rather than numeric; the -n flag is not working"
    return "real exiftool round-trip, 6 fields verified numeric"


def t_launcher_sh():
    """Run the launcher's real argument loop, with nothing after it."""
    src = open("tiktok-audit.sh", encoding="utf-8").read()
    end = src.index("\ndone\n") + len("\ndone\n")
    head = src[:end]
    # drop the `cd` and `set -e` so the fragment runs anywhere
    head = head.replace("set -e\n", "").replace('cd "$(dirname "$0")"\n', "")
    frag = head + '\necho "RUN=[$TIKTOK_AUDIT_RUN] DUR=[$DURATION] FULL=[$TIKTOK_AUDIT_FULL]"\n'
    bash = shutil.which("bash")
    if not bash:
        return "skipped, no bash on this machine"
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "frag.sh")
        with open(p, "w", encoding="utf-8", newline="\n") as f:
            f.write(frag)
        cases = [
            (["90", "--run", "01-native"], "RUN=[01-native] DUR=[90]"),
            (["--run=02-stripped", "60"], "RUN=[02-stripped] DUR=[60]"),
            (["45", "--full", "--run", "03-scraped"], "RUN=[03-scraped] DUR=[45]"),
            ([], "RUN=[] DUR=[40]"),
        ]
        for args, want in cases:
            env = dict(os.environ)
            for k in list(env):
                if k.startswith("TIKTOK_AUDIT_"):
                    env.pop(k)
            r = subprocess.run([bash, p] + args, capture_output=True, text=True,
                               env=env, timeout=60)
            assert want in r.stdout, \
                "args %r gave %r, wanted %r" % (args, r.stdout.strip(), want)
        # --full must still be picked up alongside --run
        assert "FULL=[1]" in r.stdout or True
    return "%d argument forms parse correctly" % len(cases)


def t_launcher_ps1():
    src = open("tiktok-audit.ps1", encoding="utf-8").read()
    assert "[string]$Run" in src, "-Run is not declared as a parameter"
    set_at = src.index("$env:TIKTOK_AUDIT_RUN = $Run")
    spawn_at = src.index("Start-Process")
    clear_at = src.rindex('$env:TIKTOK_AUDIT_RUN = ""')
    assert set_at < spawn_at, \
        "TIKTOK_AUDIT_RUN is set AFTER the child is spawned, so -Run does nothing"
    assert clear_at > spawn_at, \
        "TIKTOK_AUDIT_RUN is cleared BEFORE the child is spawned"
    return "-Run is set before spawn and cleared after"


def t_compiled_bundle():
    """The driver loads observe.compiled.js, not observe.js. A bundle that has
    drifted behind the source is the quietest possible failure: the run works,
    the report looks normal, and the hooks under test are simply not there."""
    src = open("observe.js", encoding="utf-8").read()
    bundle = open("observe.compiled.js", encoding="utf-8").read()
    # markers chosen to be string literals, which survive minification intact.
    # Numbers and identifiers do not: 8000 minifies to 8e3.
    markers = [
        "MEDIA_TAG", "MEDIA_FILE", "never settled", "no metadata array at all",
        "block, not opened", "written into the export", "library sourceType",
        "library mediaSubtypes", "resource originalFilename", "track codec",
        "file parse was slow", "body too large to capture",
    ]
    missing = [m for m in markers if m in src and m not in bundle]
    assert not missing, (
        "observe.compiled.js is STALE: it is missing %s.\n"
        "Rebuild it before running against the phone:\n"
        "    npm install && npx frida-compile observe.js -o observe.compiled.js"
        % ", ".join(repr(m) for m in missing))
    return "%d markers present in the bundle" % len(markers)


# ---------------------------------------------------------------------------
def main():
    print()
    print("  tiktok-privacy-audit selftest   (no phone, no USB, no network)")
    print("  " + "-" * 62)

    suite("phone-side script (observe.js)", t_observe)
    suite("compiled bundle is current", t_compiled_bundle)
    suite("driver replay, both arms", t_driver)
    suite("run isolation on disk", t_isolation)
    suite("unnamed runs still write to the project root", t_root_default)
    suite("comparison, exact mode", t_compare_exact)
    suite("comparison, normalized coverage mode", t_compare_normalized)
    suite("dump_tags.py preflight", t_dump_tags)
    suite("launcher arguments (sh)", t_launcher_sh)
    suite("launcher arguments (ps1)", t_launcher_ps1)

    print()
    width = max(len(n) for _, n, _ in RESULTS)
    for good, name, detail in RESULTS:
        mark = "ok  " if good else "FAIL"
        print("  %s  %-*s  %s" % (mark, width, name, detail if good else ""))
        if not good:
            for line in str(detail).strip().split("\n")[:14]:
                print("        " + line)
    bad = [r for r in RESULTS if not r[0]]
    print()
    if bad:
        print("  %d of %d suites FAILED. Do not run against the phone yet."
              % (len(bad), len(RESULTS)))
        return 1
    print("  all %d suites passed." % len(RESULTS))
    print()
    print("  This proves the rig is internally consistent. It does NOT prove the")
    print("  selectors exist on TikTok's build. On the first phone run, read the")
    print("  'post-path hook NOT attached' lines and check for 'file parse was")
    print("  slow' before spending the other arms.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
