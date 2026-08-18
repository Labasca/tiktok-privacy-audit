#!/usr/bin/env python3
"""Read a sweep run and say where the picker stopped.

    python score_sweep.py runs/roll-sweep            # the 300-still question
    python score_sweep.py runs/video-sweep-A --video # the two-clip question

For the stills run it recovers the index of every numbered file whose value
appeared, on both channels independently, and reports whether the set is a
prefix of the roll or the whole of it. A prefix means the sweep is bounded by
what the grid rendered and the bound is readable; the whole roll means it walks
the library.

For the video run it just asks whether the other clip's canary showed up.
"""

import argparse
import json
import os
import re
import sys


def vals(tags, key):
    m = tags.get(key)
    if not m:
        return []
    v = m["value"]
    return [str(x) for x in (v if isinstance(v, list) else [v])]


def load(run):
    p = os.path.join(run, "tags.json")
    if not os.path.isfile(p):
        sys.exit("no tags.json in %s" % run)
    with open(p, encoding="utf-8") as fh:
        return json.load(fh)


def stills(tags, total):
    by_make = {int(m.group(1)) for v in vals(tags, "image {TIFF} Make")
               for m in [re.fullmatch(r"CANARY-(\d{4})", v)] if m}
    by_lon = set()
    for v in vals(tags, "image {GPS} Longitude"):
        try:
            f = float(v)
        except ValueError:
            continue
        i = round((f - 100.0) * 1000)
        if 0 <= i < total and abs((100.0 + i / 1000.0) - f) < 5e-4:
            by_lon.add(i)
    return by_make, by_lon


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("run")
    ap.add_argument("--video", action="store_true")
    ap.add_argument("--total", type=int, default=300)
    args = ap.parse_args()
    d = load(args.run)
    tags = d["tags"]

    if args.video:
        found = {}
        for k in tags:
            for v in vals(tags, k):
                m = re.search(r"CANARYMK-SWEEP([AB])", str(v))
                if m:
                    found.setdefault(m.group(1), []).append(k)
        print("run %s  (%s tags)" % (args.run, d.get("tag_count")))
        for arm in ("A", "B"):
            where = found.get(arm)
            print("  clip %s  %s" % (arm, "READ  via %s" % where[0] if where else "not seen"))
        if len(found) > 1:
            print("\nBoth clips appear in one session: video sweeps the roll the way")
            print("stills do, so roll hygiene is not a stills-only concern.")
        elif found:
            print("\nOnly the posted clip appears. On this evidence video does not")
            print("sweep -- run the mirror session before relying on it.")
        else:
            print("\nNeither canary appeared. The post probably fell outside the")
            print("window; nothing can be concluded from this run.")
        return 0

    by_make, by_lon = stills(tags, args.total)
    both = by_make & by_lon
    print("run %s  (%s tags)" % (args.run, d.get("tag_count")))
    print("  indices recovered from Make          %d" % len(by_make))
    print("  indices recovered from GPS longitude %d" % len(by_lon))
    if by_make != by_lon:
        only = (by_make ^ by_lon)
        print("  ! the two channels disagree on %d index/indices: %s"
              % (len(only), sorted(only)[:8]))
        print("    treat the smaller set as the finding, not the larger")
    if not both:
        print("\nNo numbered file was read at all. Either the post fell outside")
        print("the window or the import did not land; nothing concluded.")
        return 1

    lo, hi = min(both), max(both)
    n = len(both)
    print("\n  read %d of %d, lowest index %d, highest %d" % (n, args.total, lo, hi))
    contiguous = both == set(range(lo, hi + 1))
    if n == args.total:
        print("\nEvery file in the roll was read. The sweep walks the library, so")
        print("roll size is exposure and retire-once-posted is load bearing.")
    elif contiguous and lo == 0:
        print("\nThe first %d and nothing after. The sweep is bounded by what the" % n)
        print("grid rendered, and %d is the bound -- only the top of the roll has" % n)
        print("to be coherent, which makes a rolling window safe.")
    elif contiguous:
        print("\nA contiguous block %d..%d rather than a prefix. Something scrolled," % (lo, hi))
        print("so the bound is real but this run does not locate its start.")
    else:
        print("\n%d files, not contiguous. Neither a prefix nor the whole roll," % n)
        print("so the selection is driven by something this test did not control.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
