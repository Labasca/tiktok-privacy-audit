#!/usr/bin/env python3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from dump_tags import collect

NEEDLES = (
    "make", "model", "gps", "software", "encoder", "artist", "comment",
    "location", "apple", "creationdate", "handler", "compressor",
    "duration", "filesize", "imagewidth", "imageheight",
)

for p in sorted(Path(__file__).resolve().parent.glob("IMG_*")):
    if p.suffix.lower() not in {".mov", ".mp4", ".m4v"}:
        continue
    tags = collect(str(p))
    print("=" * 72)
    print(p.name, p.stat().st_size, "bytes", "tag_count", len(tags))
    for k, v in tags.items():
        lk = k.lower()
        if any(s in lk for s in NEEDLES):
            print(f"  {k}: {v['value']}")
