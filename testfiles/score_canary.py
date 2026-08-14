#!/usr/bin/env python3
"""Did TikTok read the canary strings? File dump vs a rig tags.json."""
from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def load(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def main() -> None:
    if len(sys.argv) < 3:
        raise SystemExit(
            "usage: score_canary.py testfiles/unique-6-canary.json "
            "runs/NAME/tags.json"
        )
    cans = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    blob = load(Path(sys.argv[2]))
    needles = [
        ("make", cans["make"]),
        ("model", cans["model"]),
        ("software", cans["software"]),
        ("title", cans["title"]),
        ("comment", cans["comment"]),
        ("created", "2025-01-02T03:04:05"),
        ("gps 11.1111", "11.1111"),
        ("gps 22.2222", "22.2222"),
        ("Apple (must be absent)", "Apple"),
        ("iPhone X (must be absent)", "iPhone X"),
        ("Vilnius GPS (must be absent)", "54.6389"),
    ]
    print("needle                          hit")
    print("-" * 40)
    for label, s in needles:
        print("%-30s %s" % (label, "YES" if s in blob else "no"))


if __name__ == "__main__":
    main()
