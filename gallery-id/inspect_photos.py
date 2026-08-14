#!/usr/bin/env python3
import sqlite3
from pathlib import Path

db = Path(__file__).resolve().parent / "photos-db" / "Photos.sqlite"
con = sqlite3.connect("file:%s?mode=ro" % db.as_posix(), uri=True)
con.row_factory = sqlite3.Row
cur = con.cursor()

print("tables:")
for (t,) in cur.execute(
    "SELECT name FROM sqlite_master WHERE type='table' ORDER BY 1"
):
    if any(s in t.upper() for s in ("ASSET", "FILE", "TRASH", "ADDIT")):
        print(" ", t)

cols = [r[1] for r in cur.execute("PRAGMA table_info(ZASSET)")]
print("\nZASSET interesting columns:")
for c in cols:
    if any(
        s in c.upper()
        for s in (
            "FILE",
            "DIR",
            "TRASH",
            "HIDDEN",
            "CLOUD",
            "DATE",
            "WIDTH",
            "HEIGHT",
            "KIND",
            "UNIFORM",
            "ORIGINAL",
            "DIRECTORY",
        )
    ):
        print(" ", c)

print("\nZADDITIONALASSETATTRIBUTES interesting:")
acols = [r[1] for r in cur.execute("PRAGMA table_info(ZADDITIONALASSETATTRIBUTES)")]
for c in acols:
    if any(s in c.upper() for s in ("FILE", "ORIG", "DIR", "TITLE", "NAME")):
        print(" ", c)
