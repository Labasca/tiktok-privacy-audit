#!/usr/bin/env python3
import plistlib
import sqlite3
from pathlib import Path
from pprint import pp

here = Path(__file__).resolve().parent / "accounts"
for name in ("mobileCPL.plist", "cloudphotos-1.0.plist"):
    print("====", name)
    try:
        pp(plistlib.loads((here / name).read_bytes()))
    except Exception as e:
        print(e)

db = here / "Accounts3.sqlite"
con = sqlite3.connect("file:%s?mode=ro" % db.as_posix(), uri=True)
con.row_factory = sqlite3.Row
print("==== tables")
for (t,) in con.execute("SELECT name FROM sqlite_master WHERE type='table'"):
    print(" ", t)
    cols = [r[1] for r in con.execute("PRAGMA table_info(%s)" % t)]
    if any("PHOTO" in c.upper() or "DATA" in c.upper() or "TYPE" in c.upper() or "IDENT" in c.upper() or "DESC" in c.upper() for c in cols):
        print("   cols", cols)
