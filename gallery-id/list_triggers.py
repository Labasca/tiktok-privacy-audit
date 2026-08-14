#!/usr/bin/env python3
import sqlite3
from pathlib import Path

db = Path(__file__).resolve().parent / "photos-db" / "Photos.sqlite"
con = sqlite3.connect("file:%s?mode=ro" % db.as_posix(), uri=True)
cur = con.cursor()
rows = cur.execute(
    "SELECT name, tbl_name, sql FROM sqlite_master WHERE type='trigger' ORDER BY 1"
).fetchall()
print("triggers", len(rows))
for name, tbl, sql in rows:
    interesting = "ZASSET" in (tbl or "") or (
        sql and "ZASSET" in sql and "TRASH" in (sql or "").upper()
    )
    if tbl == "ZASSET" or interesting:
        print("=" * 60)
        print(name, "on", tbl)
        print(sql)
