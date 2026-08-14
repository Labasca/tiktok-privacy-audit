#!/usr/bin/env python3
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

db = Path(__file__).resolve().parent / "photos-db" / "Photos.sqlite"
con = sqlite3.connect("file:%s?mode=ro" % db.as_posix(), uri=True)
con.row_factory = sqlite3.Row
cur = con.cursor()

APPLE_EPOCH = datetime(2001, 1, 1, tzinfo=timezone.utc)

def apple_time(v):
    if v is None:
        return "-"
    try:
        return datetime.fromtimestamp(float(v) + APPLE_EPOCH.timestamp()).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
    except Exception:
        return str(v)

rows = cur.execute(
    """
    SELECT
      a.Z_PK,
      a.ZFILENAME,
      a.ZDIRECTORY,
      a.ZTRASHEDSTATE,
      a.ZHIDDEN,
      a.ZKIND,
      a.ZWIDTH,
      a.ZHEIGHT,
      a.ZUNIFORMTYPEIDENTIFIER,
      a.ZDATECREATED,
      aa.ZORIGINALFILENAME,
      aa.ZORIGINALFILESIZE,
      aa.ZIMPORTEDBYDISPLAYNAME,
      aa.ZTITLE
    FROM ZASSET a
    LEFT JOIN ZADDITIONALASSETATTRIBUTES aa ON aa.ZASSET = a.Z_PK
    ORDER BY a.ZFILENAME
    """
).fetchall()

print("n=", len(rows))
print(
    "%-6s %-14s %-6s %-6s %8s %6sx%-6s %-22s %-20s %s"
    % ("pk", "file", "trash", "hide", "bytes", "w", "h", "imported_by", "created", "orig")
)
for r in rows:
    print(
        "%-6s %-14s %-6s %-6s %8s %6sx%-6s %-22s %-20s %s"
        % (
            r["Z_PK"],
            r["ZFILENAME"] or "-",
            r["ZTRASHEDSTATE"],
            r["ZHIDDEN"],
            r["ZORIGINALFILESIZE"] if r["ZORIGINALFILESIZE"] is not None else "-",
            r["ZWIDTH"] or "-",
            r["ZHEIGHT"] or "-",
            (r["ZIMPORTEDBYDISPLAYNAME"] or "-")[:22],
            apple_time(r["ZDATECREATED"]),
            r["ZORIGINALFILENAME"] or "-",
        )
    )
