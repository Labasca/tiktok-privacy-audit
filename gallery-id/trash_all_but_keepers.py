#!/usr/bin/env python3
"""Trash/hide every Photos asset except the seven test clips."""
import shutil
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

SRC = Path(__file__).resolve().parent / "photos-db"
WORK = Path(__file__).resolve().parent / "photos-db-edit"
KEEP = {
    "IMG_0005.MOV",
    "IMG_0006.MOV",
    "IMG_0008.MOV",
    "IMG_0009.MOV",
    "IMG_0010.MOV",
    "IMG_0011.MOV",
    "IMG_0012.MOV",
}

if WORK.exists():
    shutil.rmtree(WORK)
WORK.mkdir()
for name in ("Photos.sqlite", "Photos.sqlite-wal", "Photos.sqlite-shm"):
    src = SRC / name
    if src.is_file():
        shutil.copy2(src, WORK / name)

con = sqlite3.connect(str(WORK / "Photos.sqlite"))
con.row_factory = sqlite3.Row


def _noop(*_args):
    return None


for name, n in (
    ("NSCoreDataTriggerUpdateAffectedObjectValue", 5),
    ("NSCoreDataDATriggerInsertUpdatedAffectedObjectValue", 5),
    ("NSCoreDataDATriggerUpdatedAffectedObjectValue", 5),
):
    con.create_function(name, n, _noop)

cur = con.cursor()
apple_now = (
    datetime.now(timezone.utc) - datetime(2001, 1, 1, tzinfo=timezone.utc)
).total_seconds()

# what cloud flags does the already-trashed asset use?
print("sample already-trashed cloud flags:")
for r in cur.execute(
    "SELECT ZFILENAME, ZTRASHEDSTATE, ZHIDDEN, ZCLOUDDELETESTATE, "
    "ZCLOUDLOCALSTATE, ZCLOUDISDELETABLE FROM ZASSET WHERE ZTRASHEDSTATE=1"
):
    print(" ", dict(r))

all_rows = cur.execute(
    "SELECT Z_PK, ZFILENAME, ZDIRECTORY, ZTRASHEDSTATE, ZHIDDEN "
    "FROM ZASSET"
).fetchall()
drop = [r for r in all_rows if r["ZFILENAME"] not in KEEP]
keep_rows = [r for r in all_rows if r["ZFILENAME"] in KEEP]
print("drop", len(drop), "keep", len(keep_rows))

pks = [r["Z_PK"] for r in drop]
if pks:
    q = ",".join("?" * len(pks))
    cur.execute(
        "UPDATE ZASSET SET ZTRASHEDSTATE=1, ZTRASHEDDATE=?, ZHIDDEN=1, "
        "ZCLOUDDELETESTATE=1 WHERE Z_PK IN (%s)" % q,
        (apple_now, *pks),
    )
    print("updated drop", cur.rowcount)

if keep_rows:
    q = ",".join("?" * len(keep_rows))
    cur.execute(
        "UPDATE ZASSET SET ZTRASHEDSTATE=0, ZTRASHEDDATE=NULL, ZHIDDEN=0 "
        "WHERE Z_PK IN (%s)" % q,
        [r["Z_PK"] for r in keep_rows],
    )
    print("updated keep", cur.rowcount)

print("after:")
for r in cur.execute(
    "SELECT ZFILENAME, ZTRASHEDSTATE, ZHIDDEN, ZCLOUDDELETESTATE "
    "FROM ZASSET ORDER BY ZTRASHEDSTATE, ZFILENAME"
):
    mark = "KEEP" if r["ZFILENAME"] in KEEP else "drop"
    print(" ", mark, dict(r))

paths = []
for r in drop:
    d = r["ZDIRECTORY"] or ""
    f = r["ZFILENAME"] or ""
    if d and f:
        paths.append("/var/mobile/Media/%s/%s" % (d, f))

(WORK / "delete_paths.txt").write_text("\n".join(paths) + "\n", encoding="utf-8")
print("files to delete", len(paths))

con.commit()
cur.execute("PRAGMA wal_checkpoint(TRUNCATE)")
print("checkpoint", list(cur.fetchall()))
con.close()
print("db size", (WORK / "Photos.sqlite").stat().st_size)
