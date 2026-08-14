#!/usr/bin/env python3
"""Mark TikTok re-saves and leftover test clutter as Recently Deleted."""
import shutil
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

SRC = Path(__file__).resolve().parent / "photos-db"
WORK = Path(__file__).resolve().parent / "photos-db-edit"
TRASH = {
    "IMG_0001.PNG",
    "IMG_0002.MP4",
    "IMG_0003.MOV",
    "IMG_0004.MOV",
    "IMG_0007.JPG",
    "IMG_0013.MOV",
    "IMG_0014.MOV",
    "IMG_0015.MOV",
    "IMG_0016.MOV",
    "IMG_0017.MOV",
    "IMG_0018.MOV",
    "IMG_0019.MOV",
}
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
    shutil.copy2(SRC / name, WORK / name)

con = sqlite3.connect(str(WORK / "Photos.sqlite"))
con.row_factory = sqlite3.Row


def _noop(*_args):
    return None


# Core Data ships these; stock sqlite3 does not. Face-count triggers call them
# on ZTRASHEDSTATE changes. Videos have no faces, so a no-op is fine.
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

qmarks = ",".join("?" * len(TRASH))
before = cur.execute(
    "SELECT Z_PK, ZFILENAME, ZTRASHEDSTATE FROM ZASSET WHERE ZFILENAME IN (%s)"
    % qmarks,
    tuple(TRASH),
).fetchall()
print("matching rows:", len(before))
for r in before:
    print(" ", dict(r))

cur.execute(
    "UPDATE ZASSET SET ZTRASHEDSTATE = 1, ZTRASHEDDATE = ? "
    "WHERE ZFILENAME IN (%s)" % qmarks,
    (apple_now, *TRASH),
)
print("updated", cur.rowcount)

keep_rows = cur.execute(
    "SELECT ZFILENAME, ZTRASHEDSTATE FROM ZASSET WHERE ZFILENAME IN (%s)"
    % ",".join("?" * len(KEEP)),
    tuple(KEEP),
).fetchall()
print("keepers still active:")
for r in keep_rows:
    print(" ", dict(r))

con.commit()
cur.execute("PRAGMA wal_checkpoint(TRUNCATE)")
print("checkpoint", cur.fetchall())
con.close()

# after checkpoint, wal should be empty; keep a clean trio for push
wal = WORK / "Photos.sqlite-wal"
shm = WORK / "Photos.sqlite-shm"
print("after sizes", (WORK / "Photos.sqlite").stat().st_size, wal.stat().st_size, shm.stat().st_size)
