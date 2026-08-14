#!/usr/bin/env python3
"""Turn off iCloud Photos dataclass on this device only. Does not delete iCloud."""
import shutil
import sqlite3
from pathlib import Path

SRC = Path(__file__).resolve().parent / "accounts"
WORK = Path(__file__).resolve().parent / "accounts-edit"
PHOTOS_DC = 6
CLOUDPHOTOS_DC = 39
ICLOUD_ACCOUNT = 8

if WORK.exists():
    shutil.rmtree(WORK)
WORK.mkdir()
for name in ("Accounts3.sqlite", "Accounts3.sqlite-wal", "Accounts3.sqlite-shm"):
    shutil.copy2(SRC / name, WORK / name)

con = sqlite3.connect(str(WORK / "Accounts3.sqlite"))


def _noop(*_a):
    return None


for name, n in (
    ("NSCoreDataTriggerUpdateAffectedObjectValue", 5),
    ("NSCoreDataDATriggerInsertUpdatedAffectedObjectValue", 5),
    ("NSCoreDataDATriggerUpdatedAffectedObjectValue", 5),
):
    try:
        con.create_function(name, n, _noop)
    except Exception:
        pass

cur = con.cursor()
print(
    "enabled before",
    cur.execute(
        "SELECT * FROM Z_2ENABLEDDATACLASSES WHERE Z_2ENABLEDACCOUNTS=?",
        (ICLOUD_ACCOUNT,),
    ).fetchall(),
)
n = cur.execute(
    "DELETE FROM Z_2ENABLEDDATACLASSES WHERE Z_2ENABLEDACCOUNTS=? "
    "AND Z_7ENABLEDDATACLASSES IN (?,?)",
    (ICLOUD_ACCOUNT, PHOTOS_DC, CLOUDPHOTOS_DC),
).rowcount
print("removed enabled rows", n)
print(
    "enabled after",
    cur.execute(
        "SELECT * FROM Z_2ENABLEDDATACLASSES WHERE Z_2ENABLEDACCOUNTS=?",
        (ICLOUD_ACCOUNT,),
    ).fetchall(),
)
con.commit()
cur.execute("PRAGMA wal_checkpoint(TRUNCATE)")
print("checkpoint", list(cur.fetchall()))
con.close()
print("db", (WORK / "Accounts3.sqlite").stat().st_size)
