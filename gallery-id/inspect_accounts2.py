#!/usr/bin/env python3
import sqlite3
from pathlib import Path

db = Path(__file__).resolve().parent / "accounts" / "Accounts3.sqlite"
con = sqlite3.connect("file:%s?mode=ro" % db.as_posix(), uri=True)
con.row_factory = sqlite3.Row

print("==== ZDATACLASS")
cols = [r[1] for r in con.execute("PRAGMA table_info(ZDATACLASS)")]
print("cols", cols)
for r in con.execute("SELECT * FROM ZDATACLASS"):
    print(dict(r))

print("\n==== ZACCOUNT")
for r in con.execute(
    "SELECT Z_PK, ZACTIVE, ZUSERNAME, ZACCOUNTDESCRIPTION, ZIDENTIFIER, ZOWNINGBUNDLEID FROM ZACCOUNT"
):
    print(dict(r))

print("\n==== ZACCOUNTTYPE")
for r in con.execute(
    "SELECT Z_PK, ZIDENTIFIER, ZACCOUNTTYPEDESCRIPTION, ZOWNINGBUNDLEID FROM ZACCOUNTTYPE"
):
    print(dict(r))

print("\n==== Z_2ENABLEDDATACLASSES")
for r in con.execute("SELECT * FROM Z_2ENABLEDDATACLASSES"):
    print(dict(r))

print("\n==== Z_2PROVISIONEDDATACLASSES")
for r in con.execute("SELECT * FROM Z_2PROVISIONEDDATACLASSES"):
    print(dict(r))
