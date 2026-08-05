#!/usr/bin/env python3
"""
Pull TikTok's own privacy declarations off the phone. READ-ONLY.

Attaches to the already-running TikTok process and reads static files out of its
app bundle: every PrivacyInfo.xcprivacy (the app's own machine-readable statement
of which required-reason APIs, tracking domains, and data types it uses), plus the
root Info.plist (for LSApplicationQueriesSchemes, the declared app-probe list).

This is the safest possible Frida op: a cold directory walk + a few small file
reads via libc (opendir/readdir/fopen/fread). No Interceptor, no hooks on hot
functions, nothing that can peg frida-server or wedge USB. Attach (not spawn) so
we never touch app launch.

Usage:  .venv\\Scripts\\python.exe pull_manifests.py
Output: manifests/  (raw files, gitignored)  +  console summary
"""
import base64
import os
import plistlib
import sys
import time

import frida

TARGET = "TikTok"
BUNDLE_ID = "com.zhiliaoapp.musically"
OUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "manifests")

JS = r"""
'use strict';

function gexp(name) {
  // Frida 17 dropped the static Module.findExportByName(null, ...) in favor of
  // getGlobalExportByName; support both so this runs on either.
  if (typeof Module.getGlobalExportByName === 'function') return Module.getGlobalExportByName(name);
  return Module.findExportByName(null, name);
}

var opendir  = new NativeFunction(gexp('opendir'),  'pointer', ['pointer']);
var readdir  = new NativeFunction(gexp('readdir'),  'pointer', ['pointer']);
var closedir = new NativeFunction(gexp('closedir'), 'int',     ['pointer']);
var fopen    = new NativeFunction(gexp('fopen'),    'pointer', ['pointer', 'pointer']);
var fseek    = new NativeFunction(gexp('fseek'),    'int',     ['pointer', 'long', 'int']);
var ftell    = new NativeFunction(gexp('ftell'),    'long',    ['pointer']);
var fread    = new NativeFunction(gexp('fread'),    'ulong',   ['pointer', 'ulong', 'ulong', 'pointer']);
var fclose   = new NativeFunction(gexp('fclose'),   'int',     ['pointer']);

var SEEK_SET = 0, SEEK_END = 2;
var DT_DIR = 4;

function readFileBytes(path) {
  var f = fopen(Memory.allocUtf8String(path), Memory.allocUtf8String('rb'));
  if (f.isNull()) return null;
  fseek(f, 0, SEEK_END);
  var size = ftell(f).toNumber();
  fseek(f, 0, SEEK_SET);
  if (size <= 0 || size > 8 * 1024 * 1024) { fclose(f); return null; }
  var buf = Memory.alloc(size);
  var n = fread(buf, 1, size, f).toNumber();
  fclose(f);
  return buf.readByteArray(n);
}

function findBundleRoot() {
  var mods = Process.enumerateModules();
  var best = null;
  for (var i = 0; i < mods.length; i++) {
    var p = mods[i].path || '';
    var idx = p.indexOf('.app/');
    if (idx !== -1) {
      var root = p.substring(0, idx + 4); // include ".app"
      if (best === null || root.length < best.length) best = root;
    }
  }
  return best;
}

var root = findBundleRoot();
if (!root) {
  send({ type: 'done', error: 'could not locate .app bundle root', root: null, visited: 0, found: 0 });
} else {
  send({ type: 'log', msg: 'bundle root: ' + root });

  var MAX_VISITED = 120000, MAX_DEPTH = 12;
  var visited = 0, found = 0, capped = false;
  var stack = [{ dir: root, depth: 0 }];

  function wanted(name, full) {
    if (name.length > 10 && name.slice(-10) === '.xcprivacy') return true;
    if (name === 'Info.plist' && full === root + '/Info.plist') return true; // root only
    return false;
  }

  while (stack.length) {
    var cur = stack.pop();
    var dp = opendir(Memory.allocUtf8String(cur.dir));
    if (dp.isNull()) continue;
    var ent;
    while (!(ent = readdir(dp)).isNull()) {
      if (visited++ > MAX_VISITED) { capped = true; break; }
      var namlen = ent.add(18).readU16();
      var dtype  = ent.add(20).readU8();
      var name   = ent.add(21).readUtf8String(namlen);
      if (name === '.' || name === '..') continue;
      var full = cur.dir + '/' + name;
      if (dtype === DT_DIR) {
        if (cur.depth < MAX_DEPTH) stack.push({ dir: full, depth: cur.depth + 1 });
      } else if (wanted(name, full)) {
        var bytes = readFileBytes(full);
        if (bytes) {
          found++;
          send({ type: 'file', path: full, rel: full.substring(root.length + 1) }, bytes);
        }
      }
    }
    closedir(dp);
    if (capped) break;
  }
  send({ type: 'done', error: null, root: root, visited: visited, found: found, capped: capped });
}
"""


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    dev = frida.get_usb_device(timeout=5)

    # Prefer attaching to a live TikTok. If it is not running, spawn it SUSPENDED
    # and never resume: the libc file reads work on the paused process, so TikTok's
    # own code never executes. This sidesteps the launch-time crashes entirely.
    spawned_pid = None
    try:
        session = dev.attach(TARGET)
        print("  attached to running TikTok")
    except (frida.ProcessNotFoundError, frida.NotSupportedError):
        print("  TikTok not running, spawning it suspended (will not resume)")
        spawned_pid = dev.spawn([BUNDLE_ID])
        session = dev.attach(spawned_pid)

    saved = []
    state = {"done": False, "info": None}

    def on_message(message, data):
        if message["type"] == "error":
            print("  script error:", message.get("description"))
            print("   ", message.get("stack"))
            state["done"] = True
            return
        p = message.get("payload", {})
        kind = p.get("type")
        if kind == "log":
            print("  ·", p.get("msg"))
        elif kind == "file":
            rel = p["rel"]
            flat = rel.replace("/", "__").replace("\\", "__")
            raw_path = os.path.join(OUT_DIR, flat)
            with open(raw_path, "wb") as fh:
                fh.write(data)
            saved.append((rel, raw_path, len(data)))
            print(f"  + {rel}  ({len(data)} bytes)")
        elif kind == "done":
            state["info"] = p
            state["done"] = True

    script = session.create_script(JS)
    script.on("message", on_message)
    script.load()

    t0 = time.time()
    while not state["done"] and time.time() - t0 < 90:
        time.sleep(0.1)

    try:
        script.unload()
    except Exception:
        pass
    try:
        session.detach()
    except Exception:
        pass
    # kill the suspended spawn without ever resuming it
    if spawned_pid is not None:
        try:
            dev.kill(spawned_pid)
            print("  killed spawned TikTok (never resumed)")
        except Exception:
            pass

    info = state["info"] or {}
    print()
    print(f"  walked {info.get('visited', '?')} entries, pulled {len(saved)} file(s)"
          + ("  [WALK CAPPED]" if info.get("capped") else ""))
    if info.get("error"):
        print("  error:", info["error"])

    # parse each pulled file so we can eyeball it immediately
    print()
    for rel, path, size in saved:
        print("=" * 78)
        print(rel)
        print("-" * 78)
        try:
            with open(path, "rb") as fh:
                obj = plistlib.load(fh)
            import json
            print(json.dumps(obj, indent=2, default=str)[:6000])
        except Exception as e:
            print("  (not a plist / parse failed:", e, ")")
    print("=" * 78)
    print(f"  raw files in: {OUT_DIR}")


if __name__ == "__main__":
    main()
