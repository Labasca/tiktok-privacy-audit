/*
 * observe.js  -  READ-ONLY privacy audit for TikTok on a device you own.
 *
 * PRINCIPLE: every hook here only LOGS what the app does. None of them
 * change a return value, an argument, or the app's view of the world.
 * We are watching what TikTok reads off THIS phone, nothing more.
 *
 * Explicitly NOT in this file (and not something I'll add):
 *   - faking GPS / overriding CLLocation results
 *   - lying to getifaddrs / NEVPNManager about VPN state
 *   - spoofing identifierForVendor / device fingerprint values
 * Those cross from "observe my data" into "deceive the app", which is
 * a different thing. This file stays on the observe side.
 *
 * OUTPUT: this script emits structured events, not formatted text.
 * Every event is { cat, key, value } and the driver (run_observe.py) owns
 * all deduplication, naming and presentation. Keep it that way: the hooks
 * are the sensor, the driver is the report.
 *
 * Run:  frida -U -f com.zhiliaoapp.musically -l observe.compiled.js --no-pause
 */

'use strict';

// Frida 17 removed the ObjC bridge as a global, it is now a bundled module.
import ObjC from 'frida-objc-bridge';

/* ---------------------------------------------------------------------------
 * BOUNDED, BATCHED REPORTING. Read this before adding a hook.
 *
 * Every hook funnels through emit(), and emit() NEVER sends. It counts in
 * memory, and a timer ships only what changed, a few times a second.
 *
 * The reason is not tidiness. Calling send() from a hot function such as open()
 * or -[UIScreen scale] floods the USB channel with tens of thousands of
 * messages a second. The driver on the other end allocates for every one of
 * them, the queue grows faster than it drains, and the HOST machine runs out of
 * memory and locks up. Aggregating here makes the message rate a constant no
 * matter how hot the hooked function is.
 *
 * Three hard limits, all fail-safe: past them we stop recording rather than
 * grow without bound, and the report says it was truncated.
 * ------------------------------------------------------------------------- */
var FLUSH_MS = 400;
// Distinct cat+key+value combinations. Raised for the tag inventory: a full
// dump of eight media files is several hundred rows on its own, and the old
// ceiling would have been spent by exactly the data the post path exists to
// collect. These are strings in a Map, so the cost of the headroom is nothing.
var MAX_DISTINCT = 8000;
var MAX_EVENTS = 2000000;     // total observed calls before we stop counting

/* ---------------------------------------------------------------------------
 * WHY NOTHING HOT ATTACHES AT LOAD ANY MORE.
 *
 * The failure this file kept chasing was never the USB link. iOS crash reports
 * name it exactly: SpringBoard's launch watchdog kills TikTok for missing the
 * 10.00 second wall-clock allowance it gets to bring a scene up, at 5-26% CPU.
 * The app is not busy, it is BLOCKED. Every intercepted call is a native-to-JS
 * transition onto one serialized script thread, so the app's threads queue
 * behind each other. That cost is invisible in CPU time and fatal in wall-clock
 * time, which is the only metric iOS enforces.
 *
 * So the rule is now about WHEN, not just how much:
 *
 *   1. Hooks that fire at app-logic rate (ObjC selectors, keychain,
 *      sysctlbyname, getenv) attach at load and stay. They have never been
 *      implicated in a termination.
 *   2. Hooks that fire at packet or syscall rate are REGISTERED at load and
 *      attach later, when the driver arms their group, one group at a time,
 *      for well under a second, long after the scene is up.
 *   3. Both cutoffs, sample count and wall clock, are checked INLINE on the
 *      trap itself. The old wall-clock time-box ran on the flush timer, which
 *      is starved by exactly the call storm it exists to stop.
 *
 * There is no digit-flipping of the compiled bundle any more. The driver picks
 * groups by calling rpc.exports.arm(), so the byte offsets of the compiled
 * package are no longer load bearing.
 * ------------------------------------------------------------------------- */

// How long the always-on probes may stay attached, measured from the moment the
// app is actually resumed rather than from script load. Everything else attaches
// later, on the driver's schedule, and carries its own much shorter window.
var BASE_WINDOW_MS = 4000;

// Fallback window for a group the driver arms without naming one.
var GROUP_WINDOW_MS = 800;

var SEP = String.fromCharCode(1);   // never occurs inside a key or a value
var _tally = new Map();       // key -> [count, firstMs, lastSentCount]
var _t0 = Date.now();
var _events = 0, _dropped = 0, _capped = false;

function emit(cat, key, value) {
  if (_events >= MAX_EVENTS) { _capped = true; return; }
  _events++;
  var k = cat + SEP + (key == null ? '' : key) +
          SEP + (value == null ? '' : value);
  var row = _tally.get(k);
  if (row === undefined) {
    if (_tally.size >= MAX_DISTINCT) { _dropped++; _capped = true; return; }
    _tally.set(k, [1, Date.now() - _t0, 0]);
  } else {
    row[0]++;
  }
}

/* ---------------------------------------------------------------------------
 * PROBES. A probe is a hook that is allowed to be expensive, but only briefly
 * and only when the driver says so.
 *
 * probe(group, target, limit, label, handlers) REGISTERS. It does not attach.
 * Registration is free: it resolves a symbol and pushes a record. Attaching is
 * what costs, so attaching is what gets scheduled.
 *
 * The 'base' group is the exception: it attaches at load, because those hooks
 * are the ones that have always been safe and they cover the launch sequence,
 * which is where most identifier reads happen. Their limits are small.
 *
 * Every attached probe dies on whichever comes first:
 *   a. its sample count, checked on every trap
 *   b. its wall-clock deadline, checked on every 32nd trap
 *   c. the driver disarming its group
 *   d. the flush-timer sweep, when the timer is able to run at all
 *
 * (a) and (b) are inline, on the trap itself, so they still fire when the JS
 * thread is saturated. That is the whole point: the previous time-box lived in
 * the flush timer and was starved by precisely the storm it was meant to end.
 * ------------------------------------------------------------------------- */
var GROUP_BASE = 'base';
var _probes = [];         // every registered probe, attached or not
var _live = [];           // probes currently attached
var _detachQueue = [];    // listeners that spent their sample, swept on flush
var _startedAt = 0;       // set by rpc start(), the moment the app is resumed

/* ---------------------------------------------------------------------------
 * THE POST-PATH TAG INVENTORY.
 *
 * The rest of this file answers "what did TikTok read". The three pieces below
 * answer the harder question the metadata work needs: "what was actually IN the
 * file, field by field, and what came out the other side".
 *
 * _selfRead is the reason the other two are safe. Introspecting a media file
 * means opening it with the same frameworks TikTok uses, which re-enters the
 * very hooks doing the observing. Without a guard, our own reads are logged as
 * the app's and every count in the report is inflated by our own curiosity.
 * Every media hook checks it first.
 *
 * _pendingFiles is a work queue, not a hook. Parsing a file is far too slow to
 * do on the app's thread inside an interceptor, so hooks only RECORD the paths
 * they see and the flush timer drains one per tick on the script thread, where
 * blocking costs the app nothing.
 *
 * _blobs carries request bodies out whole. emit() cannot: it is a counter keyed
 * by string, so a 40 KB JSON body would either blow the distinct-key ceiling or
 * arrive truncated. Bodies ride beside the batch instead and the driver writes
 * them to disk.
 * ------------------------------------------------------------------------- */
var _selfRead = false;
var _pendingFiles = [];   // [path, container-label], drained by flush()
var _seenFiles = {};      // path -> 1, so a file is only ever parsed once
var _fileBudget = 8;      // total files this run will parse, hard stop
var _blobs = [];          // [{n: name, b: base64}], shipped and cleared on flush
var _blobBytes = 0;
var MAX_BLOB = 262144;        // per body
var MAX_BLOB_TOTAL = 4194304; // per run

function queueFile(path, label) {
  if (!path || _fileBudget <= 0) return;
  if (_seenFiles[path]) return;
  _seenFiles[path] = 1;
  _fileBudget--;
  _pendingFiles.push([path, label, 0]);
}

// Assigned once the ObjC bridge is up. flush() cannot reach into that scope, so
// the drain worker registers itself here instead.
var _drainFiles = null;

// A request can legitimately reach reportRequest down two different paths: the
// task constructor and -resume on the task it produced. Deduping the hook
// addresses fixes the triple-attach, but not that, so the same bytes can still
// arrive twice. Storing them twice wastes a budget that exists to make room for
// the one body that matters, the publish call.
//
// The fingerprint samples rather than hashes. A quarter-megabyte body would
// otherwise be walked end to end on the app's own thread, and length plus both
// ends is already far more discriminating than anything two distinct request
// bodies to the same endpoint would collide on.
var _blobSeen = {};

function captureBlob(name, b64, nbytes) {
  var fp = nbytes + ':' + b64.length + ':' + b64.slice(0, 48) + ':' + b64.slice(-48);
  if (_blobSeen[fp]) {
    // The repeat is still a fact worth keeping, just not worth another copy.
    _blobSeen[fp]++;
    emit('BODY', name, 'identical body seen again, not stored twice');
    return false;
  }
  if (_blobBytes + nbytes > MAX_BLOB_TOTAL) return false;
  _blobSeen[fp] = 1;
  _blobBytes += nbytes;
  _blobs.push({ n: name, b: b64 });
  return true;
}

function probe(group, target, limit, label, handlers) {
  if (!target) return;
  var p = { g: group, t: target, lim: limit, lbl: label, h: handlers,
            l: null, dl: Infinity };
  _probes.push(p);
  if (group === GROUP_BASE) attachProbe(p, BASE_WINDOW_MS);
}

// Kept so the existing call sites that are genuinely always-on read unchanged.
function hotHook(target, limit, label, handlers) {
  probe(GROUP_BASE, target, limit, label, handlers);
}

function attachProbe(p, windowMs) {
  if (p.l) return;                       // already attached
  var n = 0, dead = false, self = null;
  // Base probes are registered while the process is still spawn-paused, so their
  // clock cannot start until the app is actually resumed. start() stamps it.
  p.dl = _startedAt ? (Date.now() + windowMs) : Infinity;
  p.win = windowMs;
  try {
    self = Interceptor.attach(p.t, {
      onEnter: function (args) {
        if (dead) return;                // cheapest possible: one read + return
        n++;
        // Both cutoffs inline. Date.now() is read on every 32nd call only, so
        // the common path stays a compare and an increment.
        if (n > p.lim || ((n & 31) === 0 && Date.now() > p.dl)) {
          dead = true;
          emit('CAPPED', p.lbl, n > p.lim ? String(p.lim) : (p.win + 'ms'));
          _detachQueue.push(self);
          try { self.detach(); } catch (e) {}
          return;
        }
        this._s = true;
        if (p.h.onEnter) { try { p.h.onEnter.call(this, args); } catch (e) {} }
      },
      onLeave: function (ret) {
        if (this._s && p.h.onLeave) {
          try { p.h.onLeave.call(this, ret); } catch (e) {}
        }
      }
    });
  } catch (e) { return; }
  p.l = self;
  // Read the sample count without paying for it on every trap. A probe that was
  // armed and saw zero calls is a real finding about the run (the app was idle),
  // and without this the report cannot tell that apart from "the hook is broken".
  p.count = function () { return n; };
  _live.push(p);
}

function detachProbe(p) {
  if (!p.l) return;
  try { p.l.detach(); } catch (e) {}
  p.l = null;
  try { emit('PROBE', p.g + '|' + p.lbl, 'saw ' + p.count() + ' calls'); } catch (e) {}
  var i = _live.indexOf(p);
  if (i >= 0) _live.splice(i, 1);
}

function armGroup(group, windowMs) {
  var w = windowMs || GROUP_WINDOW_MS;
  var n = 0;
  _probes.forEach(function (p) {
    if (p.g !== group || p.l) return;
    attachProbe(p, w);
    if (p.l) n++;
  });
  emit('PROBE', group, 'armed ' + n + ' hooks for ' + w + 'ms');
  return n;
}

function disarmGroup(group) {
  var n = 0;
  _live.slice().forEach(function (p) {
    if (group && p.g !== group) return;   // null group means tear everything down
    detachProbe(p);
    n++;
  });
  return n;
}

function flush() {
  // 1. sweep listeners whose inline detach was deferred by Frida's interceptor
  // transaction. Cheap and idempotent.
  while (_detachQueue.length) {
    var l = _detachQueue.pop();
    try { l.detach(); } catch (e) {}
  }
  // 2. backstop for probes that never reached their sample limit and never hit
  // the every-32nd-call check because they simply are not being called much.
  // This is the layer that only works when the timer is free to run, which is
  // fine: a probe that is not being called is not the one that saturates us.
  var now = Date.now();
  _live.slice().forEach(function (p) {
    if (now > p.dl) {
      emit('CAPPED', p.lbl, p.win + 'ms');
      detachProbe(p);
    }
  });
  // 3. parse at most ONE queued media file per tick. This runs on the script
  // thread with no app thread waiting on it, which is the only place in this
  // file where blocking for tens of milliseconds is free. One per tick keeps
  // the flush cadence itself honest.
  if (_drainFiles) { try { _drainFiles(); } catch (e) {} }

  // 4. ship the batch. Always send something, even an empty batch, so the driver
  // can tell "idle" from "the phone-side script has wedged" and abort if so.
  var batch = [];
  _tally.forEach(function (row, k) {
    if (row[0] === row[2]) return;
    var p = k.split(SEP);
    batch.push([p[0], p[1], p[2], row[0], row[1]]);
    row[2] = row[0];
  });
  var blobs = _blobs;
  _blobs = [];
  send({ b: batch, dropped: _dropped, capped: _capped, events: _events,
         live: _live.length, hb: 1, blobs: blobs });
}
setInterval(flush, FLUSH_MS);

rpc.exports = {
  flush: flush,
  // Called by the driver the instant the app is resumed. Until this lands the
  // base probes have no deadline, because a spawn-paused process burns no time.
  start: function () {
    _startedAt = Date.now();
    _t0 = _startedAt;
    _live.forEach(function (p) { p.dl = _startedAt + BASE_WINDOW_MS; });
    return _probes.length;
  },
  // Drops a boundary into the timeline so several posts in one run can still be
  // told apart. The tally is cumulative by design, so the driver diffs counts
  // either side of a mark rather than the script resetting anything.
  mark: function (label) {
    emit('MARK', String(label || 'mark'), String(Date.now() - _t0) + 'ms');
    return true;
  },
  arm: function (group, windowMs) { return armGroup(group, windowMs); },
  disarm: function (group) { return disarmGroup(group); },
  disarmall: function () { return disarmGroup(null); },
  groups: function () {
    var g = {};
    _probes.forEach(function (p) { g[p.g] = (g[p.g] || 0) + 1; });
    return g;
  }
};

/* Kept for hooks called at APP-LOGIC rate (settings reads, sysctls) rather than
 * PACKET rate. Those never approach the trap volume that requires detaching, so
 * a plain budget on the work is enough. Anything on the data path uses hotHook
 * instead. */
function budget(limit, label) {
  var n = 0, warned = false;
  return function () {
    if (++n <= limit) return true;
    if (!warned) { warned = true; emit('CAPPED', label || 'a hook', String(limit)); }
    return false;
  };
}

/* Resolve a hot C symbol. Resolving is just an address lookup and costs nothing,
 * so this no longer gates anything: the gate moved to WHEN the probe's group is
 * armed, which is the thing that actually matters. Route every hot C function
 * through this so the dangerous ones stay easy to find, and keep the safe ones
 * (sysctlbyname, uname, SecItemCopyMatching) on a plain findGlobalExportByName. */
function dangerousExport(name) {
  try { return Module.findGlobalExportByName(name); } catch (e) { return null; }
}

// The global lookup returns ONE address for a symbol, and TLS symbols are not
// unique on this phone. Measured inside TikTok: SSL_read exists twice, once in
// TikTok.app/Frameworks/boringssl.framework (its own statically shipped copy,
// which the global lookup happens to win) and once in /usr/lib/libboringssl.dylib
// (the system copy, which is what Network.framework uses). Hooking only the
// first means every byte that goes out over the nw stack is missed, and this
// run already showed endpoints opened that way. So: every copy, each labelled
// by the module it came from, so the report can say which stack carried what.
function eachExport(name) {
  const out = [];
  try {
    Process.enumerateModules().forEach(function (m) {
      try {
        const p = m.findExportByName && m.findExportByName(name);
        if (p) out.push({ addr: p, mod: m.name });
      } catch (e) {}
    });
  } catch (e) {}
  if (!out.length) {
    const p = dangerousExport(name);
    if (p) out.push({ addr: p, mod: '?' });
  }
  return out;
}

// Darwin utsname is 5 fixed-size char[256] fields back to back.
const SYS_NAMELEN = 256;

// Always read C strings NUL-terminated. Passing an explicit length makes Frida
// read (and UTF-8 validate) the whole span, which throws the moment it runs off
// the end of the string into padding or unmapped memory. That is what turns
// every sysctl name into "?".
function cstr(ptr) {
  try {
    const s = ptr.readUtf8String();
    return s === null ? null : s.replace(/\0.*$/, '');
  } catch (e) { return null; }
}

// sysctl returns raw bytes with no type tag, so length alone cannot tell a
// string from an integer: "16.7.16\0" is exactly 8 bytes and would otherwise be
// decoded as a uint64. Sniff the buffer instead, a string is printable ASCII
// with a NUL inside the returned length.
function looksLikeString(ptr, n) {
  try {
    const a = new Uint8Array(ptr.readByteArray(n));
    let i = 0;
    while (i < n && a[i] !== 0) {
      if (a[i] < 0x20 || a[i] > 0x7e) return false;
      i++;
    }
    return i > 0 && i < n;
  } catch (e) { return false; }
}

const KEYCHAIN_CLASS = {
  genp: 'generic password',
  inet: 'internet password',
  cert: 'certificate',
  keys: 'cryptographic key',
  idnt: 'identity',
};

if (!ObjC.available) {
  emit('ERROR', 'objc-runtime', 'Objective-C runtime not available');
} else {
  // --- Location: what location TikTok asks for (read-only) ---
  try {
    const CLLocationManager = ObjC.classes.CLLocationManager;
    ['startUpdatingLocation', 'requestLocation', 'requestWhenInUseAuthorization',
     'requestAlwaysAuthorization', 'startMonitoringSignificantLocationChanges'].forEach(function (sel) {
      if (CLLocationManager[sel] === undefined) return;
      Interceptor.attach(CLLocationManager[sel].implementation, {
        onEnter: function () { emit('LOCATION', sel, null); }
      });
    });
    // reading the current fix (we log the value it RECEIVES, we do not alter it)
    const locGetter = CLLocationManager['- location'];
    if (locGetter) {
      Interceptor.attach(locGetter.implementation, {
        onLeave: function (ret) {
          try {
            if (ret.isNull()) return;
            emit('LOCATION', 'location', new ObjC.Object(ret).toString());
          } catch (e) {}
        }
      });
    }
  } catch (e) { emit('ERROR', 'location-hook', String(e)); }

  // --- Device identifiers TikTok reads (read-only) ---
  try {
    const UIDevice = ObjC.classes.UIDevice;
    const idfv = UIDevice['- identifierForVendor'];
    if (idfv) {
      Interceptor.attach(idfv.implementation, {
        onLeave: function (ret) {
          try {
            if (ret.isNull()) return;
            emit('IDENTIFIER', 'identifierForVendor', new ObjC.Object(ret).toString());
          } catch (e) {}
        }
      });
    }
    ['- systemVersion', '- model', '- name', '- localizedModel'].forEach(function (sel) {
      const m = UIDevice[sel];
      if (!m) return;
      const key = sel.slice(2);
      Interceptor.attach(m.implementation, {
        onLeave: function (ret) {
          try {
            if (ret.isNull()) return;
            emit('IDENTIFIER', key, new ObjC.Object(ret).toString());
          } catch (e) {}
        }
      });
    });
  } catch (e) { emit('ERROR', 'identifier-hook', String(e)); }

  // --- Keychain lookups (read-only) ---
  // The query dictionary tells us WHICH item is being looked for, which is the
  // whole point: keychain entries outlive app deletion, so an id kept here
  // re-identifies the device after a reinstall.
  try {
    const SecItemCopyMatching = Module.findGlobalExportByName('SecItemCopyMatching');
    if (SecItemCopyMatching) {
      Interceptor.attach(SecItemCopyMatching, {
        onEnter: function (args) {
          let item = '(unnamed)';
          let kind = 'keychain item';
          try {
            // CFDictionaryRef is toll-free bridged to NSDictionary.
            const q = new ObjC.Object(args[0]);
            const cls = q.objectForKey_('class');
            const svc = q.objectForKey_('svce');
            const acct = q.objectForKey_('acct');
            if (cls && !cls.isNull()) {
              const cs = String(cls);
              kind = KEYCHAIN_CLASS[cs] || cs;
            }
            if (svc && !svc.isNull() && String(svc).length) item = String(svc);
            else if (acct && !acct.isNull() && String(acct).length) item = String(acct);
          } catch (e) {}
          emit('KEYCHAIN', item, kind);
        }
      });
    }
  } catch (e) {}

  // --- Low-level fingerprint reads: sysctl / uname (read-only) ---
  // We hook onLeave as well so we capture the VALUE the kernel handed back,
  // not just the fact that the key was asked for. sysctlbyname is normally
  // called twice per read (once with a null buffer to size it, once for real),
  // which is why raw call counts run about double the number of actual reads.
  try {
    const sysctlbyname = Module.findGlobalExportByName('sysctlbyname');
    if (sysctlbyname) {
      Interceptor.attach(sysctlbyname, {
        onEnter: function (args) {
          this.name = cstr(args[0]) || '?';
          this.oldp = args[1];
          this.oldlenp = args[2];
        },
        onLeave: function (retval) {
          // The first call of a pair passes a null buffer just to size the
          // result, so it yields no value. The second call carries the data.
          let value = null;
          try {
            if (retval.toInt32() === 0 && !this.oldp.isNull() && !this.oldlenp.isNull()) {
              // readULong hands back a Frida UInt64, which is never === a JS
              // number. Without the Number() every integer sysctl falls through
              // to the string branch and gets read as control characters.
              const n = Number(this.oldlenp.readULong());
              if (n > 0 && n < 1024) {
                if (looksLikeString(this.oldp, n)) value = cstr(this.oldp);
                else if (n === 4) value = String(this.oldp.readU32());
                else if (n === 8) value = String(this.oldp.readU64());
              }
            }
          } catch (e) {}
          emit('FINGERPRINT', this.name, value);
        }
      });
    }

    const uname = Module.findGlobalExportByName('uname');
    if (uname) {
      Interceptor.attach(uname, {
        onEnter: function (args) { this.buf = args[0]; },
        onLeave: function (retval) {
          let value = null;
          try {
            if (retval.toInt32() === 0 && !this.buf.isNull()) {
              const release = cstr(this.buf.add(SYS_NAMELEN * 2));
              const machine = cstr(this.buf.add(SYS_NAMELEN * 4));
              value = [release, machine].filter(Boolean).join(' / ') || null;
            }
          } catch (e) {}
          emit('FINGERPRINT', 'uname', value);
        }
      });
    }
  } catch (e) {}

  // --- Network interface enumeration (read-only) ---
  // Counting the calls says nothing. What matters is what the call HANDED BACK,
  // so we walk the returned list and decode every interface and address the app
  // was shown: local IPs, the carrier interface, and any VPN tunnel. This is
  // still pure observation, we only read the buffer the kernel already filled.
  const AF_INET = 2, AF_LINK = 18, AF_INET6 = 30;
  const IFF_UP = 0x1, IFF_LOOPBACK = 0x8, IFF_POINTOPOINT = 0x10;
  const seenAddrs = new Set();

  // Every caller of this used to sit inside one try that wrapped a whole walk,
  // so a single unmapped ifa_addr threw away every interface after it and said
  // nothing. The try belongs here, per address, so one bad entry costs one entry.
  function readSockaddr(sa) {
    try {
      if (!sa || sa.isNull()) return null;
      const family = sa.add(1).readU8();
      if (family === AF_INET) {
        const b = new Uint8Array(sa.add(4).readByteArray(4));
        return b.length === 4 ? b.join('.') : null;
      }
      if (family === AF_INET6) {
        const b = new Uint8Array(sa.add(8).readByteArray(16));
        if (b.length !== 16) return null;
        // The zone matters: without it every interface's fe80:: address is the
        // same string, and five tunnels collapse into one row. It arrives one
        // of two ways. sin6_scope_id is the documented field, but the routing
        // socket embeds the zone in bytes 2-3 of a link-local address instead
        // (the old KAME trick), which renders as fe80:8:: and is not an address
        // anyone has. Pull it back out and put it where it belongs.
        let scope = 0;
        try { scope = sa.add(24).readU32(); } catch (e) {}
        if (b[0] === 0xfe && (b[1] & 0xc0) === 0x80 && (b[2] || b[3])) {
          if (!scope) scope = (b[2] << 8) | b[3];
          b[2] = 0; b[3] = 0;
        }
        const parts = [];
        for (let i = 0; i < 16; i += 2) parts.push((((b[i] << 8) | b[i + 1]) >>> 0).toString(16));
        return v6Canon(parts) + (scope ? '%' + scope : '');
      }
      return null;  // AF_LINK is read by readLinkAddr, not here
    } catch (e) { return null; }
  }

  // The report diffs addresses across runs and matches them against RFC lists,
  // so they have to be spelled the one canonical way rather than eight groups.
  function v6Canon(parts) {
    let bestAt = -1, bestLen = 0, at = -1, len = 0;
    for (let i = 0; i < 8; i++) {
      if (parts[i] === '0') {
        if (at < 0) { at = i; len = 1; } else len++;
        if (len > bestLen) { bestLen = len; bestAt = at; }
      } else { at = -1; len = 0; }
    }
    if (bestLen < 2) return parts.join(':');
    const head = parts.slice(0, bestAt).join(':');
    const tail = parts.slice(bestAt + bestLen).join(':');
    return head + '::' + tail;
  }

  // AF_LINK carries no routable address, which is why it used to be dropped.
  // It carries the interface's hardware address instead, which outlives every
  // IP on this list and every network the phone joins.
  function readLinkAddr(sa) {
    try {
      if (!sa || sa.isNull() || sa.add(1).readU8() !== AF_LINK) return null;
      const nlen = sa.add(5).readU8(), alen = sa.add(6).readU8();
      if (alen < 1 || alen > 8) return null;
      const b = new Uint8Array(sa.add(8).add(nlen).readByteArray(alen));
      if (b.length !== alen) return null;
      const hex = [];
      for (let i = 0; i < b.length; i++) hex.push(('0' + b[i].toString(16)).slice(-2));
      return hex.join(':');
    } catch (e) { return null; }
  }

  function readPort(sa) {
    try {
      const p = sa.add(2).readU16();          // network byte order
      return ((p & 0xff) << 8) | ((p >> 8) & 0xff);
    } catch (e) { return 0; }
  }

  function isUnspecified(addr) {
    return addr === '0.0.0.0' || /^0(:0)*$/.test(addr);
  }

  // Stays in the base group so the launch sequence is still covered, but the
  // sample is small: every single call hands back the COMPLETE interface list,
  // so 48 of them answer the question as well as 500 did, at a tenth the cost.
  hotHook(Module.findGlobalExportByName('getifaddrs'), 48, 'interface scans', {
    onEnter: function (args) { this.listp = args[0]; },
    onLeave: function (retval) {
      emit('NETWORK', 'getifaddrs', null);
      if (retval.toInt32() !== 0 || this.listp.isNull()) return;
      try {
        // struct ifaddrs on arm64: next 0, name 8, flags 16, addr 24,
        // netmask 32, dstaddr 40, data 48. Only the first four were ever read.
        // The kernel filled all of them in the same call, so the other three
        // cost nothing to take and each answers a question the address cannot:
        // the netmask says how big the LAN is, dstaddr names the far end of a
        // tunnel, and the AF_LINK entry is where the hardware address lives.
        let cur = this.listp.readPointer();
        let guard = 0;
        while (!cur.isNull() && guard++ < 256) {
          const name = cstr(cur.add(8).readPointer());
          const flags = cur.add(16).readU32();
          if (!name || !(flags & IFF_UP)) { cur = cur.readPointer(); continue; }

          const ap = cur.add(24).readPointer();
          const addr = readSockaddr(ap);
          if (addr) {
            const tag = name + '|' + addr;
            if (!seenAddrs.has(tag)) {
              seenAddrs.add(tag);
              emit('INTERFACE', name, addr);
              const mask = readSockaddr(cur.add(32).readPointer());
              if (mask) emit('IFACE_MASK', name + ' ' + addr, mask);
            }
          } else {
            // No routable address on this entry. On Darwin that is usually the
            // AF_LINK row, which carries the interface's hardware address.
            const mac = readLinkAddr(ap);
            if (mac) {
              const tag = name + '|hw|' + mac;
              if (!seenAddrs.has(tag)) { seenAddrs.add(tag); emit('IFACE_HW', name, mac); }
            }
          }

          // A point-to-point interface names its peer. For a live VPN that is
          // the concentrator on the other side of the tunnel.
          if (flags & IFF_POINTOPOINT) {
            const peer = readSockaddr(cur.add(40).readPointer());
            if (peer) {
              const tag = name + '|peer|' + peer;
              if (!seenAddrs.has(tag)) { seenAddrs.add(tag); emit('IFACE_PEER', name, peer); }
            }
          }
          cur = cur.readPointer();
        }
      } catch (e) {}
    }
  });

  // --- Where traffic actually goes, and which address it leaves from ---
  // getifaddrs says what the phone HAS. These say what it USES. connect gives
  // the destination of every socket including the ones that never touch
  // NSURLSession, getsockname gives the source address the kernel picked for
  // them, and getaddrinfo ties raw addresses back to the names they came from.
  const seenEgress = new Set();

  function reportDest(sa) {
    try {
      if (!sa || sa.isNull()) return;
      const addr = readSockaddr(sa);
      if (!addr || isUnspecified(addr)) return;
      emit('CONNECT', addr, String(readPort(sa)));
    } catch (e) {}
  }

  // All of these fire per network operation, which during streaming means many
  // per second. They are registered here and attached only when the driver arms
  // the 'net' group, which it does after the scene is up, for well under a
  // second. Nothing in this group is ever live during a watchdog window.
  // connect() was recorded on the way in, which cannot tell a destination the
  // phone reached from one it could not. A device with no global IPv6 still
  // calls connect() on every AAAA it was handed and fails instantly, so an
  // onEnter-only hook reports addresses that never carried a byte.
  const EAI = { 2: 'temporary DNS failure', 4: 'permanent DNS failure',
                7: 'name exists but has no address', 8: 'no such name',
                11: 'system error', 12: 'bad hints' };
  const CONN_ERR = { 36: 'in progress', 51: 'network unreachable',
                     65: 'host unreachable', 61: 'refused', 60: 'timed out',
                     56: 'already connected', 22: 'rejected by the kernel' };
  // A connect() to port 443 is TLS or it is QUIC, and the address alone cannot
  // say which. The socket already knows: SOCK_DGRAM on 443 is QUIC. Buffers are
  // allocated once, because this runs per connect.
  const SOL_SOCKET = 0xffff, SO_TYPE = 0x1008;
  let sockType = function () { return null; };
  try {
    const gso = Module.findGlobalExportByName('getsockopt');
    if (gso) {
      const _gso = new NativeFunction(gso, 'int',
                                      ['int', 'int', 'int', 'pointer', 'pointer']);
      const tbuf = Memory.alloc(8), lbuf = Memory.alloc(4);
      sockType = function (fd) {
        try {
          lbuf.writeU32(4);
          if (_gso(fd, SOL_SOCKET, SO_TYPE, tbuf, lbuf) !== 0) return null;
          const t = tbuf.readU32();
          return t === 2 ? 'UDP' : t === 1 ? 'TCP' : null;
        } catch (e) { return null; }
      };
    }
  } catch (e) {}

  probe('net', dangerousExport('connect'), 120, 'outbound connects', {
    onEnter: function (args) {
      this.sa = args[1];
      reportDest(args[1]);
      try {
        // Only the datagram case is recorded. TCP is the assumption, and saying
        // so for every socket would spend the distinct-event budget on nothing.
        if (sockType(args[0].toInt32()) === 'UDP') {
          const a = readSockaddr(args[1]);
          if (a) emit('SOCKTYPE', a, 'UDP, so QUIC rather than TLS');
        }
      } catch (e) {}
    },
    onLeave: function (retval) {
      try {
        if (retval.toInt32() === 0) return;      // connected outright
        const e = this.errno;
        if (e === 36) return;                    // EINPROGRESS, the normal case
        const addr = readSockaddr(this.sa);
        if (addr) emit('CONNECT_FAIL', addr, CONN_ERR[e] || ('errno ' + e));
      } catch (e2) {}
    }
  });

  // Network.framework goes through connectx. In sa_endpoints_t the destination
  // pointer sits at offset 24 on arm64.
  probe('net', dangerousExport('connectx'), 120, 'outbound connects (nw)', {
    onEnter: function (args) {
      try {
        if (args[1].isNull()) return;
        reportDest(args[1].add(24).readPointer());
      } catch (e) {}
    }
  });

  probe('net', dangerousExport('getsockname'), 120, 'egress address reads', {
    onEnter: function (args) { this.sa = args[1]; },
    onLeave: function (retval) {
      try {
        if (retval.toInt32() !== 0 || this.sa.isNull()) return;
        const addr = readSockaddr(this.sa);
        if (!addr || isUnspecified(addr) || seenEgress.has(addr)) return;
        seenEgress.add(addr);
        emit('EGRESS', addr, null);
      } catch (e) {}
    }
  });

  probe('net', dangerousExport('getaddrinfo'), 120, 'name lookups', {
    onEnter: function (args) {
      this.host = args[0].isNull() ? null : cstr(args[0]);
      this.res = args[3];
      // ai_flags is the first field of the hints struct. AI_NUMERICHOST means
      // the caller is not asking for a lookup at all, it is asking "is this
      // string already an address". An app that does this is deciding whether
      // it needs DNS, which is what a client with its own resolver does.
      this.numeric = false;
      try {
        if (!args[2].isNull()) this.numeric = !!(args[2].readU32() & 0x4);
      } catch (e) {}
    },
    onLeave: function (retval) {
      try {
        if (!this.host) return;
        // A lookup that failed is still a lookup. It used to vanish here, which
        // made a blocked or non-existent name indistinguishable from a name the
        // app never asked about.
        if (retval.toInt32() !== 0) {
          const code = retval.toInt32();
          const why = EAI[code] || ('error ' + code);
          emit('DNS_FAIL', this.host,
               this.numeric ? ('not a literal address (' + why + ')') : why);
          return;
        }
        if (this.numeric) emit('DNS_NUMERIC', this.host, 'confirmed as a literal address');
        if (this.res.isNull()) return;
        // struct addrinfo on Darwin: ai_canonname at 24, ai_addr at 32,
        // ai_next at 40. The canonical name is the end of the CNAME chain and
        // says who really serves a host behind a vanity name.
        let ai = this.res.readPointer();
        let guard = 0;
        const seen = new Set();
        while (!ai.isNull() && guard++ < 32) {
          const addr = readSockaddr(ai.add(32).readPointer());
          if (addr && !seen.has(addr)) {
            seen.add(addr);
            emit('DNS', this.host, addr);
          }
          const cn = ai.add(24).readPointer();
          if (!cn.isNull()) {
            const canon = cstr(cn);
            if (canon && canon !== this.host) emit('DNS_CNAME', this.host, canon);
          }
          ai = ai.add(40).readPointer();
        }
      } catch (e) {}
    }
  });

  // --- The rest of the resolver surface ---
  // getaddrinfo reports failure through its own numbering, not errno.
  // getaddrinfo is one door of several. A name resolved through any of these
  // never appears above, and an app that uses its own resolver appears, from
  // getaddrinfo alone, not to resolve anything at all.
  probe('net', dangerousExport('getnameinfo'), 60, 'reverse lookups', {
    onEnter: function (args) { this.sa = args[0]; this.hostbuf = args[2]; },
    onLeave: function (retval) {
      try {
        if (retval.toInt32() !== 0 || this.hostbuf.isNull()) return;
        const addr = readSockaddr(this.sa), name = cstr(this.hostbuf);
        if (addr && name) emit('DNS_REVERSE', addr, name);
      } catch (e) {}
    }
  });

  ['gethostbyname', 'gethostbyname2'].forEach(function (sym) {
    probe('net', dangerousExport(sym), 60, 'legacy name lookups', {
      onEnter: function (args) { this.host = args[0].isNull() ? null : cstr(args[0]); },
      onLeave: function (retval) {
        try {
          if (!this.host || retval.isNull()) return;
          // struct hostent: h_length at 20, h_addr_list at 24
          const len = retval.add(20).readS32();
          if (len !== 4 && len !== 16) return;
          let listp = retval.add(24).readPointer(), guard = 0;
          while (!listp.isNull() && guard++ < 16) {
            const ap = listp.readPointer();
            if (ap.isNull()) break;
            const b = new Uint8Array(ap.readByteArray(len));
            if (b.length === 4) emit('DNS', this.host, b.join('.'));
            listp = listp.add(8);
          }
        } catch (e) {}
      }
    });
  });

  // Network.framework resolves and connects without going near any of the above.
  // These two accessors are the choke point every nw_ endpoint passes through.
  probe('net', dangerousExport('nw_endpoint_get_hostname'), 150, 'nw endpoint names', {
    onLeave: function (retval) {
      try {
        if (retval.isNull()) return;
        const h = cstr(retval);
        if (h) emit('NW_ENDPOINT', h, 'name');
      } catch (e) {}
    }
  });

  probe('net', dangerousExport('nw_endpoint_copy_address_string'), 150,
        'nw endpoint addresses', {
    onLeave: function (retval) {
      try {
        if (retval.isNull()) return;
        const a = retval.readUtf8String();
        if (a) emit('NW_ENDPOINT', a, 'address');
      } catch (e) {}
    }
  });

  // --- Peers that connect() never sees ---
  // Every UDP flow: QUIC, and STUN, which is the one mechanism on the phone
  // that can hand the app its own public address.
  probe('net', dangerousExport('sendto'), 60, 'datagrams sent', {
    onEnter: function (args) {
      try {
        const addr = readSockaddr(args[4]);
        if (addr && !isUnspecified(addr)) {
          emit('UDP_PEER', addr, String(readPort(args[4])));
        }
      } catch (e) {}
    }
  });

  probe('net', dangerousExport('recvfrom'), 60, 'datagrams received', {
    onEnter: function (args) { this.from = args[4]; },
    onLeave: function (retval) {
      try {
        if (retval.toInt32() < 0 || this.from.isNull()) return;
        const addr = readSockaddr(this.from);
        if (addr && !isUnspecified(addr)) {
          emit('UDP_PEER', addr, String(readPort(this.from)));
        }
      } catch (e) {}
    }
  });

  probe('net', dangerousExport('getpeername'), 120, 'peer address reads', {
    onEnter: function (args) { this.sa = args[1]; },
    onLeave: function (retval) {
      try {
        if (retval.toInt32() !== 0 || this.sa.isNull()) return;
        const addr = readSockaddr(this.sa);
        if (addr && !isUnspecified(addr)) {
          emit('PEER', addr, String(readPort(this.sa)));
        }
      } catch (e) {}
    }
  });

  // --- The name on the certificate, before any of it is encrypted ---
  // SNI is set once per TLS handshake, which is far quieter than SSL_write and
  // gives the hostname for connections whose bytes are never parsed, including
  // anything the app's own network stack opens.
  probe('net', dangerousExport('SSLSetPeerDomainName'), 120, 'TLS SNI (Secure Transport)', {
    onEnter: function (args) {
      try {
        const n = args[2].toInt32();
        if (n > 0 && n < 256) {
          const h = args[1].readUtf8String(n);
          if (h) emit('SNI', h, null);
        }
      } catch (e) {}
    }
  });

  eachExport('SSL_set_tlsext_host_name').forEach(function (ex) {
    probe('net', ex.addr, 120, 'TLS SNI (BoringSSL in ' + ex.mod + ')', {
      onEnter: function (args) {
        try {
          if (args[1].isNull()) return;
          const h = cstr(args[1]);
          if (h) emit('SNI', h, null);
        } catch (e) {}
      }
    });
  });

  // The modern way to ask "is there a VPN" is to ask whether the path uses
  // interface type 'other'. Called very frequently by networking, so hotHook.
  const NW_TYPE = ['other, which is where a VPN shows up', 'Wi-Fi', 'cellular',
                   'wired', 'loopback'];
  probe('net', dangerousExport('nw_path_uses_interface_type'), 150,
        'path type checks', {
    onEnter: function (args) { this.t = args[1].toInt32(); },
    onLeave: function (retval) {
      emit('NWPATH', NW_TYPE[this.t] || ('interface type ' + this.t),
           retval.toInt32() ? 'yes' : 'no');
    }
  });

  // The older, quieter way to enumerate interfaces, which getifaddrs hooks miss
  try {
    const SIOCGIFCONF = 0xc0106924, SIOCGIFADDR = 0xc0206921;
    // ioctl runs on EVERY socket operation, one of the hottest syscalls there is.
    // Sample stays tiny: this signal is redundant with getifaddrs, so missing a
    // rare SIOCGIFCONF is an acceptable trade for never being live at launch.
    probe('net', dangerousExport('ioctl'), 150, 'ioctl calls', {
      onEnter: function (args) {
        const req = args[1].toUInt32();
        if (req === SIOCGIFCONF) emit('IFENUM', 'ioctl SIOCGIFCONF', null);
        else if (req === SIOCGIFADDR) emit('IFENUM', 'ioctl SIOCGIFADDR', null);
      }
    });
  } catch (e) {}

  // --- The routing table, which is the only way to learn the router ---
  // getifaddrs says which addresses the phone holds. It never says which box
  // those packets are handed to. iOS exposes no API for the gateway, so the
  // one way to it from inside a sandbox is a PF_ROUTE dump through sysctl,
  // and nothing about that read is permission-gated or prompted.
  //
  // The default route is the entry that is up, has a gateway, and whose
  // destination is the wildcard. Its gateway is the router on this network,
  // and a router address is a fixed point that every device behind it shares.
  const CTL_NET = 4, PF_ROUTE = 17;
  const NET_RT_DUMP = 1, NET_RT_FLAGS = 2, NET_RT_IFLIST = 3, NET_RT_IFLIST2 = 6;
  const RTF_UP = 0x1, RTF_GATEWAY = 0x2;
  const RT_WHICH = {};
  RT_WHICH[NET_RT_DUMP] = 'routing table';
  RT_WHICH[NET_RT_FLAGS] = 'neighbour cache';
  RT_WHICH[NET_RT_IFLIST] = 'interface list';
  RT_WHICH[NET_RT_IFLIST2] = 'interface list';

  function roundup(n) { return n ? ((n + 3) & ~3) : 4; }

  function isWildcard(a) {
    return a === '0.0.0.0' || a === '::' || a === '' || /^0(:0)*$/.test(a);
  }

  try {
    const sysctlp = Module.findGlobalExportByName('sysctl');
    if (sysctlp) {
      const routeBudget = budget(24, 'routing table dumps');
      Interceptor.attach(sysctlp, {
        onEnter: function (args) {
          // Cheap gate: two words, on every sysctl. Anything heavier than this
          // does not belong on a call this common.
          this.route = false;
          if (_selfRead) return;      // the capability sweep calls this itself
          try {
            if (args[1].toInt32() < 6) return;
            const mib = args[0];
            if (mib.readU32() !== CTL_NET || mib.add(4).readU32() !== PF_ROUTE) return;
            this.route = true;
            this.which = mib.add(16).readU32();
            this.oldp = args[2];
            this.oldlenp = args[3];
          } catch (e) { this.route = false; }
        },
        onLeave: function (retval) {
          try {
            if (!this.route) return;
            emit('ROUTE', 'read the ' + (RT_WHICH[this.which] || 'route table'), null);
            if (retval.toInt32() !== 0 || this.oldp.isNull() || this.oldlenp.isNull()) return;
            if (!routeBudget()) return;

            const total = this.oldlenp.readULong();
            let off = 0, guard = 0;
            while (off + 92 <= total && guard++ < 512) {
              const rec = this.oldp.add(off);
              const msglen = rec.readU16();
              if (msglen < 92 || off + msglen > total) break;
              const flags = rec.add(8).readS32();
              const addrs = rec.add(12).readS32();

              // The sockaddrs follow the header, present-only, in bit order.
              let p = rec.add(92), dst = null, gw = null, gwSa = null;
              for (let bit = 0; bit < 8; bit++) {
                if (!(addrs & (1 << bit))) continue;
                const salen = p.readU8();
                if (bit === 0) dst = readSockaddr(p);
                if (bit === 1) { gw = readSockaddr(p); gwSa = p; }
                p = p.add(roundup(salen));
              }

              if ((flags & RTF_UP) && (flags & RTF_GATEWAY) && dst !== null &&
                  isWildcard(dst) && gw) {
                emit('ROUTE', 'default gateway', gw);
              } else if (this.which === NET_RT_FLAGS && dst && gwSa) {
                // A neighbour-cache dump pairs an address on this LAN with the
                // hardware address behind it. That is every other device on the
                // network, named twice.
                const mac = readLinkAddr(gwSa);
                if (mac) emit('NEIGHBOUR', dst, mac);
              }
              off += msglen;
            }
          } catch (e) {}
        }
      });
    }
  } catch (e) {}

  /* ---------------------------------------------------------------------
   * CAPABILITY SWEEP
   *
   * Everything above answers "what did TikTok read in this window". That is a
   * lower bound and nothing more: a 45-second sample cannot tell an app that
   * never asks from one that asks on the days you are not watching.
   *
   * This answers the other half. Each call below is one TikTok could make --
   * no entitlement the app lacks, no private API -- and it is made from inside
   * TikTok's own process, so the sandbox and entitlements deciding the answer
   * are the app's, not the rig's. A refusal here is therefore a real finding:
   * it means the protection holds FOR THIS APP, not merely that iOS has one.
   *
   * Three outcomes, and the report keeps them apart:
   *   REACH      the call returned a value    -> this is what it would get
   *   REACH_NO   iOS refused it               -> the protection holds
   *   (observed) already in the stream above  -> it actually asked
   *
   * _selfRead is held for the whole sweep, so the hooks above ignore these
   * calls and no count in the report is inflated by the rig's own curiosity.
   * Runs on the flush timer, never on an app thread, and only when the driver
   * asks -- after the launch watchdog has passed.
   * ------------------------------------------------------------------------ */

  function reachEmit(name, value) {
    emit('REACH', name, value == null ? 'available' : String(value).slice(0, 160));
  }
  function reachDenied(name, why) { emit('REACH_NO', name, why); }

  // sysctl(name, namelen, oldp, oldlenp, newp, newlen)
  let _sysctlFn = null;
  try {
    const sp = Module.findGlobalExportByName('sysctl');
    if (sp) {
      _sysctlFn = new NativeFunction(sp, 'int',
        ['pointer', 'uint', 'pointer', 'pointer', 'pointer', 'ulong']);
    }
  } catch (e) {}

  // Ask for the size first, then the data. The table changes between the two
  // calls, so the buffer is padded rather than sized exactly.
  function routeDump(family, which, flags) {
    if (!_sysctlFn) return null;
    const mib = Memory.alloc(24);
    mib.writeU32(CTL_NET);
    mib.add(4).writeU32(PF_ROUTE);
    mib.add(8).writeU32(0);
    mib.add(12).writeU32(family);
    mib.add(16).writeU32(which);
    mib.add(20).writeU32(flags || 0);
    const lenp = Memory.alloc(8);
    lenp.writeULong(0);
    if (_sysctlFn(mib, 6, NULL, lenp, NULL, 0) !== 0) return null;
    let need = Number(lenp.readULong());
    if (need <= 0 || need > 4194304) return null;
    need = need + (need >> 2) + 4096;
    const buf = Memory.alloc(need);
    lenp.writeULong(need);
    if (_sysctlFn(mib, 6, buf, lenp, NULL, 0) !== 0) return null;
    return { buf: buf, len: Number(lenp.readULong()) };
  }

  // Same record walk the passive hook uses: header, then present-only
  // sockaddrs in bit order, each padded to a 4-byte boundary.
  function walkRoutes(d, onEntry) {
    let off = 0, guard = 0, seen = 0;
    while (off + 92 <= d.len && guard++ < 4096) {
      const rec = d.buf.add(off);
      const msglen = rec.readU16();
      if (msglen < 92 || off + msglen > d.len) break;
      const flags = rec.add(8).readS32();
      const addrs = rec.add(12).readS32();
      let p = rec.add(92), dst = null, gw = null, gwSa = null;
      for (let bit = 0; bit < 8; bit++) {
        if (!(addrs & (1 << bit))) continue;
        const salen = p.readU8();
        if (bit === 0) dst = readSockaddr(p);
        if (bit === 1) { gw = readSockaddr(p); gwSa = p; }
        p = p.add(roundup(salen));
      }
      onEntry(flags, dst, gw, gwSa);
      seen++;
      off += msglen;
    }
    return seen;
  }

  function sweepGateway() {
    try {
      const d = routeDump(0, NET_RT_DUMP, 0);
      if (!d) { reachDenied('default gateway', 'the route dump was refused'); return; }
      let found = 0, rows = 0;
      rows = walkRoutes(d, function (flags, dst, gw) {
        if ((flags & RTF_UP) && (flags & RTF_GATEWAY) && dst !== null &&
            isWildcard(dst) && gw) {
          reachEmit('default gateway', gw);
          found++;
        }
      });
      reachEmit('routing table size', rows + ' routes readable');
      if (!found) reachEmit('default gateway', 'no default route present');
    } catch (e) { reachDenied('default gateway', 'read failed'); }
  }

  function sweepNeighbours() {
    try {
      let total = 0;
      [[AF_INET, 'IPv4'], [AF_INET6, 'IPv6']].forEach(function (fam) {
        const d = routeDump(fam[0], NET_RT_FLAGS, 0x400);   // RTF_LLINFO
        if (!d) return;
        walkRoutes(d, function (flags, dst, gw, gwSa) {
          if (!dst) return;
          const mac = readLinkAddr(gwSa);
          // Measured on this phone: iOS hands back 02:00:00:00:00:00 for the
          // hardware address of every neighbour, exactly as it does for the
          // device's own interfaces. The address is real, the MAC is not.
          emit('REACH_NEIGHBOUR', dst,
               (mac && !/^0[02]:00:00:00:00:00$/.test(mac))
                 ? mac : 'IP readable, MAC masked by iOS');
          total++;
        });
      });
      if (total) reachEmit('neighbour cache', total + ' other devices on this network, by IP');
      else reachDenied('neighbour cache', 'iOS returned no neighbours to this app');
    } catch (e) { reachDenied('neighbour cache', 'read failed'); }
  }

  // NET_RT_IFLIST is the third enumeration route, and the one TikTok actually
  // hammers -- 128 to 172 calls a run -- while getifaddrs gets 48. Until now
  // the rig counted those calls and never decoded what came back.
  //
  // Two record types, two header sizes, which is why the plain 92-byte route
  // header cannot read them: RTM_IFINFO carries the interface itself (name and
  // hardware address, in a sockaddr_dl after a variable-length if_data), and
  // RTM_NEWADDR carries one address of it after a 20-byte header.
  const RTM_IFINFO = 0x0e, RTM_IFINFO2 = 0x12, RTM_NEWADDR = 0x0c;

  function findLinkAddr(rec, msglen) {
    // if_data's size is not fixed across releases, so rather than hardcode an
    // offset, scan for the sockaddr_dl and validate it before trusting it.
    for (let o = 16; o + 8 <= msglen; o += 4) {
      try {
        const salen = rec.add(o).readU8(), fam = rec.add(o + 1).readU8();
        if (fam !== AF_LINK || salen < 8 || salen > 64 || o + salen > msglen) continue;
        const nlen = rec.add(o + 5).readU8(), alen = rec.add(o + 6).readU8();
        if (8 + nlen + alen > salen) continue;
        let name = '';
        if (nlen > 0 && nlen < 24) {
          const nb = new Uint8Array(rec.add(o + 8).readByteArray(nlen));
          for (let i = 0; i < nb.length; i++) name += String.fromCharCode(nb[i]);
        }
        return { name: name, mac: alen ? readLinkAddr(rec.add(o)) : null,
                 index: rec.add(o + 2).readU16() };
      } catch (e) {}
    }
    return null;
  }

  function sweepInterfaceList() {
    try {
      const d = routeDump(0, NET_RT_IFLIST, 0);
      if (!d) { reachDenied('interface list via sysctl', 'the dump was refused'); return; }
      let off = 0, guard = 0, ifaces = 0;
      const byIndex = {};
      while (off + 4 <= d.len && guard++ < 4096) {
        const rec = d.buf.add(off);
        const msglen = rec.readU16();
        if (msglen < 4 || off + msglen > d.len) break;
        const type = rec.add(3).readU8();
        if (type === RTM_IFINFO || type === RTM_IFINFO2) {
          const li = findLinkAddr(rec, msglen);
          if (li && li.name) {
            byIndex[li.index] = li.name;
            ifaces++;
            const masked = !li.mac || /^0[02]:00:00:00:00:00$/.test(li.mac);
            emit('REACH_IFACE', li.name,
                 li.mac ? (masked ? 'hardware address masked by iOS' : li.mac)
                        : 'no hardware address');
          }
        } else if (type === RTM_NEWADDR) {
          const addrs = rec.add(4).readS32();
          const idx = rec.add(12).readU16();
          let p = rec.add(20), mask = null, addr = null;
          for (let bit = 0; bit < 8; bit++) {
            if (!(addrs & (1 << bit))) continue;
            const salen = p.readU8();
            if (bit === 2) mask = readSockaddr(p);       // RTA_NETMASK
            if (bit === 5) addr = readSockaddr(p);       // RTA_IFA
            p = p.add(roundup(salen));
          }
          if (addr) {
            emit('REACH_IFADDR', (byIndex[idx] || ('if' + idx)) + '  ' + addr,
                 mask ? ('netmask ' + mask) : 'no netmask');
          }
        }
        off += msglen;
      }
      reachEmit('interface list via sysctl',
                ifaces + ' interfaces, with names and hardware addresses');
    } catch (e) { reachDenied('interface list via sysctl', 'read failed'); }
  }

  function cfStr(js) {
    try { return ObjC.classes.NSString.stringWithUTF8String_(Memory.allocUtf8String(js)); }
    catch (e) { return null; }
  }

  function sweepWifiIdentity() {
    // The SSID and the router's MAC. Gated since iOS 13 behind an entitlement
    // AND live location authorisation, so a refusal is the expected answer and
    // is worth recording as one.
    try {
      const p = Module.findGlobalExportByName('CNCopyCurrentNetworkInfo');
      if (!p) { reachDenied('Wi-Fi SSID and BSSID', 'the API is not present'); return; }
      const fn = new NativeFunction(p, 'pointer', ['pointer']);
      const nameStr = cfStr('en0');
      const ret = fn(nameStr ? nameStr.handle : NULL);
      if (ret.isNull()) {
        reachDenied('Wi-Fi SSID and BSSID',
                    'iOS refused it: this app is not entitled to Wi-Fi info');
        return;
      }
      const d = new ObjC.Object(ret);
      const ssid = d.objectForKey_('SSID'), bssid = d.objectForKey_('BSSID');
      if (ssid && !ssid.handle.isNull()) reachEmit('Wi-Fi network name', String(ssid));
      if (bssid && !bssid.handle.isNull()) reachEmit('Wi-Fi router address', String(bssid));
    } catch (e) { reachDenied('Wi-Fi SSID and BSSID', 'read failed'); }

    try {
      const p2 = Module.findGlobalExportByName('CNCopySupportedInterfaces');
      if (!p2) return;
      const fn2 = new NativeFunction(p2, 'pointer', []);
      const ret2 = fn2();
      if (ret2.isNull()) { reachDenied('Wi-Fi interface list', 'iOS returned nothing'); return; }
      const arr = new ObjC.Object(ret2);
      const names = [];
      for (let i = 0; i < Math.min(arr.count(), 8); i++) names.push(String(arr.objectAtIndex_(i)));
      reachEmit('Wi-Fi interface list', names.join(', '));
    } catch (e) {}
  }

  function sweepResolvers() {
    try {
      const p = Module.findGlobalExportByName('res_9_getservers');
      const init = Module.findGlobalExportByName('res_9_ninit');
      if (!p) { reachDenied('DNS servers', 'the resolver API is not present'); return; }
      // res_state is opaque and large; 4 KB is comfortably past its real size.
      const st = Memory.alloc(4096);
      if (init) {
        try { new NativeFunction(init, 'int', ['pointer'])(st); } catch (e) {}
      }
      const set = Memory.alloc(128 * 8);
      const fn = new NativeFunction(p, 'int', ['pointer', 'pointer', 'int']);
      const n = fn(st, set, 8);
      if (n <= 0) { reachDenied('DNS servers', 'the resolver returned none'); return; }
      const out = [];
      for (let i = 0; i < Math.min(n, 8); i++) {
        const a = readSockaddr(set.add(i * 128));
        if (a) out.push(a);
      }
      if (out.length) reachEmit('DNS servers', out.join(', '));
      else reachDenied('DNS servers', 'the resolver returned none');
    } catch (e) { reachDenied('DNS servers', 'read failed'); }
  }

  function sweepProxy() {
    try {
      const p = Module.findGlobalExportByName('CFNetworkCopySystemProxySettings');
      if (!p) return;
      const ret = new NativeFunction(p, 'pointer', [])();
      if (ret.isNull()) { reachDenied('proxy settings', 'iOS returned nothing'); return; }
      const d = new ObjC.Object(ret);
      const out = [];
      for (let i = 0; i < PROXY_KEYS.length; i++) {
        const v = d.objectForKey_(PROXY_KEYS[i]);
        if (v === null || v.handle.isNull()) continue;
        const sv = String(v);
        if (sv === '0') continue;
        out.push(PROXY_KEYS[i] + '=' + sv);
      }
      reachEmit('proxy settings', out.length ? out.join(' ') : 'no proxy configured');
    } catch (e) {}
  }

  // The keys TikTok already asks for every launch. The passive hook records the
  // key and never the answer, deliberately. Here the answer is the point.
  const GESTALT_WANTED = ['RegionCode', 'RegionInfo', 'DeviceName', 'ProductType',
                          'ReleaseType', 'InternationalMobileEquipmentIdentity',
                          'SerialNumber', 'UniqueDeviceID', 'WifiAddress',
                          'BluetoothAddress'];
  function sweepGestalt() {
    try {
      const mg = Module.findGlobalExportByName('MGCopyAnswer');
      if (!mg) return;
      const fn = new NativeFunction(mg, 'pointer', ['pointer']);
      GESTALT_WANTED.forEach(function (k) {
        try {
          const ks = cfStr(k);
          if (!ks) return;
          const ret = fn(ks.handle);
          if (ret.isNull()) { reachDenied('gestalt ' + k, 'iOS refused it'); return; }
          reachEmit('gestalt ' + k, String(new ObjC.Object(ret)));
        } catch (e) { reachDenied('gestalt ' + k, 'read failed'); }
      });
    } catch (e) {}
  }

  // The only probe that puts a packet on the wire. TikTok can do this -- any
  // app can ask a server for its own address -- but running it means one
  // request attributable to the app that the user did not make, so it is a
  // separate opt-in and never fires by default.
  const _wanBlocks = [];

  // Path 1 and 2: NSURLSession. This is the app's own networking, so whatever
  // proxy or tunnel iOS has configured applies -- which is exactly what makes
  // it the right answer for "what would TikTok see", and exactly what makes it
  // fail silently when an on-device proxy is in the way. The error is captured
  // now rather than discarded, because "returned nothing" is not a diagnosis.
  function wanQuery(urlStr, label, ephemeral) {
    try {
      const NSURL = ObjC.classes.NSURL, NSURLSession = ObjC.classes.NSURLSession;
      if (!NSURL || !NSURLSession) return;
      const url = NSURL.URLWithString_(urlStr);
      if (!url) return;

      let session;
      if (ephemeral && ObjC.classes.NSURLSessionConfiguration) {
        // A fresh ephemeral configuration, in case the shared session's is the
        // thing that is broken. Longer timeout: a proxy adds a hop.
        const cfg = ObjC.classes.NSURLSessionConfiguration.ephemeralSessionConfiguration();
        try { cfg.setTimeoutIntervalForRequest_(12.0); } catch (e) {}
        try { cfg.setTimeoutIntervalForResource_(18.0); } catch (e) {}
        session = NSURLSession.sessionWithConfiguration_(cfg);
      } else {
        session = NSURLSession.sharedSession();
      }

      const blk = new ObjC.Block({
        retType: 'void', argTypes: ['object', 'object', 'object'],
        implementation: function (data, resp, err) {
          try {
            if (err && !err.handle.isNull()) {
              let why = '';
              try {
                why = String(err.localizedDescription()) + ' (code ' + err.code() + ')';
              } catch (e) { why = 'error with no description'; }
              reachDenied(label, 'the request failed: ' + why);
              return;
            }
            if (!data || data.handle.isNull() || data.length() === 0) {
              let code = '';
              try { code = ' (HTTP ' + resp.statusCode() + ')'; } catch (e) {}
              reachDenied(label, 'the request returned an empty body' + code);
              return;
            }
            const v = String(ObjC.classes.NSString.alloc()
                        .initWithData_encoding_(data, 4)).trim();
            if (v && v.length < 46) emit('REACH_WAN', v, label);
            else reachDenied(label, 'the reply was not an address');
          } catch (e) { reachDenied(label, 'the reply could not be read'); }
        }
      });
      _wanBlocks.push(blk);
      session.dataTaskWithURL_completionHandler_(url, blk).resume();
    } catch (e) { reachDenied(label, 'the request could not be made'); }
  }

  // Path 3: a raw socket to a numeric address, with a hand-written request.
  // No DNS, no NSURLSession, no proxy configuration consulted -- so this is the
  // address seen by traffic that ignores the app's proxy settings entirely.
  // When it disagrees with path 1, that disagreement IS the finding: some of
  // the phone's traffic is not going where the proxy thinks it is.
  //
  // 1.1.1.1 is used because it is a stable anycast address that needs no
  // lookup, and /cdn-cgi/trace answers with a line reading ip=<address>.
  function wanRawSocket(ipStr, hostHdr, path, label) {
    let fd = -1;
    try {
      const g = Module.findGlobalExportByName.bind(Module);
      const _socket = new NativeFunction(g('socket'), 'int', ['int', 'int', 'int']);
      const _connect = new NativeFunction(g('connect'), 'int', ['int', 'pointer', 'uint']);
      const _send = new NativeFunction(g('send'), 'long', ['int', 'pointer', 'ulong', 'int']);
      const _recv = new NativeFunction(g('recv'), 'long', ['int', 'pointer', 'ulong', 'int']);
      const _close = new NativeFunction(g('close'), 'int', ['int']);
      const _setsockopt = new NativeFunction(g('setsockopt'), 'int',
        ['int', 'int', 'int', 'pointer', 'uint']);

      fd = _socket(2, 1, 0);                       // AF_INET, SOCK_STREAM
      if (fd < 0) { reachDenied(label, 'no socket'); return; }

      // Short timeouts on purpose: this runs on the script thread, and the
      // driver treats five seconds of silence as a wedged script.
      const tv = Memory.alloc(16);
      tv.writeU64(3); tv.add(8).writeU64(0);       // 3s: long enough that
                                                   // impatience is not mistaken
                                                   // for a blocked path
      _setsockopt(fd, 0xffff, 0x1005, tv, 16);     // SO_RCVTIMEO
      _setsockopt(fd, 0xffff, 0x1006, tv, 16);     // SO_SNDTIMEO

      const sa = Memory.alloc(16);
      sa.writeU8(16); sa.add(1).writeU8(2);
      sa.add(2).writeU8(0); sa.add(3).writeU8(80); // port 80, network order
      const parts = ipStr.split('.');
      for (let i = 0; i < 4; i++) sa.add(4 + i).writeU8(parseInt(parts[i], 10));

      if (_connect(fd, sa, 16) !== 0) {
        reachDenied(label, 'could not connect to ' + ipStr + ' directly');
        _close(fd); return;
      }
      const req = 'GET ' + path + ' HTTP/1.1\r\nHost: ' + hostHdr +
                  '\r\nUser-Agent: curl/8\r\nConnection: close\r\n\r\n';
      const buf = Memory.allocUtf8String(req);
      if (_send(fd, buf, req.length, 0) < 0) {
        reachDenied(label, 'the direct request could not be sent');
        _close(fd); return;
      }
      const rbuf = Memory.alloc(4096);
      const n = _recv(fd, rbuf, 4095, 0);
      _close(fd); fd = -1;
      if (n <= 0) { reachDenied(label, 'no reply from ' + ipStr); return; }
      const body = rbuf.readUtf8String(Number(n)) || '';
      const m = /(?:^|\n)ip=([0-9a-fA-F:.]{3,45})/.exec(body) ||
                /\b(\d{1,3}(?:\.\d{1,3}){3})\b\s*$/.exec(body.trim());
      if (m) emit('REACH_WAN', m[1], label);
      else reachDenied(label, 'the reply carried no address');
    } catch (e) {
      reachDenied(label, 'the direct request failed');
      try { if (fd >= 0) new NativeFunction(
        Module.findGlobalExportByName('close'), 'int', ['int'])(fd); } catch (e2) {}
    }
  }

  // Control. Not an address probe: it only reports whether a request made this
  // way completes at all, to a host the app itself talks to. If the controls
  // succeed while the echo endpoints fail, the destinations are being rejected
  // by something on the phone rather than the probe being broken.
  function wanControl(urlStr, label) {
    try {
      const NSURL = ObjC.classes.NSURL, NSURLSession = ObjC.classes.NSURLSession;
      const url = NSURL.URLWithString_(urlStr);
      if (!url) return;
      const cfg = ObjC.classes.NSURLSessionConfiguration.ephemeralSessionConfiguration();
      try { cfg.setTimeoutIntervalForRequest_(12.0); } catch (e) {}
      const blk = new ObjC.Block({
        retType: 'void', argTypes: ['object', 'object', 'object'],
        implementation: function (data, resp, err) {
          try {
            if (err && !err.handle.isNull()) {
              emit('REACH_PATH', label, 'failed: ' + String(err.localizedDescription()));
            } else {
              let code = '?';
              try { code = String(resp.statusCode()); } catch (e) {}
              emit('REACH_PATH', label, 'the request completed, HTTP ' + code);
            }
          } catch (e) {}
        }
      });
      _wanBlocks.push(blk);
      NSURLSession.sessionWithConfiguration_(cfg)
        .dataTaskWithURL_completionHandler_(url, blk).resume();
    } catch (e) {}
  }

  function sweepWanDual() {
    // A battery, not a single endpoint. Through an on-device proxy the obvious
    // call fails with -1005 and tells you nothing about why, so several
    // providers and several transports are tried and each reports its own
    // outcome. Whichever answers, answers; the pattern of failures is itself
    // information about what the tunnel is doing.
    wanQuery('https://api.ipify.org', 'over IPv4, what a server sees', false);
    wanQuery('https://api64.ipify.org', 'over whichever family it prefers', false);
    wanQuery('https://api.ipify.org', 'over IPv4, on a fresh session', true);
    wanQuery('https://icanhazip.com', 'a second provider, over TLS', true);
    wanQuery('https://1.1.1.1/cdn-cgi/trace', 'to a numeric address, no lookup', true);
    wanControl('https://www.tiktok.com/robots.txt', 'a TikTok host, same method');
    wanControl('https://www.apple.com/library/test/success.html',
               'an unrelated host, same method');
  }

  // Direct sockets, no resolver and no NSURLSession. Two targets so a single
  // blocked destination cannot be mistaken for a blocked path: 1.1.1.1 is also
  // a resolver and a proxy may treat it specially, an ordinary CDN edge is not.
  function sweepWanDirect() {
    // One, not three. Each blocks the script thread for its timeout, and the
    // driver treats five seconds of silence as a wedged script.
    wanRawSocket('1.1.1.1', '1.1.1.1', '/cdn-cgi/trace',
                 'a direct socket, no proxy settings consulted');
  }

  rpc.exports.reachwan = function () {
    const was = _selfRead;
    _selfRead = true;
    try { sweepWanDirect(); } finally { _selfRead = was; }
    return true;
  };

  function reachSweep(doWan) {
    const was = _selfRead;
    _selfRead = true;
    try {
      sweepGateway();
      sweepNeighbours();
      sweepResolvers();
      sweepProxy();
      sweepInterfaceList();
      sweepWifiIdentity();
      sweepGestalt();
      if (doWan) sweepWanDual();
    } catch (e) {
      emit('REACH_NO', 'capability sweep', 'aborted: ' + e);
    } finally {
      _selfRead = was;
    }
    return true;
  }
  rpc.exports.reach = function (doWan) { return reachSweep(!!doWan); };

  // --- Locale, language, timezone and keyboards (read-only) ---
  // Every one of these is permission-free and each carries real entropy. The
  // keyboard list is the sharpest: it names the languages you actually type in.
  function objcRet(cls, sel, cat, key, fmt) {
    try {
      const m = ObjC.classes[cls] && ObjC.classes[cls][sel];
      if (!m) return;
      Interceptor.attach(m.implementation, {
        onLeave: function (ret) {
          try {
            if (ret.isNull()) return;
            const o = new ObjC.Object(ret);
            emit(cat, key, fmt ? fmt(o) : String(o));
          } catch (e) {}
        }
      });
    } catch (e) {}
  }

  // an NSLocale prints as <__NSCFLocale: 0x...>, which tells the reader nothing.
  // The identifier is the actual finding.
  function localeId(o) {
    try { return String(o.localeIdentifier()); } catch (e) { return String(o); }
  }
  // and an NSArray prints as ( "en-US" ), so flatten it
  function joinArray(o) {
    try {
      const n = o.count();
      const out = [];
      for (let i = 0; i < n && i < 12; i++) out.push(String(o.objectAtIndex_(i)));
      return out.join(', ');
    } catch (e) { return String(o); }
  }

  objcRet('NSLocale', '+ currentLocale', 'LOCALE', 'current locale', localeId);
  objcRet('NSLocale', '+ preferredLanguages', 'LOCALE', 'preferred languages', joinArray);
  objcRet('NSLocale', '+ autoupdatingCurrentLocale', 'LOCALE', 'current locale', localeId);
  objcRet('NSTimeZone', '+ localTimeZone', 'LOCALE', 'timezone', function (o) {
    try { return String(o.name()); } catch (e) { return String(o); }
  });
  objcRet('NSTimeZone', '+ systemTimeZone', 'LOCALE', 'timezone', function (o) {
    try { return String(o.name()); } catch (e) { return String(o); }
  });
  objcRet('NSTimeZone', '+ defaultTimeZone', 'LOCALE', 'timezone', function (o) {
    try { return String(o.name()); } catch (e) { return String(o); }
  });
  objcRet('NSCalendar', '+ currentCalendar', 'LOCALE', 'calendar', function (o) {
    try { return String(o.calendarIdentifier()); } catch (e) { return String(o); }
  });

  try {
    const m = ObjC.classes.NSTimeZone['- secondsFromGMT'];
    if (m) {
      Interceptor.attach(m.implementation, {
        onLeave: function (ret) {
          emit('LOCALE', 'offset from GMT', (ret.toInt32() / 3600) + ' hours');
        }
      });
    }
  } catch (e) {}

  // the enabled keyboards, which is to say the languages you type in
  try {
    const m = ObjC.classes.UITextInputMode['+ activeInputModes'];
    if (m) {
      Interceptor.attach(m.implementation, {
        onLeave: function (ret) {
          try {
            if (ret.isNull()) return;
            const arr = new ObjC.Object(ret);
            const langs = [];
            const n = arr.count();
            for (let i = 0; i < n && i < 24; i++) {
              const mode = arr.objectAtIndex_(i);
              try {
                const pl = mode.primaryLanguage();
                if (pl && !pl.isNull()) langs.push(String(pl));
              } catch (e) {}
            }
            emit('LOCALE', 'installed keyboards', langs.join(', ') || String(n));
          } catch (e) {}
        }
      });
    }
  } catch (e) {}

  // --- Settings it reads (read-only) ---
  // The KEY is the finding. AppleLanguages and AppleKeyboards live here, and so
  // do the accessibility toggles, each of which is another bit of entropy.
  const LOCALE_KEY = /^Apple(Languages|Locale|Keyboards)/i;
  // Building an ObjC wrapper and a string on every call is expensive, and a big
  // app reads defaults constantly. Past the budget this is one integer compare.
  const defBudget = budget(20000, 'NSUserDefaults reads');
  ['- objectForKey:', '- stringForKey:', '- arrayForKey:', '- boolForKey:'].forEach(
    function (sel) {
      try {
        const m = ObjC.classes.NSUserDefaults[sel];
        if (!m) return;
        Interceptor.attach(m.implementation, {
          onEnter: function (args) {
            this.k = null;
            if (!defBudget()) return;
            try {
              this.k = new ObjC.Object(args[2]).toString();
            } catch (e) { this.k = null; }
          },
          onLeave: function (ret) {
            if (!this.k) return;
            let v = null;
            if (LOCALE_KEY.test(this.k)) {
              try { if (!ret.isNull()) v = String(new ObjC.Object(ret)); } catch (e) {}
            }
            emit('SETTINGS', this.k, v);
          }
        });
      } catch (e) {}
    });

  // --- Carrier and radio (read-only) ---
  objcRet('CTTelephonyNetworkInfo', '- subscriberCellularProvider', 'CARRIER',
          'carrier', function (o) {
    try { return String(o.carrierName()); } catch (e) { return String(o); }
  });
  objcRet('CTTelephonyNetworkInfo', '- currentRadioAccessTechnology', 'CARRIER',
          'radio technology');
  objcRet('CTCarrier', '- carrierName', 'CARRIER', 'carrier name');
  objcRet('CTCarrier', '- isoCountryCode', 'CARRIER', 'country code');
  objcRet('CTCarrier', '- mobileCountryCode', 'CARRIER', 'mobile country code');
  objcRet('CTCarrier', '- mobileNetworkCode', 'CARRIER', 'mobile network code');

  // --- Advertising identity (read-only) ---
  objcRet('ASIdentifierManager', '- advertisingIdentifier', 'IDENTIFIER',
          'advertisingIdentifier');
  try {
    const m = ObjC.classes.ATTrackingManager &&
              ObjC.classes.ATTrackingManager['+ trackingAuthorizationStatus'];
    if (m) {
      Interceptor.attach(m.implementation, {
        onLeave: function (ret) {
          const S = ['not determined', 'restricted', 'denied', 'authorised'];
          emit('IDENTIFIER', 'tracking permission', S[ret.toInt32()] || String(ret.toInt32()));
        }
      });
    }
  } catch (e) {}

  // --- Clipboard (read-only) ---
  // Reading the pasteboard is how apps have historically scraped whatever you
  // last copied. We log THAT it was read, never the contents.
  ['- string', '- strings', '- items', '- URL', '- image', '- hasStrings',
   '- changeCount'].forEach(function (sel) {
    try {
      const m = ObjC.classes.UIPasteboard && ObjC.classes.UIPasteboard[sel];
      if (!m) return;
      Interceptor.attach(m.implementation, {
        onEnter: function () { emit('PASTEBOARD', 'UIPasteboard ' + sel.slice(2), null); }
      });
    } catch (e) {}
  });

  // --- Screen, battery, storage, uptime (read-only) ---
  // NOT hooked: -[UIScreen scale]. UIKit calls it on every layout pass, so a
  // hook there is thousands of calls a second for a value we already infer from
  // the hardware model. Resolution and brightness are read rarely and are the
  // parts that actually carry fingerprint value.
  try {
    const scr = ObjC.classes.UIScreen;
    const scrBudget = budget(5000, 'screen reads');
    [['- nativeBounds', 'screen resolution'],
     ['- brightness', 'screen brightness']].forEach(function (pair) {
      const m = scr && scr[pair[0]];
      if (!m) return;
      Interceptor.attach(m.implementation, {
        onEnter: function () { if (scrBudget()) emit('DISPLAY', pair[1], null); }
      });
    });
  } catch (e) {}

  try {
    const dev = ObjC.classes.UIDevice;
    [['- batteryLevel', 'battery level'], ['- batteryState', 'battery state']].forEach(
      function (pair) {
        const m = dev && dev[pair[0]];
        if (!m) return;
        Interceptor.attach(m.implementation, {
          onEnter: function () { emit('DISPLAY', pair[1], null); }
        });
      });
  } catch (e) {}

  const procBudget = budget(20000, 'NSProcessInfo reads');
  ['- physicalMemory', '- processorCount', '- activeProcessorCount',
   '- systemUptime', '- thermalState', '- isLowPowerModeEnabled'].forEach(function (sel) {
    try {
      const m = ObjC.classes.NSProcessInfo && ObjC.classes.NSProcessInfo[sel];
      if (!m) return;
      Interceptor.attach(m.implementation, {
        onEnter: function () {
          if (procBudget()) emit('DISPLAY', sel.slice(2), 'via NSProcessInfo');
        }
      });
    } catch (e) {}
  });

  // free disk space is high entropy and needs no permission at all.
  // getattrlist is deliberately excluded: it is a general file-metadata call
  // that fires constantly, and statfs already covers the disk question.
  const diskBudget = budget(20000, 'disk space reads');
  ['statfs', 'statfs64'].forEach(function (fn) {
    try {
      probe('fs', dangerousExport(fn), 80, 'disk checks (' + fn + ')', {
        onEnter: function () { emit('DISPLAY', 'free disk space', 'read via ' + fn); }
      });
    } catch (e) {}
  });

  // --- Which other apps you have installed (read-only) ---
  try {
    const m = ObjC.classes.UIApplication['- canOpenURL:'];
    if (m) {
      Interceptor.attach(m.implementation, {
        onEnter: function (args) {
          try { emit('SCHEME', String(new ObjC.Object(args[2])), null); } catch (e) {}
        }
      });
    }
  } catch (e) {}

  // The COMPLETE, authoritative list of apps TikTok can probe for. iOS requires
  // every scheme an app will ever pass to canOpenURL to be declared here, and
  // silently fails the check for anything not listed. So this Info.plist array
  // is the full set, not just the schemes it happened to probe during the run.
  //
  // CRUCIAL: this CALLS ObjC methods, unlike the hooks which only attach. At
  // load the process is still spawn-paused and its Objective-C runtime is not
  // up, so calling methods now crashes the whole process (connection closed).
  // Defer it with setTimeout so it runs a couple of seconds after resume, once
  // the runtime is live.
  setTimeout(function () {
    try {
      const info = ObjC.classes.NSBundle.mainBundle().infoDictionary();
      const q = info.objectForKey_('LSApplicationQueriesSchemes');
      if (q && !q.isNull()) {
        const n = q.count();
        for (let i = 0; i < n && i < 800; i++) {
          emit('QUERYABLE', String(q.objectAtIndex_(i)), null);
        }
      }
    } catch (e) {}
  }, 2500);

  // --- Tamper checks the sysctl hooks miss (read-only) ---
  // sysctlbyname is the friendly form. The numeric one bypasses it entirely,
  // and kern.proc through that route is the classic debugger check.
  try {
    // sysctl is called frequently, so sample-then-detach, never a bare attach
    // that keeps trapping.
    probe('sys', dangerousExport('sysctl'), 200, 'numeric sysctl reads', {
        onEnter: function (args) {
          try {
            const n = args[1].toInt32();
            if (n < 1 || n > 8) return;
            const mib = [];
            for (let i = 0; i < n; i++) mib.push(args[0].add(i * 4).readU32());
            const s = mib.join('.');
            // Only kern.proc is a tamper signal. The rest of the numeric form is
            // ordinary attribute reading that happens to skip sysctlbyname, and
            // filing it under tamper detection would be misleading.
            if (mib[0] === 1 && mib[1] === 14) {
              emit('TAMPER', 'sysctl kern.proc', 'reads its own process record, '
                   + 'which is the standard debugger check');
            } else {
              emit('DISPLAY', 'sysctl by number ' + s,
                   mib[0] === 1 ? 'a kernel attribute' :
                   mib[0] === 6 ? 'a hardware attribute' : null);
            }
          } catch (e) {}
        }
      });
  } catch (e) {}

  // a library-enumeration sweep calls these once per loaded image. A plain attach
  // keeps trapping, so sample-then-detach instead.
  [['_dyld_image_count', 'counting loaded libraries'],
   ['_dyld_get_image_name', 'reading loaded library names']].forEach(function (pair) {
    try {
      // 64, not 800. "The app sweeps its loaded libraries" is proven by the
      // first few dozen calls; the rest were pure trap cost during launch.
      hotHook(Module.findGlobalExportByName(pair[0]), 64, 'dyld scan (' + pair[0] + ')', {
        onEnter: function () { emit('TAMPER', pair[0], pair[1]); }
      });
    } catch (e) {}
  });

  // csops reads the process's code-signing status. It is the closest thing to a
  // "is this a development / debugged device" check, since iOS 16 Developer Mode
  // itself has no readable public API. The status flags tell the app whether it
  // is being debugged (CS_DEBUGGED) or is a development build (CS_GET_TASK_ALLOW).
  // Low-frequency, but routed through hotHook to stay safe. CS_OPS_STATUS = 0.
  const CS_DEBUGGED = 0x10000000, CS_GET_TASK_ALLOW = 0x00000004;
  ['csops', 'csops_audittoken'].forEach(function (fn) {
    probe('sys', dangerousExport(fn), 80, 'code-signing checks (' + fn + ')', {
      onEnter: function (args) {
        // csops(pid, ops, useraddr, usersize); audittoken variant shifts by one
        var opsIdx = fn === 'csops' ? 1 : 1;
        this.ops = args[opsIdx].toInt32();
        this.useraddr = fn === 'csops' ? args[2] : args[3];
      },
      onLeave: function (ret) {
        if (this.ops !== 0 || this.useraddr.isNull()) {   // only CS_OPS_STATUS
          emit('TAMPER', 'csops (code-signing status)', 'read its own signing state');
          return;
        }
        try {
          var flags = this.useraddr.readU32();
          var notes = [];
          if (flags & CS_DEBUGGED) notes.push('debugged');
          if (flags & CS_GET_TASK_ALLOW) notes.push('development build');
          emit('TAMPER', 'csops (code-signing status)',
               notes.length ? 'checked, saw ' + notes.join(', ')
                            : 'checked, clean');
        } catch (e) {
          emit('TAMPER', 'csops (code-signing status)', 'read its own signing state');
        }
      }
    });
  });

  // jailbreak path probing. Anchored so it does not match every container path
  // that happens to contain the letters "apt".
  const JBPATH = new RegExp([
    'Cydia', 'Sileo\\.app', 'Zebra\\.app', 'MobileSubstrate', 'substrate',
    'TweakInject', 'TweakLoader', 'libhooker', 'ellekit', 'frida', 'cynject',
    '^/var/jb', '^/bin/sh', '^/bin/bash', '^/usr/sbin/sshd', '^/etc/apt',
    '^/var/lib/apt', '^/var/lib/dpkg', '^/Library/MobileSubstrate', '^/Applications/',
  ].join('|'), 'i');
  // stat / lstat / access are among the hottest functions in the process, so
  // each self-detaches after its sample. A jailbreak check happens in the first
  // seconds, so a bounded sample still catches it. open() and fopen() are left
  // out entirely: a jailbreak probe uses stat or access, and open() carries far
  // more traffic. Guards inside stay cheap-first: length before regex.
  ['stat', 'lstat', 'access'].forEach(function (fn) {
    probe('fs', dangerousExport(fn), 150, 'filesystem checks (' + fn + ')', {
      onEnter: function (args) {
        try {
          // NUL-terminated, never an explicit length: a length makes Frida
          // validate the whole span and throw at a page boundary
          const path = args[0].readUtf8String();
          if (!path || path.length > 70) return;
          if (JBPATH.test(path)) emit('TAMPER', path, 'looked for this file');
        } catch (e) {}
      }
    });
  });

  // --- What it checked you had allowed (read-only) ---
  // Asking for a permission STATUS is not itself permission-gated. An app can
  // sweep every one of these silently, and the answers together describe your
  // whole privacy posture without a single prompt.
  const PERM3 = ['not determined', 'restricted', 'denied', 'allowed'];
  const PERM_PH = ['not determined', 'restricted', 'denied', 'allowed', 'limited'];
  const PERM_CL = ['not determined', 'restricted', 'denied', 'always allowed',
                   'allowed while in use'];

  function statusHook(cls, sel, key, names) {
    try {
      const k = ObjC.classes[cls];
      if (!k || !k[sel]) return;
      Interceptor.attach(k[sel].implementation, {
        onLeave: function (ret) {
          const v = ret.toInt32();
          emit('PERMS', key, (names && names[v]) || ('status ' + v));
        }
      });
    } catch (e) {}
  }

  statusHook('PHPhotoLibrary', '+ authorizationStatus', 'photo library', PERM_PH);
  statusHook('PHPhotoLibrary', '+ authorizationStatusForAccessLevel:', 'photo library', PERM_PH);
  statusHook('CNContactStore', '+ authorizationStatusForEntityType:', 'contacts', PERM3);
  statusHook('EKEventStore', '+ authorizationStatusForEntityType:', 'calendar', PERM3);
  statusHook('AVCaptureDevice', '+ authorizationStatusForMediaType:', 'camera or microphone', PERM3);
  statusHook('CLLocationManager', '+ authorizationStatus', 'location', PERM_CL);
  statusHook('CLLocationManager', '- authorizationStatus', 'location', PERM_CL);
  statusHook('ABAddressBook', '+ authorizationStatus', 'contacts (legacy API)', PERM3);

  try {
    const m = ObjC.classes.UNUserNotificationCenter &&
              ObjC.classes.UNUserNotificationCenter['- getNotificationSettingsWithCompletionHandler:'];
    if (m) {
      Interceptor.attach(m.implementation, {
        onEnter: function () { emit('PERMS', 'notifications', 'asked'); }
      });
    }
  } catch (e) {}

  // is Face ID or Touch ID set up on this phone
  try {
    const m = ObjC.classes.LAContext && ObjC.classes.LAContext['- canEvaluatePolicy:error:'];
    if (m) {
      Interceptor.attach(m.implementation, {
        onLeave: function (ret) {
          emit('PERMS', 'biometrics available', ret.toInt32() ? 'yes' : 'no');
        }
      });
    }
  } catch (e) {}

  // Apple's own per-device attestation. Two bits of state Apple keeps for this
  // device, which survives reinstalling the app.
  ['- generateTokenWithCompletionHandler:', '- isSupported'].forEach(function (sel) {
    try {
      const m = ObjC.classes.DCDevice && ObjC.classes.DCDevice[sel];
      if (!m) return;
      Interceptor.attach(m.implementation, {
        onEnter: function () { emit('PERMS', 'Apple device attestation', sel.slice(2)); }
      });
    } catch (e) {}
  });

  // --- More device state (read-only) ---
  // installed fonts, a classic fingerprint: the set you have is unusual enough
  // to narrow a crowd, and reading it needs nothing
  try {
    const m = ObjC.classes.UIFont && ObjC.classes.UIFont['+ familyNames'];
    if (m) {
      Interceptor.attach(m.implementation, {
        onLeave: function (ret) {
          try {
            if (ret.isNull()) return;
            emit('DISPLAY', 'installed fonts',
                 String(new ObjC.Object(ret).count()) + ' families');
          } catch (e) {}
        }
      });
    }
  } catch (e) {}

  // what the audio is coming out of, which says whether headphones or a
  // Bluetooth device are connected and sometimes names it
  try {
    const m = ObjC.classes.AVAudioSession && ObjC.classes.AVAudioSession['- currentRoute'];
    if (m) {
      const routeBudget = budget(2000, 'audio route reads');
      Interceptor.attach(m.implementation, {
        onLeave: function (ret) {
          if (!routeBudget()) return;
          try {
            if (ret.isNull()) return;
            const outs = new ObjC.Object(ret).outputs();
            const n = outs.count();
            const names = [];
            for (let i = 0; i < n && i < 4; i++) {
              names.push(String(outs.objectAtIndex_(i).portType()));
            }
            emit('DISPLAY', 'audio output', names.join(', ') || 'none');
          } catch (e) {}
        }
      });
    }
  } catch (e) {}

  try {
    const m = ObjC.classes.NSHTTPCookieStorage &&
              ObjC.classes.NSHTTPCookieStorage['- cookies'];
    if (m) {
      const cookieBudget = budget(2000, 'cookie store reads');
      Interceptor.attach(m.implementation, {
        onLeave: function (ret) {
          if (!cookieBudget()) return;
          try {
            if (ret.isNull()) return;
            emit('DISPLAY', 'stored cookies',
                 String(new ObjC.Object(ret).count()) + ' cookies');
          } catch (e) {}
        }
      });
    }
  } catch (e) {}

  // which DNS servers the phone is using. These identify your ISP even when a
  // VPN is carrying the traffic, if resolution goes outside the tunnel.
  // res_getservers(res_state, union res_sockaddr_union *set, int cnt) fills the
  // caller's array and RETURNS the number it wrote, so an onEnter hook could
  // never have seen a server address: at that point the array is still empty.
  // That is why this used to record the question and not the answer. The union
  // is a flat 128 bytes per slot whichever family it holds.
  try {
    const rgs = Module.findGlobalExportByName('res_9_getservers');
    if (rgs) {
      const rgsBudget = budget(64, 'resolver list reads');
      Interceptor.attach(rgs, {
        onEnter: function (args) { this.set = args[1]; this.cnt = args[2].toInt32(); },
        onLeave: function (retval) {
          try {
            if (_selfRead || !rgsBudget()) return;
            emit('RESOLVER', 'resolver list', null);
            let n = retval.toInt32();
            if (n < 0 || this.set.isNull()) return;
            if (n > this.cnt) n = this.cnt;
            if (n > 8) n = 8;                       // more than 8 is a bad read
            for (let i = 0; i < n; i++) {
              const a = readSockaddr(this.set.add(i * 128));
              if (a) emit('RESOLVER', 'DNS server', a);
            }
          } catch (e) {}
        }
      });
    }
  } catch (e) {}

  try {
    // Reachability is polled during network activity, so the work is budgeted
    // rather than the trap being detached. args[1] is an out-param the call
    // writes on the way back: the kWWAN bit alone says cellular versus Wi-Fi.
    const scr = Module.findGlobalExportByName('SCNetworkReachabilityGetFlags');
    if (scr) {
      const scrBudget = budget(200, 'reachability checks');
      const REACH = [[0x1, 'transient'], [0x2, 'reachable'], [0x4, 'connection required'],
                     [0x8, 'connects automatically'], [0x10, 'connects on demand'],
                     [0x20, 'is local address'], [0x40, 'is direct'],
                     [0x40000, 'over cellular']];
      Interceptor.attach(scr, {
        onEnter: function (args) { this.flags = args[1]; },
        onLeave: function (retval) {
          try {
            if (!scrBudget()) return;
            emit('DISPLAY', 'connection reachability', 'via SystemConfiguration');
            if (!retval.toInt32() || this.flags.isNull()) return;
            const f = this.flags.readU32();
            for (let i = 0; i < REACH.length; i++) {
              if (f & REACH[i][0]) emit('NWPATH', REACH[i][1], 'yes');
            }
          } catch (e) {}
        }
      });
    }
  } catch (e) {}

  // --- Motion sensors (read-only) ---
  // Accelerometer output carries the chip's factory calibration, which differs
  // between physically identical handsets, so a raw stream is close to a serial
  // number. None of it needs a permission prompt.
  //
  // We hook the START calls and the accessors, never the sample callbacks:
  // those fire up to 100 times a second per sensor and hooking them would cost
  // more than it tells us. Knowing collection began is the finding.
  ['- startAccelerometerUpdates', '- startAccelerometerUpdatesToQueue:withHandler:',
   '- startGyroUpdates', '- startGyroUpdatesToQueue:withHandler:',
   '- startMagnetometerUpdates', '- startMagnetometerUpdatesToQueue:withHandler:',
   '- startDeviceMotionUpdates', '- startDeviceMotionUpdatesToQueue:withHandler:',
   '- startDeviceMotionUpdatesUsingReferenceFrame:toQueue:withHandler:',
  ].forEach(function (sel) {
    try {
      const m = ObjC.classes.CMMotionManager && ObjC.classes.CMMotionManager[sel];
      if (!m) return;
      Interceptor.attach(m.implementation, {
        onEnter: function () {
          emit('SENSOR', sel.replace(/^- start/, '').replace(/(ToQueue.*|Updates.*)$/, '')
                            .toLowerCase() || 'motion',
               'started collecting');
        }
      });
    } catch (e) {}
  });

  ['- accelerometerData', '- gyroData', '- magnetometerData', '- deviceMotion']
    .forEach(function (sel) {
      try {
        const m = ObjC.classes.CMMotionManager && ObjC.classes.CMMotionManager[sel];
        if (!m) return;
        const b = budget(5000, 'motion sample reads');
        Interceptor.attach(m.implementation, {
          onEnter: function () {
            if (b()) emit('SENSOR', sel.slice(2), 'read a sample');
          }
        });
      } catch (e) {}
    });

  ['- startPedometerUpdatesFromDate:withHandler:',
   '- queryPedometerDataFromDate:toDate:withHandler:'].forEach(function (sel) {
    try {
      const m = ObjC.classes.CMPedometer && ObjC.classes.CMPedometer[sel];
      if (!m) return;
      Interceptor.attach(m.implementation, {
        onEnter: function () { emit('SENSOR', 'step count', 'asked for walking data'); }
      });
    } catch (e) {}
  });

  try {
    const m = ObjC.classes.CMAltimeter &&
              ObjC.classes.CMAltimeter['- startRelativeAltitudeUpdatesToQueue:withHandler:'];
    if (m) {
      Interceptor.attach(m.implementation, {
        onEnter: function () {
          emit('SENSOR', 'barometric altitude', 'started collecting, which gives floor level');
        }
      });
    }
  } catch (e) {}

  try {
    const m = ObjC.classes.CMMotionActivityManager &&
              ObjC.classes.CMMotionActivityManager['- startActivityUpdatesToQueue:withHandler:'];
    if (m) {
      Interceptor.attach(m.implementation, {
        onEnter: function () {
          emit('SENSOR', 'motion activity', 'whether you are walking, cycling or driving');
        }
      });
    }
  } catch (e) {}

  // --- Which Wi-Fi network you are on (read-only) ---
  // The BSSID is the router's MAC. Public databases map those to street
  // addresses, so it is a location fix that never touches location permission.
  try {
    const p = Module.findGlobalExportByName('CNCopyCurrentNetworkInfo');
    if (p) {
      Interceptor.attach(p, {
        onEnter: function (args) {
          if (!_selfRead) {
            emit('INTERFACE_ID', 'Wi-Fi network identity', 'asked for SSID and BSSID');
          }
          this.iface = args[0].isNull() ? null : String(new ObjC.Object(args[0]));
        },
        onLeave: function (retval) {
          try {
            if (_selfRead) return;
            // Since iOS 13 this needs the Access WiFi Information entitlement
            // AND live location authorisation, so a null return is the normal
            // answer and is worth recording: it is iOS refusing, not the app
            // declining to ask.
            if (retval.isNull()) {
              emit('INTERFACE_ID', 'Wi-Fi network identity answer',
                   'iOS returned nothing, the app is not entitled to it');
              return;
            }
            const d = new ObjC.Object(retval);
            if (this.iface) emit('INTERFACE_ID', 'asked about interface', this.iface);
            const ssid = d.objectForKey_('SSID');
            const bssid = d.objectForKey_('BSSID');
            if (ssid && !ssid.handle.isNull()) {
              emit('INTERFACE_ID', 'Wi-Fi network name', String(ssid));
            }
            if (bssid && !bssid.handle.isNull()) {
              emit('INTERFACE_ID', 'Wi-Fi router address', String(bssid));
            }
          } catch (e) {}
        }
      });
    }
  } catch (e) {}

  // The companion call. It enumerates the Wi-Fi interfaces before the one above
  // asks about them, and unlike that one it is not entitlement-gated.
  try {
    const csi = Module.findGlobalExportByName('CNCopySupportedInterfaces');
    if (csi) {
      const csiBudget = budget(32, 'Wi-Fi interface list reads');
      Interceptor.attach(csi, {
        onLeave: function (retval) {
          try {
            if (_selfRead || !csiBudget() || retval.isNull()) return;
            const arr = new ObjC.Object(retval);
            const n = Math.min(arr.count(), 8);
            for (let i = 0; i < n; i++) {
              emit('INTERFACE_ID', 'Wi-Fi interface', String(arr.objectAtIndex_(i)));
            }
          } catch (e) {}
        }
      });
    }
  } catch (e) {}

  ['- SSID', '- BSSID'].forEach(function (sel) {
    try {
      const m = ObjC.classes.NEHotspotNetwork && ObjC.classes.NEHotspotNetwork[sel];
      if (!m) return;
      Interceptor.attach(m.implementation, {
        onLeave: function (ret) {
          try {
            if (ret.isNull()) return;
            emit('INTERFACE_ID', sel === '- SSID' ? 'Wi-Fi network name'
                                                  : 'Wi-Fi router address',
                 String(new ObjC.Object(ret)));
          } catch (e) {}
        }
      });
    } catch (e) {}
  });

  // --- Enumerating every installed app (read-only) ---
  // canOpenURL: asks about one app at a time. This private API returns the lot.
  ['- allInstalledApplications', '- applicationsAvailableForOpeningURL:',
   '- installedPlugins'].forEach(function (sel) {
    try {
      const k = ObjC.classes.LSApplicationWorkspace;
      if (!k || !k[sel]) return;
      Interceptor.attach(k[sel].implementation, {
        onLeave: function (ret) {
          let n = '';
          try { if (!ret.isNull()) n = String(new ObjC.Object(ret).count()) + ' apps'; }
          catch (e) {}
          emit('SCHEME', 'listed every installed app', n || sel.slice(2));
        }
      });
    } catch (e) {}
  });

  // --- Request bodies before encryption (OFF unless the driver enables it) ---
  //
  // SSLWrite carries every outbound byte, so on a streaming app it is the single
  // most dangerous thing to hook. It is disabled by default and, when enabled,
  // runs through hotHook so it detaches after a small sample and is force-killed
  // by the wall-clock backstop. A budget alone was not enough, the trapping
  // itself was the problem.
  //
  // SSLWrite is Apple's Secure Transport signature:
  //   OSStatus SSLWrite(SSLContextRef, const void *data, size_t len, size_t *n)
  // so the plaintext is arg 1 and its length is arg 2. Read only, never altered.
  const HTTP_START = /^(GET|POST|PUT|DELETE|HEAD|PATCH|OPTIONS) |^Host: /;
  const seenLines = new Set();
  // 16 bytes is all it takes to tell a request line from a ciphertext blob, and
  // this sniff runs on EVERY outbound buffer, so it reads the smallest window
  // that can decide. Only a buffer that already looks like HTTP pays for the
  // wide read below. That ordering matters: the old code read 96 bytes of every
  // buffer to decide, then still had too small a window to be useful.
  const TLS_SNIFF = 16;
  // 1200, not 400. Measured on this phone: TikTok's CDN request lines carry a
  // signed policy blob in the query string and run past 400 bytes on their own,
  // so a 400-byte window was entirely consumed by the request line and never
  // reached the Host header on the next line. The cost is bounded by the probe's
  // 60-sample limit, and only buffers already identified as HTTP pay it.
  const TLS_WINDOW = 1200;

  // Line breaks have to survive as line breaks. Mapping CR and LF to '.' along
  // with the other unprintables is what produced "HTTP/1.1..Host: lf" and made
  // the header on the next line unreachable.
  function tlsAscii(buf, n) {
    const bytes = new Uint8Array(buf.readByteArray(n));
    let s = '';
    for (let i = 0; i < n; i++) {
      const ch = bytes[i];
      if (ch === 10 || ch === 13) s += '\n';
      else s += (ch >= 0x20 && ch <= 0x7e) ? String.fromCharCode(ch) : '.';
    }
    return s;
  }

  function tlsWriteHandler(args) {
    const buf = args[1];
    const len = args[2].toInt32();
    if (len < 16 || len > 200000 || buf.isNull()) return;
    if (!HTTP_START.test(tlsAscii(buf, len < TLS_SNIFF ? len : TLS_SNIFF))) return;

    const lines = tlsAscii(buf, len < TLS_WINDOW ? len : TLS_WINDOW).split('\n');
    let first = (lines[0] || '').slice(0, 160);
    if (!first) return;
    // Host sits on a header line after the request line. Without it a capture
    // yields a path with no endpoint attached, which is not enough to say what
    // a service actually is.
    let host = '';
    for (let i = 1; i < lines.length && i < 24; i++) {
      if (lines[i].slice(0, 6).toLowerCase() === 'host: ') {
        host = lines[i].slice(6).trim().slice(0, 60);
        break;
      }
    }
    // Fold the host in right after the method rather than appending it, so the
    // endpoint survives the clipping the report does on long paths.
    if (host) {
      const sp = first.indexOf(' ');
      if (sp > 0) {
        first = first.slice(0, sp) + ' ' + host +
                first.slice(sp + 1).replace(/ HTTP\/[\d.]+$/, '');
      }
    }
    const key = first.slice(0, 200);
    if (seenLines.has(key)) return;
    if (seenLines.size < 400) seenLines.add(key);
    emit('PLAINTEXT', key, null);
  }

  // 60, not 400. SSLWrite carries every outbound byte of a video app, so the
  // sample is spent almost instantly either way; the only thing a larger limit
  // bought was a longer stretch of trapping.
  ['SSLWrite', 'SSL_write'].forEach(function (nm) {
    eachExport(nm).forEach(function (e) {
      probe('tls', e.addr, 60, 'TLS write (' + nm + ' in ' + e.mod + ')',
            { onEnter: tlsWriteHandler });
    });
  });

  // --- Publish-only TLS write (OFF unless the driver arms 'publish') ---
  //
  // -Full's tls group attaches four hooks for 600ms at a time and is what
  // killed TikTok on Post. This group is one symbol, stays up for the window,
  // and only pays for a wide read when the sniff already looks like HTTP/1.1
  // or a small buffer carries a canary / aweme needle. Read only.
  const PUB_NEEDLE = /aweme|CANARY|11\.1111|22\.2222|GPSCoordinates|ISO6709/i;
  // Stay on SSL_write only long enough to catch the media POST. Leaving it
  // up through the success-scene transition is what killed TikTok at ~51s.
  var _pubHits = 0;
  var PUB_DETACH_AFTER = 2;

  function b64ptr(ptr, n) {
    try {
      const d = ObjC.classes.NSData.dataWithBytesNoCopy_length_freeWhenDone_(
        ptr, n, false);
      if (!d || d.isNull()) return null;
      return String(d.base64EncodedStringWithOptions_(0));
    } catch (e) { return null; }
  }

  function publishWriteHandler(args) {
    const buf = args[1];
    const len = args[2].toInt32();
    if (len < 16 || len > 200000 || buf.isNull()) return;
    const sniff = tlsAscii(buf, len < TLS_SNIFF ? len : TLS_SNIFF);
    const http = HTTP_START.test(sniff);
    if (!http && len > 65536) return;
    const n = len < TLS_WINDOW ? len : TLS_WINDOW;
    const text = http || len <= 65536 ? tlsAscii(buf, n) : sniff;
    if (!http && !PUB_NEEDLE.test(text)) return;
    if (http) tlsWriteHandler(args);
    if (PUB_NEEDLE.test(text)) {
      emit('PLAINTEXT', 'publish needle in SSL_write',
           text.replace(/\s+/g, ' ').slice(0, 160));
    }
    if (http || PUB_NEEDLE.test(text)) {
      const take = len < MAX_BLOB ? len : MAX_BLOB;
      const b64 = b64ptr(buf, take);
      if (b64 && captureBlob('SSL_write ' + (http ? (text.split('\n')[0] || 'POST')
                                                 : 'needle'), b64, take)) {
        _pubHits++;
        if (_pubHits >= PUB_DETACH_AFTER) {
          emit('RIG', 'publish hook', 'self-detached after ' + _pubHits + ' bodies');
          try { disarmGroup('publish'); } catch (e) {}
        }
      }
    }
  }

  probe('publish', dangerousExport('SSL_write'), 20000, 'publish TLS write',
        { onEnter: publishWriteHandler });

  // --- Response bodies after decryption (read-only) ---
  //
  // The mirror of the write hook, with one trap: a read FILLS its buffer on the
  // way OUT, so the bytes only exist in onLeave, and the count is NOT the arg 2
  // capacity. The two TLS flavours report the count differently:
  //   SSLRead  (Apple Secure Transport): OSStatus SSLRead(ctx, buf, cap, *got)
  //            -> 0 means ok and the real length is in *got (arg 3)
  //   SSL_read (BoringSSL):              int SSL_read(ssl, buf, num)
  //            -> the return value IS the byte count, <= 0 means nothing
  //
  // We keep a response only if it starts with an HTTP status line or looks like
  // JSON. HTTP/2 framing and gzip-compressed bodies decode to binary even after
  // TLS, so those are dropped, which is an honest limit, not a bug.
  // keep JSON payloads and real HTTP responses, but drop the two high-volume,
  // low-information kinds: video/media chunks and WebSocket frames.
  const RESP_START = /^HTTP\/[0-9]|^\{"|^\[\{|^\[\s*"/;
  const RESP_SKIP = /Switching Protocols|Content-Type: (video|audio|image)|Partial Content/i;
  const seenResp = new Set();

  function makeReadHandlers(secureTransport) {
    return {
      onEnter: function (args) {
        this.buf = args[1];
        this.got = secureTransport ? args[3] : null;
        this.st = secureTransport;
      },
      onLeave: function (retval) {
        if (this.buf.isNull()) return;
        let len;
        if (this.st) {
          if (retval.toInt32() !== 0 || this.got.isNull()) return;
          len = Number(this.got.readU64());       // size_t, guard the UInt64
        } else {
          len = retval.toInt32();                 // byte count, or <= 0
        }
        if (len < 16 || len > 200000) return;
        const n = len < 128 ? len : 128;
        const bytes = new Uint8Array(this.buf.readByteArray(n));
        let ok = true;
        for (let i = 0; i < 4 && i < n; i++) {
          const ch = bytes[i];
          if (ch < 0x20 || ch > 0x7e) { ok = false; break; }
        }
        if (!ok) return;
        let s = '';
        for (let i = 0; i < n; i++) {
          const ch = bytes[i];
          s += (ch >= 0x20 && ch <= 0x7e) ? String.fromCharCode(ch) : '.';
        }
        if (!RESP_START.test(s) || RESP_SKIP.test(s)) return;
        const isJson = s[0] === '{' || s[0] === '[';
        const line = isJson ? s.replace(/[\r\n]+/g, ' ').slice(0, 120)
                            : s.split('\r')[0].split('\n')[0].slice(0, 90);
        if (seenResp.has(line)) return;
        if (seenResp.size < 400) seenResp.add(line);
        emit('RESPONSE', (isJson ? 'JSON  ' : 'HTTP  ') + line, null);
      }
    };
  }

  eachExport('SSLRead').forEach(function (e) {
    probe('tls', e.addr, 60, 'TLS read (SSLRead in ' + e.mod + ')',
          makeReadHandlers(true));
  });
  eachExport('SSL_read').forEach(function (e) {
    probe('tls', e.addr, 60, 'TLS read (SSL_read in ' + e.mod + ')',
          makeReadHandlers(false));
  });

  // --- The resolver's answer, which carries this phone's public address ---
  // ByteDance runs its own resolver over HTTPS. Its reply names the addresses
  // for each host it was asked about, and echoes back the client IP it saw the
  // question arrive from. That last field is the one thing on this phone that
  // can state the public address: the OS offers no API for it, and with no
  // global IPv6 there is nothing routable on any interface to read.
  //
  // Registered in the net group rather than tls, because the net group is the
  // one that stays armed for a whole window, and an answer that arrives once
  // is not something a 600ms sample will catch.
  const seenResolverAnswer = new Set();

  function resolverScan(buf, len) {
    try {
      if (len < 12) return;
      const head = buf.readU8();
      const isJson = (head === 0x7b || head === 0x5b);
      if (!isJson && len > 64) return;      // neither JSON nor a bare address
      const n = len < 3072 ? len : 3072;
      const bytes = new Uint8Array(buf.readByteArray(n));
      let s = '';
      for (let i = 0; i < n; i++) {
        const ch = bytes[i];
        s += (ch >= 0x20 && ch <= 0x7e) ? String.fromCharCode(ch) : ' ';
      }
      // An echo endpoint answers with the address and nothing else. Catch it
      // here too, so a reply still counts even when the call that asked for it
      // reported failure.
      const bare = /^\s*(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]{6,45})\s*$/.exec(s.slice(0, 64));
      if (bare && !seenResolverAnswer.has('wan' + bare[1])) {
        seenResolverAnswer.add('wan' + bare[1]);
        emit('REACH_WAN', bare[1], 'seen in a reply, whatever asked for it');
      }
      if (s.indexOf('"cip"') < 0 && s.indexOf('"ips"') < 0) return;

      const cip = /"cip"\s*:\s*"([0-9a-fA-F:.]{3,45})"/.exec(s);
      if (cip && !seenResolverAnswer.has('cip' + cip[1])) {
        seenResolverAnswer.add('cip' + cip[1]);
        emit('PUBLIC_IP', cip[1], 'echoed back by the resolver it asked');
      }
      // records look like {"host":"x","ttl":n,"ips":["a","b"],...}
      const rec = /"host"\s*:\s*"([^"]{1,120})"[^}]*?"ips"\s*:\s*\[([^\]]{0,400})\]/g;
      let m, guard = 0;
      while ((m = rec.exec(s)) !== null && guard++ < 24) {
        const host = m[1];
        const ips = m[2].replace(/"/g, '').split(',');
        for (let i = 0; i < ips.length && i < 16; i++) {
          const a = ips[i].trim();
          if (!a) continue;
          const tag = host + '|' + a;
          if (seenResolverAnswer.has(tag)) continue;
          seenResolverAnswer.add(tag);
          emit('HTTPDNS', host, a);
        }
      }
    } catch (e) {}
  }

  function makeResolverHandlers(secureTransport) {
    return {
      onEnter: function (args) {
        this.buf = args[1];
        this.got = secureTransport ? args[3] : null;
        this.st = secureTransport;
      },
      onLeave: function (retval) {
        try {
          if (this.buf.isNull()) return;
          let len;
          if (this.st) {
            if (retval.toInt32() !== 0 || this.got.isNull()) return;
            len = Number(this.got.readU64());
          } else {
            len = retval.toInt32();
          }
          if (len > 0) resolverScan(this.buf, len);
        } catch (e) {}
      }
    };
  }

  eachExport('SSL_read').forEach(function (e) {
    probe('net', e.addr, 1500, 'resolver answers (SSL_read in ' + e.mod + ')',
          makeResolverHandlers(false));
  });
  eachExport('SSLRead').forEach(function (e) {
    probe('net', e.addr, 1500, 'resolver answers (SSLRead in ' + e.mod + ')',
          makeResolverHandlers(true));
  });

  // --- Explicit VPN and proxy checks (read-only) ---
  // The question was already recorded. The answer is the interesting half: a
  // proxy host and port here is the difference between "the app wondered" and
  // "something on this phone is standing between it and the network".
  const PROXY_KEYS = ['HTTPEnable', 'HTTPProxy', 'HTTPPort', 'HTTPSEnable',
                      'HTTPSProxy', 'HTTPSPort', 'SOCKSEnable', 'SOCKSProxy',
                      'SOCKSPort', 'ProxyAutoConfigEnable',
                      'ProxyAutoConfigURLString'];
  try {
    const proxy = Module.findGlobalExportByName('CFNetworkCopySystemProxySettings');
    if (proxy) {
      const proxyBudget = budget(64, 'proxy config reads');
      Interceptor.attach(proxy, {
        onEnter: function () { if (!_selfRead) emit('PROXY', 'proxy config', null); },
        onLeave: function (retval) {
          try {
            if (_selfRead || !proxyBudget() || retval.isNull()) return;
            const d = new ObjC.Object(retval);
            let set = 0;
            for (let i = 0; i < PROXY_KEYS.length; i++) {
              const k = PROXY_KEYS[i];
              const v = d.objectForKey_(k);
              if (v === null || v.handle.isNull()) continue;
              const s = String(v);
              if (s === '0') continue;            // the disabled default
              set++;
              emit('PROXY', 'proxy ' + k, s);
            }
            if (!set) emit('PROXY', 'proxy answer', 'no proxy configured');
          } catch (e) {}
        }
      });
    }
  } catch (e) {}

  try {
    const NEVPNManager = ObjC.classes.NEVPNManager;
    if (NEVPNManager && NEVPNManager['- connection']) {
      // NEVPNStatus: 0 invalid, 1 disconnected, 2 connecting, 3 connected,
      // 4 reasserting, 5 disconnecting. Only this app's own tunnel is visible
      // here, so 'invalid' is the normal answer and means "none configured".
      const VPN_STATUS = ['no VPN configured for this app', 'disconnected',
                          'connecting', 'connected', 'reasserting', 'disconnecting'];
      Interceptor.attach(NEVPNManager['- connection'].implementation, {
        onEnter: function () { emit('PROXY', 'VPN status', null); },
        onLeave: function (retval) {
          try {
            if (retval.isNull()) return;
            const st = new ObjC.Object(retval).status();
            emit('PROXY', 'VPN status answer', VPN_STATUS[st] || ('status ' + st));
          } catch (e) {}
        }
      });
    }
  } catch (e) {}

  // --- Outbound requests: what URLs TikTok hits (read-only) ---
  // dataTaskWithRequest: alone misses most traffic. Hooking -resume on the
  // concrete task classes catches every NSURLSession request regardless of
  // which factory method created it.
  try {
    const NSURLSession = ObjC.classes.NSURLSession;
    ['- dataTaskWithRequest:completionHandler:', '- dataTaskWithRequest:'].forEach(function (sel) {
      if (!NSURLSession || !NSURLSession[sel]) return;
      Interceptor.attach(NSURLSession[sel].implementation, {
        onEnter: function (args) {
          try { reportRequest(new ObjC.Object(args[2])); } catch (e) {}
        }
      });
    });
  } catch (e) { emit('ERROR', 'request-hook', String(e)); }

  try {
    // These three classes are a hierarchy, not three separate targets, and
    // -resume is implemented once and inherited. Frida resolves an inherited
    // selector to the SAME implementation address for each of them, so
    // attaching per class name attached three listeners to one function and
    // every request was reported three times: counts inflated 3x, and the
    // body budget spent at triple rate on identical copies.
    //
    // Dedupe on the address, which is the thing actually being hooked. The
    // class list stays as it is because which of them owns -resume differs by
    // iOS version, and the first one that resolves is the right one.
    const seenImpl = {};
    ['__NSCFLocalSessionTask', '__NSCFURLSessionTask', 'NSURLSessionTask'].forEach(function (cn) {
      const klass = ObjC.classes[cn];
      if (!klass || !klass['- resume']) return;
      const impl = klass['- resume'].implementation;
      const addr = String(impl);
      if (seenImpl[addr]) {
        emit('RIG', 'shared -resume implementation, hooked once',
             cn + ' inherits it from ' + seenImpl[addr]);
        return;
      }
      seenImpl[addr] = cn;
      Interceptor.attach(impl, {
        onEnter: function (args) {
          try {
            const task = new ObjC.Object(args[0]);
            if (task.originalRequest === undefined) return;
            const req = task.originalRequest();
            // truthiness, not isNull(). The bridge returns JS null for nil and
            // isNull() is not one of its builtins, so calling it here would
            // throw into the catch and silently disable the whole resume path.
            if (req) reportRequest(req);
          } catch (e) {}
        }
      });
    });
  } catch (e) {}

  // One request reaches this function twice by design: the factory hook sees it
  // being built and the -resume hook sees the task carrying it. Both hooks are
  // wanted, because either alone misses traffic, but counting the request once
  // per hook makes every REQUEST, HEADER and BODY number about twice the truth.
  //
  // Keyed on the request's own address, so two genuinely separate calls to the
  // same endpoint still count as two. The table is bounded rather than cleared
  // on a timer: clearing would let a request built just before a flush and
  // resumed just after it through as two, which is the exact case being fixed.
  const _reqSeen = {};
  let _reqSeenN = 0;

  function reportRequest(req) {
    try {
      let addr = null;
      try { addr = String(req.handle); } catch (e) {}
      if (addr) {
        if (_reqSeen[addr]) return;
        // An address can be reused once the original request is freed. Dropping
        // the whole table costs at most a few double counts and cannot grow.
        if (_reqSeenN > 4096) { for (const k in _reqSeen) delete _reqSeen[k]; _reqSeenN = 0; }
        _reqSeen[addr] = 1;
        _reqSeenN++;
      }
      const url = req.URL();
      if (!url || url.isNull()) return;
      // inline data: URLs are embedded images, not traffic, and have no host
      const scheme = url.scheme();
      if (!scheme || scheme.isNull()) return;
      const s = String(scheme).toLowerCase();
      if (s !== 'http' && s !== 'https') return;
      const h = url.host();
      if (!h || h.isNull()) return;
      const method = req.HTTPMethod ? String(req.HTTPMethod()) : 'GET';
      emit('REQUEST', String(h), method + ' ' + String(url.absoluteString()));

      // Header NAMES, not values. The names alone say a lot: ByteDance's
      // X-Argus / X-Gorgon / X-Khronos are its request-signing scheme, and a
      // Cookie header means stored state is riding along.
      try {
        const hdrs = req.allHTTPHeaderFields();
        if (hdrs && !hdrs.isNull()) {
          const keys = hdrs.allKeys();
          const n = keys.count();
          for (let i = 0; i < n && i < 40; i++) {
            emit('HEADER', String(keys.objectAtIndex_(i)), null);
          }
        }
      } catch (e) {}

      // A short preview of the body, enough to tell JSON from protobuf from an
      // encrypted blob, and then the whole thing on the side.
      try {
        const body = req.HTTPBody();
        if (body && !body.isNull()) {
          const len = body.length();
          let head = '';
          try {
            const s = ObjC.classes.NSString.alloc()
              .initWithData_encoding_(body, 4);   // NSUTF8StringEncoding
            if (s && !s.isNull()) head = String(s).slice(0, 100);
          } catch (e) {}
          emit('BODY', String(h),
               len + ' bytes' + (head ? ', starts: ' + head.replace(/\s+/g, ' ') : ''));
          // The publish call is where the metadata TikTok kept becomes visible
          // again, and a 100 character preview shows the opening brace and
          // nothing else. Bodies ride beside the batch, base64 so a protobuf or
          // an encrypted payload survives the trip intact, and the driver
          // writes them out. emit() cannot carry these: it is keyed by string,
          // so a body would either be truncated or blow the distinct ceiling.
          if (len > 0 && len <= MAX_BLOB) {
            try {
              const b64 = String(body.base64EncodedStringWithOptions_(0));
              captureBlob(String(h) + ' ' +
                          (req.HTTPMethod ? String(req.HTTPMethod()) : 'POST') +
                          ' ' + String(url.path()), b64, len);
            } catch (e) {}
          } else if (len > MAX_BLOB) {
            emit('BODY', String(h), 'body too large to capture, ' + len + ' bytes');
          }
        }
      } catch (e) {}
    } catch (e) {}
  }

  // --- The publish path: what a post hands over (read-only) ---
  // Posting is the one flow that gives TikTok a file off your phone, and the
  // interesting question is not the upload, it is what rode along inside it. A
  // video carries a creation timestamp, a camera model and frequently GPS in
  // its metadata container, and none of that needs a permission prompt once the
  // file is in the app's hands. A geotag lifted out of a file is a location
  // read that CLLocationManager never sees, which is why "no location calls"
  // was never the same as "no location".
  //
  // Five questions, in the order they arise during a post:
  //   1. which picker opened. The modern out-of-process one needs no permission
  //      and grants no library access, the legacy in-process one does both, and
  //      telling them apart is what makes a silent photo-library section read
  //      as a coherent story rather than a hole in the audit.
  //   2. whether the camera and mic were actually switched on, as opposed to
  //      merely asked about, which is all the PERMS hooks can tell you.
  //   3. whether anything opened the metadata container, and if so whether a
  //      GPS block was in it.
  //   4. what got encoded.
  //   5. the shape of the upload: where to, how big, from a file or from memory.
  //
  // All of it is app-logic rate. A picker opens once, a capture session starts
  // once, an upload task is created once. The ones that could in principle run
  // hotter are the asset constructor, the PHAsset property reads and the image
  // metadata reads, because a media grid or a video feed touches those per
  // item, so those three are budgeted. If a run is ever killed after this block
  // lands, measure those three first.
  // Attached vs asked for. The $ownMethods guard below is strict on purpose, and
  // a strict guard that quietly matches nothing looks exactly like an app that
  // never posted. One line at load says which it was.
  let mediaWanted = 0, mediaGot = 0;
  const mediaMissed = [];
  function mediaHook(cls, sel, handlers) {
    mediaWanted++;
    let why;
    try {
      const k = ObjC.classes[cls];
      // Only hook a selector the class implements ITSELF. Frida happily
      // resolves inherited methods, so asking UIImagePickerController for
      // '- init' hands back NSObject's implementation, and hooking that traps
      // every object the app ever allocates. That is the freeze class, reached
      // from one careless line.
      if (!k) why = 'class not present on this build';
      else if (k.$ownMethods.indexOf(sel) === -1) why = 'not implemented by this class';
      else if (!k[sel]) why = 'selector did not resolve';
      else {
        Interceptor.attach(k[sel].implementation, handlers);
        mediaGot++;
        return true;
      }
    } catch (e) { why = 'attach threw: ' + e; }
    // Naming the miss is the whole point. A hook that never attached and a
    // mechanism the app never used produce identical silence, and only one of
    // them is a finding about TikTok.
    mediaMissed.push(cls + ' ' + sel + ' (' + why + ')');
    return false;
  }

  // --- The tag inventory -------------------------------------------------
  // MEDIA_META above is a narrative: it says a GPS block was opened. MEDIA_TAG
  // below is the inventory: it says GPSLatitudeRef was N. The first tells you
  // TikTok went looking, the second is what you need to stamp a file and check
  // your work, and neither substitutes for the other.
  //
  // VALUES are recorded here, which is a deliberate departure from the rest of
  // this file. Everywhere else only key names are kept, because the values are
  // the user's private data and the finding is that the app asked. On the post
  // path the value IS the finding: "Model" tells you nothing, "Model = iPhone X"
  // is the whole point. Scope is the safeguard, so this stays limited to media
  // provenance containers and never widens to the rest of the report.
  var TAG_VALUES = true;

  // NOTE ON nil. The bridge hands back JS null for a nil id, and isNull() is
  // NOT one of the builtins it defines on a wrapped object, so calling it on a
  // live object throws and the throw is swallowed by the surrounding catch. The
  // failure mode is silent and looks exactly like "the field was not there", so
  // everything below tests truthiness. isNull() is used only on raw pointers,
  // which is where it is real: interceptor return values and NativeFunction
  // results.
  function tagValue(v) {
    if (!TAG_VALUES) return null;
    try {
      if (v === null || typeof v === 'undefined') return null;
      var o = v;
      var cls = String(o.$className);
      // binary blobs are the common case in {MakerApple} and are never readable.
      // Their SIZE is still a fingerprint, so it is kept.
      if (cls.indexOf('NSData') !== -1 || cls.indexOf('NSConcreteData') !== -1) {
        try { return '(' + o.length() + ' bytes of data)'; } catch (e) { return '(data)'; }
      }
      var s = String(o).replace(/\s+/g, ' ').trim();
      if (s.length > 72) return s.slice(0, 69) + '...';
      return s.length ? s : null;
    } catch (e) { return null; }
  }

  // A CGImageProperties dictionary nests one level: top-level keys are geometry
  // and colour, and anything wrapped in braces is a container of its own. The
  // deep walk is gated because a feed decodes hundreds of images that carry no
  // provenance at all, and walking those is pure cost for a guaranteed empty
  // result. A file with a {TIFF} or {Exif} or {GPS} in it is a photo somebody
  // took, and that is the only kind worth opening.
  // Looked up with === 1, never for truthiness. A bare object inherits
  // Object.prototype, so a key called 'constructor' or 'toString' would come
  // back as a function and read as true.
  var DEEP_BLOCKS = { '{TIFF}': 1, '{Exif}': 1, '{GPS}': 1, '{IPTC}': 1,
                      '{MakerApple}': 1, '{ExifAux}': 1, '{XMP}': 1, '{DNG}': 1,
                      '{Photoshop}': 1, '{HEICS}': 1 };

  function walkImageTags(dict, container) {
    try {
      var keys = dict.allKeys();
      var n = keys.count();
      if (n > 96) n = 96;
      var names = [], raw = [];
      for (var i = 0; i < n; i++) {
        var kobj = keys.objectAtIndex_(i);
        raw.push(kobj);
        names.push(String(kobj));
      }
      // one cheap pass decides whether this file deserves the expensive one
      var deep = false;
      for (var d = 0; d < names.length; d++) {
        if (DEEP_BLOCKS[names[d]] === 1) { deep = true; break; }
      }
      for (var j = 0; j < names.length; j++) {
        var k = names[j];
        var val = null;
        try { val = dict.objectForKey_(raw[j]); } catch (e) {}
        if (k.charAt(0) === '{') {
          emit('MEDIA_TAG', container + ' ' + k, deep && DEEP_BLOCKS[k] === 1
               ? '(block, opened below)' : '(block, not opened)');
          if (!deep || DEEP_BLOCKS[k] !== 1 || !val) continue;
          try {
            var sub = val;
            if (!sub.allKeys) continue;
            var sk = sub.allKeys(), sn = sk.count();
            if (sn > 80) sn = 80;
            for (var m = 0; m < sn; m++) {
              var fk = sk.objectAtIndex_(m);
              emit('MEDIA_TAG', container + ' ' + k + ' ' + String(fk),
                   tagValue(sub.objectForKey_(fk)));
            }
          } catch (e) {}
        } else {
          emit('MEDIA_TAG', container + ' ' + k, tagValue(val));
        }
      }
    } catch (e) {}
  }

  // AVMetadataItem the way it should have been read the first time. commonKey
  // only resolves the handful of fields AVFoundation normalises across formats,
  // and everything an iPhone actually writes lives outside that set under
  // com.apple.quicktime.*, which is why 38 reads last run came back as
  // "format-specific field, no common key" and told us nothing.
  function walkAVTags(arr, container) {
    // nil comes back as JS null, and an absent metadata array is a real result
    // worth recording rather than a reason to fall through the catch in silence.
    if (!arr) {
      emit('MEDIA_TAG', container + ' (absent)', 'no metadata array at all');
      return;
    }
    try {
      var n = arr.count();
      if (n > 80) n = 80;
      for (var i = 0; i < n; i++) {
        var it = arr.objectAtIndex_(i);
        var name = null;
        // identifier is the fully qualified form, 'mdta/com.apple.quicktime.make'
        try {
          var id = it.identifier();
          if (id) name = String(id);
        } catch (e) {}
        if (!name) {
          var ks = null, kk = null;
          try { var x = it.keySpace(); if (x) ks = String(x); } catch (e) {}
          try {
            var y = it.key();
            if (y) kk = String(y);
          } catch (e) {}
          name = (ks ? ks + '/' : '') + (kk || 'unnamed field');
        }
        var val = null;
        try { val = tagValue(it.value()); } catch (e) {}
        emit('MEDIA_TAG', container + ' ' + name, val);
      }
      if (n === 0) emit('MEDIA_TAG', container + ' (empty)', 'no metadata in this container');
    } catch (e) {}
  }

  // 1. which picker. PHPicker runs in a separate process: no prompt, no library
  // access, the chosen file arrives already copied into the app's sandbox.
  mediaHook('PHPickerViewController', '- initWithConfiguration:', {
    onEnter: function () {
      emit('MEDIA', 'system photo picker', 'opened, runs outside the app, no permission needed');
    }
  });
  // the legacy in-process one, which does need permission and does hand over
  // library access. sourceType says whether it opened the camera or the library.
  const PICKER_SRC = ['photo library', 'camera', 'saved photos album'];
  mediaHook('UIImagePickerController', '- setSourceType:', {
    onEnter: function (args) {
      let t = -1;
      try { t = Number(args[2].toInt32()); } catch (e) {}
      emit('MEDIA', 'in-app camera or picker', PICKER_SRC[t] || ('source ' + t));
    }
  });

  // 2. camera and mic actually running. AVCaptureDevice authorizationStatus,
  // already hooked above, only says it ASKED. This says it opened the device.
  mediaHook('AVCaptureSession', '- startRunning', {
    onEnter: function () { emit('MEDIA', 'capture session', 'started, camera or mic is live'); }
  });
  mediaHook('AVCaptureSession', '- addInput:', {
    onEnter: function (args) {
      try {
        const inp = new ObjC.Object(args[2]);
        if (inp.device === undefined) return;
        const dev = inp.device();
        if (!dev || dev.isNull()) return;
        emit('MEDIA', 'capture device opened', String(dev.localizedName()));
      } catch (e) {}
    }
  });
  // the audio session category is the quieter half of the same question: an app
  // cannot record without putting the session into a Record category first.
  // Playback categories are the common case during a feed, so they are filtered
  // out here rather than emitted and sorted out later.
  const audioCatBudget = budget(4000, 'audio session category sets');
  ['- setCategory:error:', '- setCategory:withOptions:error:',
   '- setCategory:mode:options:error:'].forEach(function (sel) {
    mediaHook('AVAudioSession', sel, {
      onEnter: function (args) {
        if (!audioCatBudget()) return;
        try {
          const cat = String(new ObjC.Object(args[2]));
          if (cat.indexOf('Record') === -1) return;
          emit('MEDIA', 'audio session set to record',
               cat.replace('AVAudioSessionCategory', ''));
        } catch (e) {}
      }
    });
  });
  mediaHook('AVAudioSession', '- recordPermission', {
    onLeave: function () { emit('MEDIA', 'microphone permission', 'checked'); }
  });

  // 3. the metadata container. This is the geotag question, and it is the one
  // thing here that answers it, because a coordinate read out of a file never
  // touches CLLocationManager and never prompts.
  ['CGImageSourceCopyPropertiesAtIndex', 'CGImageSourceCopyProperties'].forEach(
    function (nm) {
      const p = dangerousExport(nm);
      if (!p) return;
      const b = budget(400, 'image metadata reads (' + nm + ')');
      const tb = budget(140, 'image tag inventory (' + nm + ')');
      Interceptor.attach(p, {
        onLeave: function (ret) {
          try {
            if (ret.isNull()) return;
            // our own introspection calls this too. Logging those would report
            // our curiosity as the app's behaviour.
            if (_selfRead) return;
            // Counting is a map increment and stays UNBUDGETED, because a count
            // that stops at the budget prints as an exact number and is read as
            // one. Only the dictionary walk below is expensive, so only the walk
            // is capped.
            emit('MEDIA_META', 'image metadata block', 'opened via ' + nm);
            if (!b()) return;
            // CFDictionary is toll-free bridged to NSDictionary, so the keys
            // read without a copy.
            const d = new ObjC.Object(ret);
            // the full inventory, field by field, on its own tighter budget
            if (tb()) walkImageTags(d, 'image');
            const keys = d.allKeys();
            const n = keys.count();
            for (let i = 0; i < n && i < 40; i++) {
              const k = String(keys.objectAtIndex_(i));
              if (k.indexOf('GPS') !== -1) {
                emit('MEDIA_META', 'GPS block read out of the file',
                     'a location read that needs no permission');
              } else if (k.indexOf('Exif') !== -1) {
                emit('MEDIA_META', 'EXIF block', 'capture time and camera settings');
              } else if (k.indexOf('TIFF') !== -1) {
                emit('MEDIA_META', 'TIFF block', 'camera make and model');
              } else {
                // everything else in one row, with the field name as the value.
                // This is what separates a decoder reading pixel geometry from
                // something going through a photo's provenance, and without it
                // the panel shows three flagged rows and hides the context that
                // makes them ordinary.
                emit('MEDIA_META', 'other metadata fields', k);
              }
            }
          } catch (e) {}
        }
      });
    });

  // the video-side equivalent. AVMetadataItem commonKey 'location' is exactly
  // the QuickTime geotag an iPhone writes into every video it records.
  const assetMetaBudget = budget(300, 'video metadata reads');
  const avTagBudget = budget(120, 'video tag inventory');
  ['AVAsset', 'AVURLAsset'].forEach(function (cls) {
    ['- commonMetadata', '- metadata'].forEach(function (sel) {
      mediaHook(cls, sel, {
        onLeave: function (ret) {
          try {
            if (ret.isNull()) return;
            if (_selfRead) return;
            emit('MEDIA_META', 'video metadata block', 'read from the file');
            if (!assetMetaBudget()) return;
            const arr = new ObjC.Object(ret);
            // the inventory, with real key names instead of the commonKey
            // placeholder that discarded 38 fields last run
            if (avTagBudget()) walkAVTags(arr, 'video ' + sel.slice(2));
            const n = arr.count();
            for (let i = 0; i < n && i < 40; i++) {
              const it = arr.objectAtIndex_(i);
              let ck = null;
              try {
                const c = it.commonKey();
                if (c && !c.isNull()) ck = String(c);
              } catch (e) {}
              if (ck === 'location') {
                emit('MEDIA_META', 'geotag inside the video',
                     'a location read that needs no permission');
              } else if (ck === 'creationDate' || ck === 'make' || ck === 'model') {
                emit('MEDIA_META', 'video ' + ck, 'read from the file');
              } else if (ck) {
                emit('MEDIA_META', 'other video metadata fields', ck);
              } else {
                // an item with no common key is format-specific, and an empty
                // metadata array is the most common outcome of all. Recording
                // it is what separates "read nothing" from "was never read".
                emit('MEDIA_META', 'other video metadata fields',
                     'format-specific field, no common key');
              }
            }
            if (n === 0) {
              emit('MEDIA_META', 'video metadata came back empty',
                   'the file carried no metadata to read');
            }
          } catch (e) {}
        }
      });
    });
  });
  // and the library-side copy of the same facts, which PHAsset hands over
  // without opening the file at all
  const phAssetBudget = budget(1200, 'photo library asset reads');
  [['- location', 'library geotag on the chosen item'],
   ['- creationDate', 'when the chosen item was shot'],
   ['- modificationDate', 'when the chosen item was last edited'],
   ['- localIdentifier', 'stable library ID of the chosen item']].forEach(function (pair) {
    mediaHook('PHAsset', pair[0], {
      onLeave: function (ret) {
        if (ret.isNull()) return;
        if (_selfRead) return;
        if (!phAssetBudget()) return;
        emit('MEDIA_META', pair[1], 'read');
      }
    });
  });
  // localIdentifier is declared on PHObject, not PHAsset, which is why the
  // strict $ownMethods guard reported it unattached every run so far.
  mediaHook('PHObject', '- localIdentifier', {
    onLeave: function (ret) {
      if (ret.isNull() || _selfRead) return;
      if (!phAssetBudget()) return;
      emit('MEDIA_META', 'stable library ID of the chosen item', 'read');
    }
  });

  // The library's own opinion of what this item IS, which is a different claim
  // from anything in the file and cannot be written by stamping one. sourceType
  // separates something the camera produced from something synced or shared in,
  // and mediaSubtypes carries the Live Photo, screenshot and HDR flags. Both are
  // plain integers, so the values are recorded: the whole question on the post
  // path is which value came back, not that the property was touched.
  const PH_SOURCE = { 0: 'none', 1: 'user library', 2: 'cloud shared',
                      4: 'iTunes synced' };
  const PH_SUBTYPE = [[1, 'panorama'], [2, 'HDR'], [4, 'screenshot'],
                      [8, 'LIVE PHOTO'], [16, 'depth effect'],
                      [65536, 'streamed video'], [131072, 'high frame rate'],
                      [262144, 'timelapse'], [2097152, 'cinematic']];
  mediaHook('PHAsset', '- sourceType', {
    onLeave: function (ret) {
      if (_selfRead || !phAssetBudget()) return;
      let v = -1;
      try { v = ret.toUInt32(); } catch (e) { return; }
      emit('MEDIA_TAG', 'library sourceType', PH_SOURCE[v] || ('value ' + v));
    }
  });
  mediaHook('PHAsset', '- mediaSubtypes', {
    onLeave: function (ret) {
      if (_selfRead || !phAssetBudget()) return;
      let v = 0;
      try { v = ret.toUInt32(); } catch (e) { return; }
      if (v === 0) { emit('MEDIA_TAG', 'library mediaSubtypes', 'none'); return; }
      PH_SUBTYPE.forEach(function (s) {
        if (v & s[0]) emit('MEDIA_TAG', 'library mediaSubtypes', s[1]);
      });
    }
  });
  [['- pixelWidth', 'library pixelWidth'],
   ['- pixelHeight', 'library pixelHeight'],
   ['- burstIdentifier', 'library burstIdentifier'],
   ['- playbackStyle', 'library playbackStyle']].forEach(function (pair) {
    mediaHook('PHAsset', pair[0], {
      onLeave: function (ret) {
        if (_selfRead || !phAssetBudget()) return;
        let v = null;
        // the two integer properties come back in the return register, the
        // object one comes back as a pointer. Telling them apart by trying the
        // cheap read first keeps this one hook shape for all four.
        try {
          v = pair[0].indexOf('Identifier') !== -1
            ? (ret.isNull() ? 'absent' : String(new ObjC.Object(ret)))
            : String(ret.toUInt32());
        } catch (e) { return; }
        emit('MEDIA_TAG', pair[1], v);
      }
    });
  });

  // The resource behind the asset. originalFilename is the cheapest native
  // capture tell there is: a camera writes IMG_0042.HEIC and a pipeline writes
  // whatever it was told to.
  [['- originalFilename', 'resource originalFilename'],
   ['- uniformTypeIdentifier', 'resource uniformTypeIdentifier']].forEach(function (pair) {
    mediaHook('PHAssetResource', pair[0], {
      onLeave: function (ret) {
        if (ret.isNull() || _selfRead) return;
        if (!phAssetBudget()) return;
        try { emit('MEDIA_TAG', pair[1], String(new ObjC.Object(ret))); } catch (e) {}
      }
    });
  });

  // 4. what got encoded. TikTok is more likely to drive VideoToolbox directly
  // than to go through AVAssetWriter, so both are covered. Each fires once per
  // export, which is why neither needs a budget.
  mediaHook('AVAssetWriter', '- startWriting', {
    onEnter: function () { emit('MEDIA', 'video encode started', 'AVAssetWriter'); }
  });
  mediaHook('AVAssetExportSession', '- exportAsynchronouslyWithCompletionHandler:', {
    onEnter: function () { emit('MEDIA', 'video export started', 'AVAssetExportSession'); }
  });
  try {
    const vt = dangerousExport('VTCompressionSessionCreate');
    if (vt) {
      const b = budget(50, 'hardware encoder sessions');
      Interceptor.attach(vt, {
        onEnter: function () {
          if (b()) emit('MEDIA', 'hardware video encoder', 'compression session created');
        }
      });
    }
  } catch (e) {}

  // 3b. XMP, which is a container of its own and not part of the EXIF
  // dictionary the hook above walks. Provenance, editing history and the
  // Content Credentials manifest all live here, so a run that never sees this
  // called cannot say anything about whether TikTok looks for them.
  try {
    const mdAt = dangerousExport('CGImageSourceCopyMetadataAtIndex');
    if (mdAt) {
      const xb = budget(60, 'XMP metadata reads');
      const copyTags = dangerousExport('CGImageMetadataCopyTags');
      const tagName = dangerousExport('CGImageMetadataTagCopyName');
      const tagPrefix = dangerousExport('CGImageMetadataTagCopyPrefix');
      const fn = function (p) {
        try { return p ? new NativeFunction(p, 'pointer', ['pointer']) : null; }
        catch (e) { return null; }
      };
      const fTags = fn(copyTags), fName = fn(tagName), fPrefix = fn(tagPrefix);
      Interceptor.attach(mdAt, {
        onLeave: function (ret) {
          try {
            if (ret.isNull() || _selfRead) return;
            emit('MEDIA_META', 'XMP metadata block', 'opened out of the file');
            if (!xb() || !fTags) return;
            // CopyTags hands back a +1 CFArray we deliberately never release.
            // A handful of small leaked arrays per run is free, and an
            // over-release in a read-only observer would crash the app we are
            // trying to watch behave normally.
            const tags = fTags(ret);
            if (tags.isNull()) return;
            const arr = new ObjC.Object(tags);
            let n = arr.count();
            if (n > 80) n = 80;
            for (let i = 0; i < n; i++) {
              // .handle, not the wrapper. A CGImageMetadataTagRef arrives from
              // the array as a bridged object, and a NativeFunction declared
              // 'pointer' wants the raw address. Passing the wrapper is the
              // quiet kind of wrong: it does not throw here, it reads a
              // different address inside CoreGraphics.
              const t = arr.objectAtIndex_(i).handle;
              let pfx = '', nm = '?';
              try {
                if (fPrefix) {
                  const p = fPrefix(t);
                  if (!p.isNull()) pfx = String(new ObjC.Object(p)) + ':';
                }
              } catch (e) {}
              try {
                if (fName) {
                  const q = fName(t);
                  if (!q.isNull()) nm = String(new ObjC.Object(q));
                }
              } catch (e) {}
              emit('MEDIA_TAG', 'XMP ' + pfx + nm, null);
            }
            if (n === 0) emit('MEDIA_TAG', 'XMP (empty)', 'no XMP tags in this file');
          } catch (e) {}
        }
      });
    }
  } catch (e) {}

  // 3c. the codec, which no metadata field carries and which separates an
  // iPhone capture from a pipeline export as reliably as any EXIF string.
  try {
    const gst = Module.findGlobalExportByName('CMFormatDescriptionGetMediaSubType');
    const fSub = gst ? new NativeFunction(gst, 'uint32', ['pointer']) : null;
    const fourcc = function (v) {
      let s = '';
      for (let i = 3; i >= 0; i--) {
        const c = (v >> (i * 8)) & 0xff;
        s += (c >= 0x20 && c <= 0x7e) ? String.fromCharCode(c) : '.';
      }
      return s;
    };
    const fdBudget = budget(60, 'track format description reads');
    mediaHook('AVAssetTrack', '- formatDescriptions', {
      onLeave: function (ret) {
        try {
          if (ret.isNull() || _selfRead || !fSub) return;
          if (!fdBudget()) return;
          const arr = new ObjC.Object(ret);
          let n = arr.count();
          if (n > 8) n = 8;
          for (let i = 0; i < n; i++) {
            // raw address, same reason as the XMP tag walk above
            emit('MEDIA_TAG', 'track codec',
                 fourcc(fSub(arr.objectAtIndex_(i).handle)));
          }
        } catch (e) {}
      }
    });
  } catch (e) {}

  // 3d. the two file URLs that bracket the whole post: what TikTok opened and
  // what its encoder produced. Neither is parsed here. Parsing a media file
  // takes tens of milliseconds and this is the app's own thread inside an
  // interceptor, which is exactly the wall-clock cost that gets a process
  // killed. The paths go on a queue and the flush timer does the work.
  ['- initWithURL:options:'].forEach(function (sel) {
    mediaHook('AVURLAsset', sel, {
      onEnter: function (args) {
        try {
          if (_selfRead) return;
          const u = new ObjC.Object(args[2]);
          if (!u.isFileURL || !u.isFileURL()) return;
          const p = String(u.path());
          emit('MEDIA', 'opened a media file', String(u.lastPathComponent()));
          queueFile(p, 'INPUT');
        } catch (e) {}
      }
    });
  });
  // 3c-bis. The timed-metadata tracks. A recording carries three mebx tracks
  // alongside the picture and sound, spanning the whole duration, and they
  // declare com.apple.quicktime.detected-face with per-frame bounds, a
  // face-id, and roll and yaw angles. None of that reaches AVAsset.metadata,
  // which is why the clip table looks so much thinner than the photo one: the
  // container carries six atoms and the tracks carry the rest.
  //
  // Reading those samples needs an AVAssetReader over the metadata track, or
  // AVPlayerItemMetadataOutput. Hooking the moment either is pointed at a
  // metadata track answers whether TikTok goes looking, without paying the
  // cost of following every sample buffer.
  ['AVAsset', 'AVURLAsset'].forEach(function (cls) {
    mediaHook(cls, '- tracksWithMediaType:', {
      onEnter: function (args) {
        try {
          if (_selfRead) return;
          this._mt = String(new ObjC.Object(args[2]));
        } catch (e) {}
      },
      onLeave: function (ret) {
        try {
          if (_selfRead || !this._mt) return;
          // 'mebx' is the sample format; the media type of those tracks is
          // 'meta'. Asking for it at all is the signal worth recording.
          if (this._mt !== 'meta' && this._mt !== 'mebx') return;
          let n = 0;
          try { n = new ObjC.Object(ret).count(); } catch (e) {}
          emit('MEDIA', 'asked for the timed-metadata tracks',
               this._mt + ', ' + n + ' returned');
        } catch (e) {}
      }
    });
  });
  mediaHook('AVAssetReaderTrackOutput', '- initWithTrack:outputSettings:', {
    onEnter: function (args) {
      try {
        if (_selfRead) return;
        const track = new ObjC.Object(args[2]);
        const mt = String(track.mediaType());
        emit('MEDIA', 'built a sample reader over a track', mt);
        if (mt === 'meta' || mt === 'mebx') {
          emit('MEDIA_TAG', 'reading timed metadata samples',
               'per-frame track, this is where detected-face lives');
        }
      } catch (e) {}
    }
  });
  ['- initWithIdentifiers:'].forEach(function (sel) {
    mediaHook('AVPlayerItemMetadataOutput', sel, {
      onEnter: function (args) {
        try {
          if (_selfRead) return;
          let ids = '(all identifiers)';
          try {
            const a = new ObjC.Object(args[2]);
            if (!a.isNull || !a.isNull()) ids = String(a);
          } catch (e) {}
          emit('MEDIA_TAG', 'subscribed to timed metadata', ids.slice(0, 120));
        } catch (e) {}
      }
    });
  });

  ['AVAssetExportSession', 'AVAssetWriter'].forEach(function (cls) {
    mediaHook(cls, '- setOutputURL:', {
      onEnter: function (args) {
        try {
          if (_selfRead) return;
          const u = new ObjC.Object(args[2]);
          if (!u.path) return;
          const p = String(u.path());
          emit('MEDIA', 'encoder output file', String(u.lastPathComponent()));
          // queued, but the encoder has not written it yet. The flush drain
          // skips zero-length files and retries them on a later tick.
          queueFile(p, 'OUTPUT');
        } catch (e) {}
      }
    });
  });
  mediaHook('AVAssetWriter', '- initWithURL:fileType:error:', {
    onEnter: function (args) {
      try {
        if (_selfRead) return;
        const u = new ObjC.Object(args[2]);
        if (!u.path) return;
        emit('MEDIA', 'encoder output file', String(u.lastPathComponent()));
        queueFile(String(u.path()), 'OUTPUT');
      } catch (e) {}
    }
  });

  // 3e. what TikTok WRITES into its own re-encode. If any harvested field is
  // propagated into the file it uploads, this is where it happens, and an empty
  // result here is itself the answer to whether provenance survives the export.
  ['AVAssetExportSession', 'AVAssetWriter'].forEach(function (cls) {
    mediaHook(cls, '- setMetadata:', {
      onEnter: function (args) {
        try {
          if (_selfRead) return;
          const arr = new ObjC.Object(args[2]);
          if (!arr || !arr.count) return;
          walkAVTags(arr, 'written into the export');
        } catch (e) {}
      }
    });
  });

  // 3f. the sandbox copy's own attributes: size and dates that no metadata
  // field carries. Filtered to media extensions because an app stats hundreds
  // of files it never uploads.
  const MEDIA_EXT = /\.(mov|mp4|m4v|heic|heif|jpg|jpeg|png|webp|gif|aae|avci)$/i;
  const attrBudget = budget(120, 'media file attribute reads');
  mediaHook('NSFileManager', '- attributesOfItemAtPath:error:', {
    onEnter: function (args) {
      this._p = null;
      try {
        if (_selfRead) return;
        const p = String(new ObjC.Object(args[2]));
        if (MEDIA_EXT.test(p)) this._p = p;
      } catch (e) {}
    },
    onLeave: function (ret) {
      try {
        if (!this._p || ret.isNull() || !attrBudget()) return;
        const d = new ObjC.Object(ret);
        const name = this._p.split('/').pop();
        try {
          emit('MEDIA_TAG', 'file size', String(d.objectForKey_('NSFileSize')) +
               ' bytes (' + name + ')');
        } catch (e) {}
        ['NSFileCreationDate', 'NSFileModificationDate'].forEach(function (k) {
          try {
            const v = d.objectForKey_(k);
            if (v && !v.isNull()) {
              emit('MEDIA_TAG', 'file ' + k.replace('NSFile', ''), String(v));
            }
          } catch (e) {}
        });
      } catch (e) {}
    }
  });

  // 5. the upload itself. The -resume hook above already sees these, but it
  // reports them as ordinary requests. Catching the constructor is what tells
  // an upload apart from a fetch, and it is the only place the payload size is
  // visible before the bytes go into the socket.
  ['- uploadTaskWithRequest:fromData:', '- uploadTaskWithRequest:fromFile:',
   '- uploadTaskWithRequest:fromData:completionHandler:',
   '- uploadTaskWithRequest:fromFile:completionHandler:',
   '- uploadTaskWithStreamedRequest:'].forEach(function (sel) {
    mediaHook('NSURLSession', sel, {
      onEnter: function (args) {
        try {
          const req = new ObjC.Object(args[2]);
          let host = 'unknown host';
          try {
            // truthiness, not isNull(). See the nil note by tagValue: the
            // bridge returns JS null for nil and isNull() is not one of its
            // builtins, so it only resolves when something in the process has
            // added an -isNull category. Depending on that is depending on
            // another SDK's implementation detail.
            const u = req.URL();
            if (u) {
              const h = u.host();
              if (h) host = String(h);
            }
          } catch (e) {}
          let what = 'streamed body, size not known yet';
          if (sel.indexOf('fromData:') !== -1) {
            try { what = new ObjC.Object(args[3]).length() + ' bytes from memory'; } catch (e) {}
          } else if (sel.indexOf('fromFile:') !== -1) {
            try {
              const f = new ObjC.Object(args[3]);
              what = 'file ' + String(f.lastPathComponent());
              // the actual artifact leaving the phone. Queued, not parsed here.
              if (f.path) queueFile(String(f.path()), 'UPLOADED');
            } catch (e) {}
          }
          emit('MEDIA', 'upload to ' + host, what);
          reportRequest(req);
        } catch (e) {}
      }
    });
  });

  // --- The file drain ----------------------------------------------------
  // The one place in this file that reads a file rather than watching the app
  // read one. It answers the question no interceptor can: not "which fields did
  // TikTok ask for" but "which fields were there to be asked for", and on the
  // OUTPUT side, "which of them survived the re-encode". Those two dumps
  // bracket the post, and the difference between them is the finding.
  //
  // It runs on the flush timer, never on an app thread, and it sets _selfRead
  // so the hooks above ignore everything it does.
  const IMG_EXT = /\.(heic|heif|jpg|jpeg|png|webp|gif|avci|tiff?)$/i;
  // An encoder registers its output URL before it writes a byte, and then the
  // file grows for as long as the export takes. Parsing on first sight would
  // read a truncated container and report an empty or wrong tag set, which is
  // indistinguishable from a real finding. So a file is only parsed once its
  // size has stopped changing between two ticks.
  const DRAIN_RETRIES = 30;      // 30 ticks at 400ms, so about 12 seconds
  _drainFiles = function () {
    if (!_pendingFiles.length) return;
    const job = _pendingFiles.shift();
    const path = job[0], label = job[1];
    const tries = job[2] + 1;
    const lastSize = job[3] || -1;
    _selfRead = true;
    const t0 = Date.now();
    try {
      // JS strings convert to NSString at the bridge, so no manual marshalling.
      const fm = ObjC.classes.NSFileManager.defaultManager();
      let size = 0;
      try {
        const a = fm.attributesOfItemAtPath_error_(path, NULL);
        if (a) size = Number(a.objectForKey_('NSFileSize')) || 0;
      } catch (e) {}
      if (size === 0 || size !== lastSize) {
        // not there yet, or still being written. Requeue with what we saw.
        if (tries < DRAIN_RETRIES) _pendingFiles.push([path, label, tries, size]);
        else emit('MEDIA_FILE', label + ' never settled',
                  path.split('/').pop() + ', still changing after ' +
                  DRAIN_RETRIES + ' checks');
        return;
      }
      const name = path.split('/').pop();
      emit('MEDIA_FILE', label, name + ', ' + size + ' bytes');

      const url = ObjC.classes.NSURL.fileURLWithPath_(path);
      if (IMG_EXT.test(path)) {
        const mk = dangerousExport('CGImageSourceCreateWithURL');
        const cp = dangerousExport('CGImageSourceCopyPropertiesAtIndex');
        if (mk && cp) {
          const fMk = new NativeFunction(mk, 'pointer', ['pointer', 'pointer']);
          const fCp = new NativeFunction(cp, 'pointer',
                                         ['pointer', 'size_t', 'pointer']);
          const src = fMk(url.handle, NULL);
          if (!src.isNull()) {
            const props = fCp(src, 0, NULL);
            if (!props.isNull()) walkImageTags(new ObjC.Object(props), label);
          }
        }
      } else {
        const asset = ObjC.classes.AVURLAsset.URLAssetWithURL_options_(url, NULL);
        if (asset) {
          walkAVTags(asset.commonMetadata(), label + ' common');
          walkAVTags(asset.metadata(), label + ' format');
          try {
            const fmts = asset.availableMetadataFormats();
            const nf = fmts.count();
            for (let i = 0; i < nf; i++) {
              const f = fmts.objectAtIndex_(i);
              walkAVTags(asset.metadataForFormat_(f), label + ' ' + String(f));
            }
          } catch (e) {}
        }
      }
    } catch (e) {
      emit('MEDIA_FILE', label + ' could not be read', String(e).slice(0, 80));
    } finally {
      _selfRead = false;
      const ms = Date.now() - t0;
      // If this ever gets slow it shows up here rather than as a mystery stall.
      if (ms > 120) emit('RIG', 'file parse was slow', ms + 'ms');
    }
  };

  emit('RIG', 'post-path hooks', mediaGot + ' of ' + mediaWanted + ' attached');
  mediaMissed.forEach(function (m) { emit('RIG', 'post-path hook NOT attached', m); });

  // =====================================================================
  // BEHAVIORAL & ANTI-AUTOMATION LAYER
  // Input provenance, accessibility state, screen capture, peripherals,
  // physical context, and the anti-tamper reads TikTok does while you use
  // the feed. None of this appears in a privacy manifest.
  //
  // SAFETY: anything that can be read per frame during a scroll uses hotHook,
  // which samples a few times then DETACHES for good, so no trap survives into
  // the scroll. The three genuinely hot input-path hooks (sendEvent touch
  // provenance, scroll velocity, live motion values) live in the 'touch' probe
  // group, which the driver only arms when -Touch is passed, and then only for a
  // fraction of a second well after launch. Low-rate reads (key and name
  // loggers, haptics) use a plain budget. Read-only: we never alter a result.
  // =====================================================================

  // --- Wave 1: accessibility state (cold C booleans, device-wide) ---
  // AssistiveTouch and VoiceOver being on are the assistive-automation tells.
  // The rest are low-entropy fingerprint bits, each a permission-free read.
  [['UIAccessibilityIsAssistiveTouchRunning', 'AssistiveTouch'],
   ['UIAccessibilityIsVoiceOverRunning', 'VoiceOver'],
   ['UIAccessibilityIsSwitchControlRunning', 'Switch Control'],
   ['UIAccessibilityIsGuidedAccessEnabled', 'Guided Access'],
   ['UIAccessibilityIsBoldTextEnabled', 'Bold Text'],
   ['UIAccessibilityIsReduceMotionEnabled', 'Reduce Motion'],
   ['UIAccessibilityIsReduceTransparencyEnabled', 'Reduce Transparency'],
   ['UIAccessibilityIsInvertColorsEnabled', 'Invert Colors'],
   ['UIAccessibilityIsGrayscaleEnabled', 'Grayscale'],
   ['UIAccessibilityDarkerSystemColorsEnabled', 'Darker Colors'],
   ['UIAccessibilityIsShakeToUndoEnabled', 'Shake to Undo'],
   ['UIAccessibilityIsMonoAudioEnabled', 'Mono Audio'],
   ['UIAccessibilityIsClosedCaptioningEnabled', 'Closed Captioning'],
   ['UIAccessibilityIsSpeakScreenEnabled', 'Speak Screen'],
   ['UIAccessibilityIsVideoAutoplayEnabled', 'Video Autoplay'],
  ].forEach(function (pair) {
    try {
      const p = Module.findGlobalExportByName(pair[0]);
      if (!p) return;
      // These are static for the session, so sample a few then DETACH. A plain
      // budget would stop the work but leave the trap firing on every layout,
      // and layout runs every frame during a scroll, which is trap-volume we
      // must not carry. hotHook removes the trap entirely after the sample.
      hotHook(p, 6, 'accessibility (' + pair[1] + ')', {
        onLeave: function (ret) { emit('A11Y', pair[1], ret.toInt32() ? 'on' : 'off'); }
      });
    } catch (e) {}
  });

  // --- Wave 1: MobileGestalt key logger ---
  // MGCopyAnswer(key) is how apps read every hardware fact: UDID, serial, IMEI,
  // Wi-Fi/Bluetooth MAC, model, region, plus the Developer Mode and production
  // status probes. We log the KEY asked for, never touch the answer.
  try {
    const mg = Module.findGlobalExportByName('MGCopyAnswer');
    if (mg) {
      const b = budget(4000, 'MobileGestalt reads');
      Interceptor.attach(mg, {
        onEnter: function (args) {
          if (_selfRead || !b()) return;
          try {
            const key = new ObjC.Object(args[0]).toString();
            if (key && key.length < 64) emit('GESTALT', key, null);
          } catch (e) {}
        }
      });
    }
  } catch (e) {}

  // --- Wave 1: screen capture, mirroring, external display ---
  // isCaptured can be polled on every cell as the feed scrolls, so it uses
  // hotHook (sample then detach), not a budget that leaves the trap in place.
  try {
    const m = ObjC.classes.UIScreen && ObjC.classes.UIScreen['- isCaptured'];
    if (m) {
      hotHook(m.implementation, 12, 'isCaptured reads', {
        onLeave: function (ret) {
          emit('CAPTURE', 'screen recording or mirroring check',
               ret.toInt32() ? 'currently captured' : 'checked, not captured');
        }
      });
    }
  } catch (e) {}
  try {
    const m = ObjC.classes.UIScreen && ObjC.classes.UIScreen['+ screens'];
    if (m) {
      hotHook(m.implementation, 12, 'screens list reads', {
        onLeave: function (ret) {
          try {
            const n = ret.isNull() ? 0 : new ObjC.Object(ret).count();
            emit('CAPTURE', 'external display check',
                 n > 1 ? (n + ' screens attached') : 'one screen');
          } catch (e) {}
        }
      });
    }
  } catch (e) {}
  try {
    const m = ObjC.classes.RPScreenRecorder && ObjC.classes.RPScreenRecorder['- isRecording'];
    if (m) {
      hotHook(m.implementation, 12, 'ReplayKit recording reads', {
        onLeave: function (ret) {
          emit('CAPTURE', 'ReplayKit recording check',
               ret.toInt32() ? 'recording' : 'not recording');
        }
      });
    }
  } catch (e) {}

  // --- Wave 1: connected peripherals (external input = automation tell) ---
  // These class methods can be polled, so sample then detach (hotHook), never a
  // bare attach that keeps trapping.
  try {
    const m = ObjC.classes.GCController && ObjC.classes.GCController['+ controllers'];
    if (m) {
      hotHook(m.implementation, 12, 'controller reads', {
        onLeave: function (ret) {
          try {
            const n = ret.isNull() ? 0 : new ObjC.Object(ret).count();
            emit('PERIPHERAL', 'game controllers', n > 0 ? (n + ' attached') : 'none');
          } catch (e) {}
        }
      });
    }
  } catch (e) {}
  try {
    const m = ObjC.classes.GCKeyboard && ObjC.classes.GCKeyboard['+ coalescedKeyboard'];
    if (m) {
      hotHook(m.implementation, 12, 'keyboard reads', {
        onLeave: function (ret) {
          emit('PERIPHERAL', 'hardware keyboard', ret.isNull() ? 'none' : 'attached');
        }
      });
    }
  } catch (e) {}
  try {
    const m = ObjC.classes.GCMouse && ObjC.classes.GCMouse['+ mice'];
    if (m) {
      hotHook(m.implementation, 12, 'mouse reads', {
        onLeave: function (ret) {
          try {
            const n = ret.isNull() ? 0 : new ObjC.Object(ret).count();
            emit('PERIPHERAL', 'mouse', n > 0 ? (n + ' attached') : 'none');
          } catch (e) {}
        }
      });
    }
  } catch (e) {}
  try {
    const m = ObjC.classes.EAAccessoryManager &&
              ObjC.classes.EAAccessoryManager['- connectedAccessories'];
    if (m) {
      hotHook(m.implementation, 12, 'accessory reads', {
        onLeave: function (ret) {
          try {
            const n = ret.isNull() ? 0 : new ObjC.Object(ret).count();
            emit('PERIPHERAL', 'MFi accessories', String(n));
          } catch (e) {}
        }
      });
    }
  } catch (e) {}
  ['- scanForPeripheralsWithServices:options:',
   '- retrieveConnectedPeripheralsWithServices:'].forEach(function (sel) {
    try {
      const m = ObjC.classes.CBCentralManager && ObjC.classes.CBCentralManager[sel];
      if (!m) return;
      Interceptor.attach(m.implementation, {
        onEnter: function () {
          emit('PERIPHERAL', 'Bluetooth', sel.indexOf('scan') >= 0
               ? 'scanned for nearby BLE devices' : 'listed connected BLE devices');
        }
      });
    } catch (e) {}
  });

  // --- Wave 1: physical context (proximity, orientation, brightness, haptics) ---
  // All three can be read per frame, so sample then detach.
  try {
    const m = ObjC.classes.UIDevice && ObjC.classes.UIDevice['- proximityState'];
    if (m) {
      hotHook(m.implementation, 12, 'proximity reads', {
        onLeave: function (ret) {
          emit('CONTEXT', 'proximity sensor (phone at your face)',
               ret.toInt32() ? 'covered' : 'clear');
        }
      });
    }
  } catch (e) {}
  try {
    const m = ObjC.classes.UIDevice && ObjC.classes.UIDevice['- orientation'];
    if (m) {
      const ORI = ['unknown', 'portrait', 'portrait upside down', 'landscape left',
                   'landscape right', 'face up', 'face down'];
      hotHook(m.implementation, 12, 'orientation reads', {
        onLeave: function (ret) {
          emit('CONTEXT', 'device orientation', ORI[ret.toInt32()] || 'read');
        }
      });
    }
  } catch (e) {}
  try {
    const m = ObjC.classes.UIScreen && ObjC.classes.UIScreen['- brightness'];
    if (m) {
      hotHook(m.implementation, 12, 'brightness reads', {
        onEnter: function () {
          emit('CONTEXT', 'screen brightness (ambient light proxy)', 'read');
        }
      });
    }
  } catch (e) {}
  try {
    const m = ObjC.classes.CHHapticEngine &&
              ObjC.classes.CHHapticEngine['+ capabilitiesForHardware'];
    if (m) {
      Interceptor.attach(m.implementation, {
        onEnter: function () {
          emit('CONTEXT', 'haptic hardware class', 'checked Taptic Engine capability');
        }
      });
    }
  } catch (e) {}

  // --- Wave 1: anti-tamper environment reads (log and pass through) ---
  // TikTok reads these to detect jailbreak, injection and debugging. We only
  // record that it looked; we never change the answer, which keeps us read-only.
  try {
    const ge = Module.findGlobalExportByName('getenv');
    if (ge) {
      const b = budget(6000, 'getenv reads');
      const WATCH_ENV = /^(DYLD_INSERT_LIBRARIES|DYLD_|_MSSafeMode|SIMULATOR_)/;
      Interceptor.attach(ge, {
        onEnter: function (args) { this.n = b() ? cstr(args[0]) : null; },
        onLeave: function (ret) {
          if (this.n && WATCH_ENV.test(this.n)) {
            emit('INSTRUMENT', 'read env ' + this.n, ret.isNull() ? 'unset' : 'set');
          }
        }
      });
    }
  } catch (e) {}
  try {
    const p = Module.findGlobalExportByName('dlsym');
    if (p) {
      const b = budget(4000, 'dlsym reads');
      const WATCH_SYM = /MSHook|MSGetImage|substrate|substitute|frida|cynject|fishhook/i;
      Interceptor.attach(p, {
        onEnter: function (args) { this.s = b() ? cstr(args[1]) : null; },
        onLeave: function () {
          if (this.s && WATCH_SYM.test(this.s)) {
            emit('INSTRUMENT', 'looked up hook symbol ' + this.s, null);
          }
        }
      });
    }
  } catch (e) {}
  try {
    const p = Module.findGlobalExportByName('SecTaskCopyValueForEntitlement');
    if (p) {
      const b = budget(2000, 'entitlement reads');
      Interceptor.attach(p, {
        onEnter: function (args) {
          if (!b()) { this.k = null; return; }
          try { this.k = new ObjC.Object(args[1]).toString(); } catch (e) { this.k = null; }
        },
        onLeave: function () {
          if (this.k && this.k.length < 80) {
            emit('INSTRUMENT', 'read entitlement ' + this.k, null);
          }
        }
      });
    }
  } catch (e) {}

  // --- Wave 2: touch provenance. ONE choke point sees every UIEvent once. ---
  // Finger vs mouse/trackpad pointer vs stylus, plus the injection tell: real
  // hardware fills coalescedTouchesForTouch, scripted/synthetic input usually
  // leaves it empty. sendEvent: is hot, so it self-detaches after a sample.
  // We do NOT gate on the event type integer (its bridged form is easy to
  // misread). Instead we ask the event for its touches: a non-touch event has
  // none, so it falls through. For each touch, UITouchType says finger vs stylus
  // vs mouse/trackpad pointer, and coalescedTouchesForTouch separates real
  // hardware (which fills sub-frame samples) from scripted input (which usually
  // does not). Number() coerces the bridged values so comparisons are reliable.
  // GATED behind -Touch. Only 20 samples before it detaches for good, so the hot
  // window is a few hundred ms of scrolling. Each sample reads a battery of touch
  // signals so a real finger and an AssistiveTouch (synthetic) touch print visibly
  // different lines: the synthetic one lacks contact width, pressure, hardware
  // micro-samples, and a digitizer origin, even though it still claims type=direct.
  {   // bare block, not a flag test: registration is free, arming is what costs
    const TOUCHSRC = { 1: 'an indirect remote', 2: 'a stylus or Apple Pencil',
                       3: 'a mouse or trackpad pointer' };
    const PHASE = { 0: 'finger down', 1: 'moving', 2: 'held still',
                    3: 'lifted off', 4: 'cancelled' };
    function bRadius(r) {
      if (!(r > 0)) return 'zero, no contact patch (synthetic tell)';
      const a = Math.round(r / 5) * 5;
      if (r < 12) return 'narrow, ~' + a + 'pt';
      if (r < 28) return 'finger-width, ~' + a + 'pt';
      return 'wide, ~' + a + 'pt';
    }
    function bForce(f) {
      if (!(f > 0)) return 'zero (synthetic, or no force applied)';
      if (f < 1) return 'light';
      if (f < 3) return 'medium';
      return 'firm';
    }
    function bCoalesced(n) {
      if (!(n > 0)) return 'none (synthetic tell)';
      if (n <= 2) return String(n);
      return n + ' (only real hardware fills these)';
    }
    function bSpeed(d) {
      if (d < 2) return 'still';
      if (d < 15) return 'slow';
      if (d < 40) return 'medium';
      return 'fast';
    }
    try {
      const se = ObjC.classes.UIApplication && ObjC.classes.UIApplication['- sendEvent:'];
      if (se) {
        probe('touch', se.implementation, 20, 'touch events (sendEvent)', {
          onEnter: function (args) {
            try {
              const ev = new ObjC.Object(args[2]);
              let arr = null;
              try {
                const touches = ev.allTouches();
                if (touches && !touches.isNull() && Number(touches.count()) > 0) {
                  arr = touches.allObjects();
                }
              } catch (e) {}
              if (!arr) return;            // not a touch event, nothing to profile
              const t = arr.objectAtIndex_(0);

              // hardware micro-samples: real finger drags fill these, synthetic none
              let coalesced = -1;
              try {
                const c = ev.coalescedTouchesForTouch_(t);
                coalesced = (c && !c.isNull()) ? Number(c.count()) : 0;
              } catch (e) {}

              // 1. input source + authenticity verdict
              let tt = 0;
              try { tt = Number(t.type()); } catch (e) {}
              let verdict;
              if (tt === 0) {
                verdict = (coalesced > 0)
                  ? 'a real finger'
                  : 'a finger with no hardware sub-samples (synthetic / AssistiveTouch)';
              } else {
                verdict = TOUCHSRC[tt] || ('input type ' + tt);
              }
              emit('TOUCH', 'what is driving the feed', verdict);

              // 2. did it come from the hardware digitizer (the strongest tell)
              try {
                const hid = ev._hidEvent();
                emit('TOUCH', 'came from the hardware digitizer',
                     (hid && !hid.isNull()) ? 'yes, real hardware' : 'no, it was synthesized');
              } catch (e) {}

              // 3. how many hardware micro-samples this move carried
              if (coalesced >= 0) {
                emit('TOUCH', 'hardware micro-samples this move', bCoalesced(coalesced));
              }

              // 4. contact patch width (a synthetic tap has none)
              try { emit('TOUCH', 'fingertip contact width', bRadius(Number(t.majorRadius()))); } catch (e) {}

              // 5. press pressure
              try { emit('TOUCH', 'finger pressure', bForce(Number(t.force()))); } catch (e) {}

              // 6. touch phase
              try { emit('TOUCH', 'touch phase', PHASE[Number(t.phase())] || 'phase'); } catch (e) {}

              // 7. swipe speed + direction, measured from the touch's own movement
              try {
                const loc = t.locationInView_(ptr(0));
                const prev = t.previousLocationInView_(ptr(0));
                const dx = loc.x - prev.x, dy = loc.y - prev.y;
                const dist = Math.sqrt(dx * dx + dy * dy);
                emit('TOUCH', 'swipe speed', bSpeed(dist));
                if (dist >= 2) {
                  emit('TOUCH', 'swipe direction',
                       (Math.abs(dy) >= Math.abs(dx)) ? (dy > 0 ? 'down' : 'up')
                                                      : (dx > 0 ? 'right' : 'left'));
                }
              } catch (e) {}
            } catch (e) {}
          }
        });
      }
    } catch (e) {}
  }

  // --- Wave 2: flick dynamics. How hard/fast each swipe is driven. GATED. ---
  {
    try {
      const m = ObjC.classes.UIPanGestureRecognizer &&
                ObjC.classes.UIPanGestureRecognizer['- velocityInView:'];
      if (m) {
        probe('touch', m.implementation, 40, 'scroll velocity reads', {
          onEnter: function () {
            emit('SCROLL', 'your flick speed and direction', 'measured as you scroll');
          }
        });
      }
    } catch (e) {}
  }

  // --- Wave 2: engagement haptics. TikTok's own taxonomy of moments. ---
  ['- impactOccurred', '- impactOccurredWithIntensity:'].forEach(function (sel) {
    try {
      const m = ObjC.classes.UIImpactFeedbackGenerator &&
                ObjC.classes.UIImpactFeedbackGenerator[sel];
      if (!m) return;
      const b = budget(3000, 'impact haptics');
      Interceptor.attach(m.implementation, {
        onEnter: function () { if (b()) emit('HAPTIC', 'a buzz on tap or like', 'played'); }
      });
    } catch (e) {}
  });
  try {
    const m = ObjC.classes.UINotificationFeedbackGenerator &&
              ObjC.classes.UINotificationFeedbackGenerator['- notificationOccurred:'];
    if (m) {
      const b = budget(3000, 'notification haptics');
      const NT = ['success', 'warning', 'error'];
      Interceptor.attach(m.implementation, {
        onEnter: function (args) {
          if (!b()) return;
          let t = -1;
          try { t = Number(args[2].toInt32()); } catch (e) {}
          emit('HAPTIC', 'a success or error buzz', NT[t] || 'played');
        }
      });
    }
  } catch (e) {}
  try {
    const m = ObjC.classes.UISelectionFeedbackGenerator &&
              ObjC.classes.UISelectionFeedbackGenerator['- selectionChanged'];
    if (m) {
      const b = budget(3000, 'selection haptics');
      Interceptor.attach(m.implementation, {
        onEnter: function () { if (b()) emit('HAPTIC', 'a selection tick', 'played'); }
      });
    }
  } catch (e) {}

  // --- Wave 3: live device-motion sampling. Real hands micro-jitter; a static ---
  // rig does not. GATED, and only 30 samples before it detaches for good.
  {
    try {
      const m = ObjC.classes.CMMotionManager && ObjC.classes.CMMotionManager['- deviceMotion'];
      if (m) {
        probe('touch', m.implementation, 30, 'device-motion value samples', {
          onLeave: function (ret) {
            try {
              if (ret.isNull()) return;
              const dm = new ObjC.Object(ret);
              const att = dm.attitude();
              if (!att || att.isNull()) return;
              const roll = Math.round(att.roll() * 10) / 10;
              const pitch = Math.round(att.pitch() * 10) / 10;
              emit('SENSOR_VALUE', 'hold angle (roll, pitch)', roll + ', ' + pitch);
            } catch (e) {}
          }
        });
      }
    } catch (e) {}
  }
  ['- startDeviceMotionUpdatesToQueue:withHandler:', '- startDeviceMotionUpdates'].forEach(
    function (sel) {
      try {
        const m = ObjC.classes.CMHeadphoneMotionManager &&
                  ObjC.classes.CMHeadphoneMotionManager[sel];
        if (!m) return;
        Interceptor.attach(m.implementation, {
          onEnter: function () { emit('SENSOR', 'AirPods head motion', 'started collecting'); }
        });
      } catch (e) {}
    });

  emit('READY', 'attached', null);
}
