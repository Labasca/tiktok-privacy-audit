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
var MAX_DISTINCT = 3000;      // distinct cat+key+value combinations
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
  // 3. ship the batch. Always send something, even an empty batch, so the driver
  // can tell "idle" from "the phone-side script has wedged" and abort if so.
  var batch = [];
  _tally.forEach(function (row, k) {
    if (row[0] === row[2]) return;
    var p = k.split(SEP);
    batch.push([p[0], p[1], p[2], row[0], row[1]]);
    row[2] = row[0];
  });
  send({ b: batch, dropped: _dropped, capped: _capped, events: _events,
         live: _live.length, hb: 1 });
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
  const AF_INET = 2, AF_INET6 = 30, IFF_UP = 0x1;
  const seenAddrs = new Set();

  function readSockaddr(sa) {
    if (sa.isNull()) return null;
    const family = sa.add(1).readU8();
    if (family === AF_INET) {
      const b = new Uint8Array(sa.add(4).readByteArray(4));
      return b.join('.');
    }
    if (family === AF_INET6) {
      const b = new Uint8Array(sa.add(8).readByteArray(16));
      const parts = [];
      for (let i = 0; i < 16; i += 2) parts.push((((b[i] << 8) | b[i + 1]) >>> 0).toString(16));
      return parts.join(':');
    }
    return null;  // AF_LINK and friends carry no routable address
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
        // struct ifaddrs on arm64: next 0, name 8, flags 16, addr 24
        let cur = this.listp.readPointer();
        let guard = 0;
        while (!cur.isNull() && guard++ < 256) {
          const name = cstr(cur.add(8).readPointer());
          const flags = cur.add(16).readU32();
          const addr = readSockaddr(cur.add(24).readPointer());
          if (name && addr && (flags & IFF_UP)) {
            const tag = name + '|' + addr;
            if (!seenAddrs.has(tag)) {
              seenAddrs.add(tag);
              emit('INTERFACE', name, addr);
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
  probe('net', dangerousExport('connect'), 120, 'outbound connects', {
    onEnter: function (args) { reportDest(args[1]); }
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
    },
    onLeave: function (retval) {
      try {
        if (retval.toInt32() !== 0 || !this.host || this.res.isNull()) return;
        // struct addrinfo on Darwin: ai_addr at 32, ai_next at 40
        let ai = this.res.readPointer();
        let guard = 0;
        const seen = new Set();
        while (!ai.isNull() && guard++ < 32) {
          const addr = readSockaddr(ai.add(32).readPointer());
          if (addr && !seen.has(addr)) {
            seen.add(addr);
            emit('DNS', this.host, addr);
          }
          ai = ai.add(40).readPointer();
        }
      } catch (e) {}
    }
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
  try {
    probe('net', dangerousExport('res_9_getservers'), 40, 'resolver list reads', {
      onEnter: function () { emit('DISPLAY', 'DNS servers', 'read the resolver list'); }
    });
  } catch (e) {}

  try {
    // reachability gets polled during network activity, so sample-then-detach.
    probe('net', dangerousExport('SCNetworkReachabilityGetFlags'), 120, 'reachability checks', {
      onEnter: function () {
        emit('DISPLAY', 'connection reachability', 'via SystemConfiguration');
      }
    });
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
        onEnter: function () {
          emit('INTERFACE_ID', 'Wi-Fi network identity', 'asked for SSID and BSSID');
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

  function tlsWriteHandler(args) {
    const buf = args[1];
    const len = args[2].toInt32();
    if (len < 16 || len > 200000 || buf.isNull()) return;
    const n = len < 96 ? len : 96;
    const bytes = new Uint8Array(buf.readByteArray(n));
    let ok = true;
    for (let i = 0; i < 8 && i < n; i++) {
      const ch = bytes[i];
      if (ch < 0x20 || ch > 0x7e) { ok = false; break; }
    }
    if (!ok) return;
    let s = '';
    for (let i = 0; i < n; i++) {
      const ch = bytes[i];
      s += (ch >= 0x20 && ch <= 0x7e) ? String.fromCharCode(ch) : '.';
    }
    if (!HTTP_START.test(s)) return;
    const firstLine = s.split('\r')[0].split('\n')[0].slice(0, 80);
    if (seenLines.has(firstLine)) return;
    if (seenLines.size < 400) seenLines.add(firstLine);
    emit('PLAINTEXT', firstLine, null);
  }

  // 60, not 400. SSLWrite carries every outbound byte of a video app, so the
  // sample is spent almost instantly either way; the only thing a larger limit
  // bought was a longer stretch of trapping.
  ['SSLWrite', 'SSL_write'].forEach(function (nm) {
    probe('tls', dangerousExport(nm), 60, 'TLS write (' + nm + ')',
          { onEnter: tlsWriteHandler });
  });

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

  probe('tls', dangerousExport('SSLRead'), 60, 'TLS read (SSLRead)',
        makeReadHandlers(true));
  probe('tls', dangerousExport('SSL_read'), 60, 'TLS read (SSL_read)',
        makeReadHandlers(false));

  // --- Explicit VPN and proxy checks (read-only) ---
  try {
    const proxy = Module.findGlobalExportByName('CFNetworkCopySystemProxySettings');
    if (proxy) {
      Interceptor.attach(proxy, {
        onEnter: function () { emit('PROXY', 'proxy config', null); }
      });
    }
  } catch (e) {}

  try {
    const NEVPNManager = ObjC.classes.NEVPNManager;
    if (NEVPNManager && NEVPNManager['- connection']) {
      Interceptor.attach(NEVPNManager['- connection'].implementation, {
        onEnter: function () { emit('PROXY', 'VPN status', null); }
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
    ['__NSCFLocalSessionTask', '__NSCFURLSessionTask', 'NSURLSessionTask'].forEach(function (cn) {
      const klass = ObjC.classes[cn];
      if (!klass || !klass['- resume']) return;
      Interceptor.attach(klass['- resume'].implementation, {
        onEnter: function (args) {
          try {
            const task = new ObjC.Object(args[0]);
            if (task.originalRequest === undefined) return;
            const req = task.originalRequest();
            if (req && !req.isNull()) reportRequest(req);
          } catch (e) {}
        }
      });
    });
  } catch (e) {}

  function reportRequest(req) {
    try {
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
      // encrypted blob. Never the whole thing.
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
        }
      } catch (e) {}
    } catch (e) {}
  }

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
          if (!b()) return;
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
