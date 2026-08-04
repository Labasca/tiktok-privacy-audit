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
var HOT_MAX_MS = 9000;        // after this, EVERY hot hook is force-detached

// Payload capture (SSLRead/SSLWrite) hooks the hottest functions in a streaming
// app. It is OFF unless the driver turns it on, because those hooks are the ones
// that have taken the machine down. The driver flips the digit below IN PLACE:
// it must stay a single character so the compiled bundle's byte offsets, which
// are baked into its header, do not shift. A length change corrupts the package.
var TLS_ENABLED = 0;   // 0 = off, driver rewrites to 1 to enable

// Raw syscall hooks (connect, getaddrinfo, stat, access, statfs, ioctl, numeric
// sysctl, reachability...) sit on the app's HOT PATH. During active scrolling
// they fire fast enough to peg the phone's frida-server and hang the USB link,
// which is what has frozen the machine. They are OFF by default. The original,
// known-safe hooks (ObjC, keychain, sysctlbyname, uname, getifaddrs) stay on.
// Same single-character flip rule as TLS_ENABLED: length must not change.
var SYSCALL_ENABLED = 0;   // 0 = off, driver rewrites to 1 to enable

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
 * HOT HOOKS. This is the fix for the crash that a plain budget did NOT solve.
 *
 * A budget stops the WORK inside a handler, but Frida still traps every call:
 * each one is a native-to-JS transition on the phone's frida-server. On a
 * function that carries the video stream (SSLRead, SSLWrite, read, write) that
 * is tens of thousands of traps a second, which pegs frida-server and hangs the
 * USB link, which hangs the host.
 *
 * The only real cure is to stop trapping. hotHook() collects a small sample,
 * then DETACHES the listener entirely, so afterwards the function runs natively
 * with zero Frida involvement. A wall-clock backstop force-detaches every hot
 * hook after HOT_MAX_MS no matter what, so a burst that never reaches the sample
 * limit still cannot run the whole session.
 * ------------------------------------------------------------------------- */
var _hotListeners = [];   // every hot listener, for the time-box kill
var _detachQueue = [];    // listeners that spent their sample, detached on flush
var _hotKilled = false;

function hotHook(target, limit, label, handlers) {
  if (!target) return;
  var n = 0, dead = false, self = null;
  self = Interceptor.attach(target, {
    onEnter: function (args) {
      if (dead) return;                    // cheapest possible: one read + return
      if (++n > limit) {
        // Spend the sample and detach RIGHT NOW, inline. Deferring to the flush
        // timer is unsafe: under a saturating call rate the JS thread never
        // yields, so the timer that would detach us is starved exactly when it
        // matters. Detaching inline stops the trapping immediately. The queue
        // and the time-box are belt-and-suspenders on top.
        dead = true;
        emit('CAPPED', label, String(limit));
        _detachQueue.push(self);
        try { self.detach(); } catch (e) {}
        return;
      }
      this._s = true;
      if (handlers.onEnter) { try { handlers.onEnter.call(this, args); } catch (e) {} }
    },
    onLeave: function (ret) {
      if (this._s && handlers.onLeave) {
        try { handlers.onLeave.call(this, ret); } catch (e) {}
      }
    }
  });
  _hotListeners.push(self);
}

function flush() {
  // 1. detach any hot hook that spent its sample but whose inline detach was
  // deferred by Frida's interceptor transaction. Cheap and idempotent.
  while (_detachQueue.length) {
    var l = _detachQueue.pop();
    try { l.detach(); } catch (e) {}
  }
  // 2. wall-clock backstop: kill EVERY remaining hot hook once the window is up
  if (!_hotKilled && (Date.now() - _t0) > HOT_MAX_MS) {
    _hotKilled = true;
    _hotListeners.forEach(function (l) { try { l.detach(); } catch (e) {} });
    _hotListeners = [];
    emit('CAPPED', 'all hot hooks (time-box)', String(HOT_MAX_MS) + 'ms');
  }
  // 3. ship the batch. Always send something, even an empty batch, so the driver
  // can tell "idle" from "the phone-side script has wedged" and abort if so.
  var batch = [];
  _tally.forEach(function (row, k) {
    if (row[0] === row[2]) return;
    var p = k.split(SEP);
    batch.push([p[0], p[1], p[2], row[0], row[1]]);
    row[2] = row[0];
  });
  send({ b: batch, dropped: _dropped, capped: _capped, events: _events, hb: 1 });
}
setInterval(flush, FLUSH_MS);
rpc.exports = { flush: flush };

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

/* Look up a hot syscall ONLY when raw-syscall capture is enabled. When it is
 * off this returns null, so every hook site that goes through it simply never
 * attaches. This is the single switch that keeps the default run on the
 * known-safe hook set. Route every hot C function through this, never the safe
 * ones (sysctlbyname, uname, getifaddrs, SecItemCopyMatching). */
function dangerousExport(name) {
  return SYSCALL_ENABLED ? Module.findGlobalExportByName(name) : null;
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

  // hotHook, not a plain attach: getifaddrs can be called in tight loops by
  // networking code, so it self-detaches after a sample like the TLS hooks.
  hotHook(Module.findGlobalExportByName('getifaddrs'), 4000, 'interface scans', {
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
  // per second, so every one self-detaches after its sample.
  hotHook(dangerousExport('connect'), 4000, 'outbound connects', {
    onEnter: function (args) { reportDest(args[1]); }
  });

  // Network.framework goes through connectx. In sa_endpoints_t the destination
  // pointer sits at offset 24 on arm64.
  hotHook(dangerousExport('connectx'), 4000, 'outbound connects (nw)', {
    onEnter: function (args) {
      try {
        if (args[1].isNull()) return;
        reportDest(args[1].add(24).readPointer());
      } catch (e) {}
    }
  });

  hotHook(dangerousExport('getsockname'), 4000, 'egress address reads', {
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

  hotHook(dangerousExport('getaddrinfo'), 4000, 'name lookups', {
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
  hotHook(dangerousExport('nw_path_uses_interface_type'), 4000,
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
    const ioctlBudget = budget(60000, 'ioctl calls');   // ioctl runs on every socket operation
    const ioctl = dangerousExport('ioctl');
    if (ioctl) {
      Interceptor.attach(ioctl, {
        onEnter: function (args) {
          if (!ioctlBudget()) return;
          const req = args[1].toUInt32();
          if (req === SIOCGIFCONF) emit('IFENUM', 'ioctl SIOCGIFCONF', null);
          else if (req === SIOCGIFADDR) emit('IFENUM', 'ioctl SIOCGIFADDR', null);
        }
      });
    }
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
  (SYSCALL_ENABLED ? ['statfs', 'statfs64'] : []).forEach(function (fn) {
    try {
      const p = Module.findGlobalExportByName(fn);
      if (!p) return;
      Interceptor.attach(p, {
        onEnter: function () {
          if (diskBudget()) emit('DISPLAY', 'free disk space', 'read via ' + fn);
        }
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
  const sysctlBudget = budget(20000, 'numeric sysctl reads');
  try {
    const p = dangerousExport('sysctl');
    if (p) {
      Interceptor.attach(p, {
        onEnter: function (args) {
          if (!sysctlBudget()) return;
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
    }
  } catch (e) {}

  // a library-enumeration sweep calls these once per loaded image, so a few
  // hundred times per sweep. Budgeted so a detector in a loop cannot run away.
  const dyldBudget = budget(20000, 'loaded-library enumeration');
  [['_dyld_image_count', 'counting loaded libraries'],
   ['_dyld_get_image_name', 'reading loaded library names']].forEach(function (pair) {
    try {
      const p = Module.findGlobalExportByName(pair[0]);
      if (!p) return;
      Interceptor.attach(p, {
        onEnter: function () { if (dyldBudget()) emit('TAMPER', pair[0], pair[1]); }
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
    hotHook(dangerousExport(fn), 4000, 'code-signing checks (' + fn + ')', {
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
  (SYSCALL_ENABLED ? ['stat', 'lstat', 'access'] : []).forEach(function (fn) {
    hotHook(Module.findGlobalExportByName(fn), 20000, 'filesystem checks (' + fn + ')', {
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
    const p = dangerousExport('res_9_getservers');
    if (p) {
      Interceptor.attach(p, {
        onEnter: function () { emit('DISPLAY', 'DNS servers', 'read the resolver list'); }
      });
    }
  } catch (e) {}

  try {
    const p = dangerousExport('SCNetworkReachabilityGetFlags');
    if (p) {
      const reachBudget = budget(20000, 'reachability checks');
      Interceptor.attach(p, {
        onEnter: function () {
          if (reachBudget()) emit('DISPLAY', 'connection reachability', 'via SystemConfiguration');
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

  if (TLS_ENABLED) {
    ['SSLWrite', 'SSL_write'].forEach(function (nm) {
      hotHook(Module.findGlobalExportByName(nm), 800, 'TLS write (' + nm + ')',
              { onEnter: tlsWriteHandler });
    });
  }

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

  if (TLS_ENABLED) {
    hotHook(Module.findGlobalExportByName('SSLRead'), 800, 'TLS read (SSLRead)',
            makeReadHandlers(true));
    hotHook(Module.findGlobalExportByName('SSL_read'), 800, 'TLS read (SSL_read)',
            makeReadHandlers(false));
  }

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

  emit('READY', 'attached', null);
}
