/*
 * discover.js  -  READ-ONLY coverage discovery, not an audit.
 *
 * observe.js answers "what did TikTok read". This answers the prior question:
 * "what COULD it read, and of that, what does it actually touch". It is how you
 * find out whether the audit has blind spots instead of guessing.
 *
 * Three passes, all read-only:
 *   1. IMPORTS   every C function the binary links against. This is the ceiling
 *                on what it can call without dlsym, and it costs nothing to read.
 *   2. CALLED    a wide net over privacy-relevant Objective-C classes. Reports
 *                which methods actually fire, so the audit can be extended based
 *                on evidence rather than on a list someone wrote from memory.
 *   3. PROBES    filesystem paths, NSUserDefaults keys and URL schemes, which is
 *                where locale, keyboards, jailbreak checks and installed-app
 *                detection all show up.
 *
 * Nothing here changes a return value. Same rule as observe.js.
 *
 * Build:  frida-compile discover.js -o discover.compiled.js
 */

'use strict';

import ObjC from 'frida-objc-bridge';

function emit(cat, key, value) {
  send({ cat: cat, key: key, value: value === undefined ? null : value });
}

const fired = new Set();
let attached = 0;
const ATTACH_CAP = 900;   // keep launch from crawling

function once(tag) {
  if (fired.has(tag)) return false;
  fired.add(tag);
  return true;
}

// ---------------------------------------------------------------- 1. imports
try {
  const main = Process.enumerateModules()[0];
  emit('MODULE', main.name, main.path);
  let imports = [];
  try {
    imports = main.enumerateImports();
  } catch (e) {
    try { imports = Module.enumerateImports(main.name); } catch (e2) {}
  }
  // one message, not five thousand
  emit('IMPORTS', main.name,
       imports.filter(function (i) { return i.type === 'function'; })
              .map(function (i) { return i.name; }));
} catch (e) {
  emit('ERROR', 'imports', String(e));
}

// ------------------------------------------------- 1b. is TLS reachable at all
// Capturing request bodies before encryption needs a symbol to hook. TikTok
// statically links BoringSSL, so the question is whether anything survived
// stripping. Enumerating symbols hooks nothing and cannot destabilise the app.
try {
  const TLS = /^(SSL_write|SSL_read|SSL_do_handshake|SSL_new|SSL_CTX_new|SSLWrite|SSLRead|ssl_write|nw_protocol_.*tls)/;
  const seenMods = [];
  Process.enumerateModules().slice(0, 40).forEach(function (m) {
    let syms = [];
    try { syms = m.enumerateSymbols(); } catch (e) { return; }
    const hits = syms.filter(function (s) { return TLS.test(s.name); })
                     .map(function (s) { return s.name; });
    if (hits.length) {
      seenMods.push(m.name);
      emit('TLSSYM', m.name, hits.slice(0, 12).join(', '));
    }
  });
  if (!seenMods.length) emit('NOTE', 'TLS symbols', 'none exported by any module');
} catch (e) { emit('NOTE', 'TLS scan', String(e)); }

if (!ObjC.available) {
  emit('ERROR', 'objc', 'runtime not available');
} else {
  // ------------------------------------------------------- 2. objc wide net
  // Small, focused classes get every method watched. Large or hot ones get a
  // pattern, or the app would spend its launch inside Frida.
  const WATCH_ALL = [
    'NSLocale', 'NSTimeZone', 'NSCalendar', 'UITextInputMode',
    'ASIdentifierManager', 'ATTrackingManager', 'CTTelephonyNetworkInfo',
    'CTCarrier', 'UIPasteboard', 'DCDevice', 'CMMotionManager', 'CMPedometer',
    'CMAltimeter', 'UIScreen', 'UIDevice', 'CMDeviceMotion',
  ];

  const WATCH_MATCH = {
    'NSProcessInfo':  /memory|processor|uptime|thermal|lowpower|host|operatingsystem|environment/i,
    'NSFileManager':  /attributesoffilesystem|fileexists|contentsofdirectory|urlsfordirectory/i,
    'UIApplication':  /canopenurl|openurl|backgroundrefresh|protecteddata|statusbar/i,
    'AVAudioSession': /currentroute|category|outputvolume|availableinputs/i,
    'UIFont':         /familynames|fontnameswithfamily/i,
    'NSBundle':       /bundleidentifier|infodictionary|objectforinfodictionarykey/i,
    'AVCaptureDevice': /authorizationstatus|devices/i,
    'PHPhotoLibrary': /authorizationstatus/i,
    'CNContactStore': /authorizationstatus|enumerate|unifiedcontacts/i,
    'EKEventStore':   /authorizationstatus/i,
    'CBCentralManager': /state|scanfor/i,
    'NSHTTPCookieStorage': /cookies/i,
    'UNUserNotificationCenter': /notificationsettings|authorization/i,
    'WKWebView':      /useragent|evaluatejavascript|customuseragent/i,
    'LAContext':      /canevaluatepolicy|biometry/i,
  };

  // A hook on a class catches calls from anywhere in the process, including
  // UIKit calling itself. Recording which module the call came FROM is what
  // separates "TikTok asked for this" from "the OS did it on its own".
  function callerOf(ctx) {
    try {
      const mod = Process.findModuleByAddress(ctx.returnAddress);
      return mod ? mod.name : '?';
    } catch (e) { return '?'; }
  }

  function watch(name, re) {
    const cls = ObjC.classes[name];
    if (!cls) { emit('ABSENT', name, null); return; }
    let methods;
    try { methods = cls.$ownMethods; } catch (e) { return; }
    let n = 0;
    methods.forEach(function (m) {
      if (attached >= ATTACH_CAP) return;
      if (re && !re.test(m)) return;
      try {
        Interceptor.attach(cls[m].implementation, {
          onEnter: function () {
            const tag = name + ' ' + m;
            if (fired.has(tag)) return;      // cheap check before the slow part
            fired.add(tag);
            emit('CALLED', tag, callerOf(this));
          }
        });
        n++; attached++;
      } catch (e) {}
    });
    emit('WATCHING', name, String(n));
  }

  WATCH_ALL.forEach(function (n) { watch(n, null); });
  Object.keys(WATCH_MATCH).forEach(function (n) { watch(n, WATCH_MATCH[n]); });

  // ----------------------------------------------------------- 3. the probes

  // NSUserDefaults is where AppleLanguages, AppleLocale and AppleKeyboards live,
  // so the KEY being asked for is the finding, not the call itself.
  // NSUserDefaults reads land in CFPreferences underneath, and an app can call
  // either. Watch both, and report which ones actually attached rather than
  // swallowing the failure and reporting an empty list as if it meant nothing.
  let defHooks = 0;
  ['- objectForKey:', '- stringForKey:', '- arrayForKey:', '- dictionaryForKey:',
   '- boolForKey:', '- integerForKey:'].forEach(function (sel) {
    try {
      const m = ObjC.classes.NSUserDefaults[sel];
      if (!m) { emit('NOTE', 'NSUserDefaults ' + sel, 'selector not found'); return; }
      Interceptor.attach(m.implementation, {
        onEnter: function (args) {
          try {
            const k = new ObjC.Object(args[2]).toString();
            if (once('def ' + k)) emit('DEFAULTS', k, callerOf(this));
          } catch (e) {}
        }
      });
      defHooks++; attached++;
    } catch (e) { emit('NOTE', 'NSUserDefaults ' + sel, String(e)); }
  });
  ['CFPreferencesCopyAppValue', 'CFPreferencesCopyValue'].forEach(function (fn) {
    try {
      const p = Module.findGlobalExportByName(fn);
      if (!p) { emit('NOTE', fn, 'not exported'); return; }
      Interceptor.attach(p, {
        onEnter: function (args) {
          try {
            const k = new ObjC.Object(args[0]).toString();
            if (once('def ' + k)) emit('DEFAULTS', k, callerOf(this));
          } catch (e) {}
        }
      });
      defHooks++;
    } catch (e) { emit('NOTE', fn, String(e)); }
  });
  emit('NOTE', 'defaults hooks attached', String(defHooks));

  // canOpenURL: is how an app inventories which other apps you have installed
  ['- canOpenURL:', '- openURL:options:completionHandler:'].forEach(function (sel) {
    try {
      const m = ObjC.classes.UIApplication[sel];
      if (!m) { emit('NOTE', 'UIApplication ' + sel, 'selector not found'); return; }
      Interceptor.attach(m.implementation, {
        onEnter: function (args) {
          try {
            const u = new ObjC.Object(args[2]).toString();
            if (once('url ' + u)) emit('SCHEME', u, callerOf(this));
          } catch (e) {}
        }
      });
      attached++;
    } catch (e) { emit('NOTE', 'UIApplication ' + sel, String(e)); }
  });

  // filesystem probes: jailbreak detection reads as a burst of stat() calls on
  // paths that only exist on a jailbroken phone
  // Anchored deliberately. A bare "apt" alternative matches Adapter, Capture and
  // chapter, which buries the real hits under container paths.
  const JB = new RegExp([
    'Cydia', 'Sileo\\.app', 'Zebra\\.app', 'MobileSubstrate', 'substrate',
    'TweakInject', 'TweakLoader', 'libhooker', 'ellekit', 'frida', 'cynject',
    '^/var/jb', '^/bin/sh', '^/bin/bash', '^/usr/sbin/sshd', '^/etc/apt',
    '^/var/lib/apt', '^/var/lib/dpkg', '^/usr/libexec/ssh-keysign',
    '^/Library/MobileSubstrate', '^/Applications/',
  ].join('|'), 'i');
  ['stat', 'lstat', 'access', 'open', 'fopen', 'faccessat'].forEach(function (fn) {
    try {
      const p = Module.findGlobalExportByName(fn);
      if (!p) return;
      Interceptor.attach(p, {
        onEnter: function (args) {
          try {
            const path = args[0].readUtf8String();
            if (path && JB.test(path) && once('fs ' + path)) emit('PROBE', path, fn);
          } catch (e) {}
        }
      });
    } catch (e) {}
  });

  // counters for the things that have no argument worth reading
  [['_dyld_image_count', 'listing loaded libraries'],
   ['_dyld_get_image_name', 'reading library names'],
   ['dlopen', 'loading a library by name'],
   ['dlsym', 'resolving a symbol at runtime'],
   ['ptrace', 'debugger control'],
   ['getenv', 'reading environment variables'],
   ['statfs', 'disk space'],
   ['statfs64', 'disk space'],
   ['tzset', 'timezone'],
   ['localtime', 'local time conversion'],
   ['gethostname', 'device hostname'],
   ['getpwuid', 'user account record'],
   ['sysctl', 'raw sysctl, the numeric form']].forEach(function (pair) {
    try {
      const p = Module.findGlobalExportByName(pair[0]);
      if (!p) return;
      Interceptor.attach(p, {
        onEnter: function () {
          if (once('c ' + pair[0])) emit('CFUNC', pair[0], pair[1]);
        }
      });
    } catch (e) {}
  });

  emit('READY', 'attached', String(attached));
}
