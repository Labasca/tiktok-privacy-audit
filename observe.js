/*
 * observe.js  —  READ-ONLY privacy audit for TikTok on a device you own.
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
 * Run:  frida -U -f com.zhiliaoapp.musically -l observe.js --no-pause
 */

'use strict';

// Frida 17 removed the ObjC bridge as a global; it's now a bundled module.
import ObjC from 'frida-objc-bridge';

function ts() { return new Date().toISOString().slice(11, 23); }
function log(tag, msg) { console.log(`[${ts()}] ${tag}  ${msg}`); }

if (!ObjC.available) {
  console.log('[!] Objective-C runtime not available');
} else {
  // --- Location: what location TikTok asks for (read-only) ---
  try {
    const CLLocationManager = ObjC.classes.CLLocationManager;
    ['startUpdatingLocation', 'requestLocation', 'requestWhenInUseAuthorization',
     'requestAlwaysAuthorization'].forEach(function (sel) {
      if (CLLocationManager[sel] === undefined) return;
      Interceptor.attach(CLLocationManager[sel].implementation, {
        onEnter: function () { log('LOCATION', `CLLocationManager -${sel} called`); }
      });
    });
    // reading the current fix (we log the value it RECEIVES, we do not alter it)
    const locGetter = CLLocationManager['- location'];
    if (locGetter) {
      Interceptor.attach(locGetter.implementation, {
        onLeave: function (ret) {
          try {
            const loc = new ObjC.Object(ret);
            log('LOCATION', `read location => ${loc.toString()}`);
          } catch (e) {}
        }
      });
    }
  } catch (e) { log('LOCATION', 'hook skipped: ' + e); }

  // --- Device identifiers TikTok reads (read-only) ---
  try {
    const UIDevice = ObjC.classes.UIDevice;
    const idfv = UIDevice['- identifierForVendor'];
    if (idfv) {
      Interceptor.attach(idfv.implementation, {
        onLeave: function (ret) {
          try { log('IDENTIFIER', `identifierForVendor => ${new ObjC.Object(ret).toString()}`); }
          catch (e) {}
        }
      });
    }
    ['- systemVersion', '- model', '- name'].forEach(function (sel) {
      const m = UIDevice[sel];
      if (!m) return;
      Interceptor.attach(m.implementation, {
        onLeave: function (ret) {
          try { log('IDENTIFIER', `UIDevice ${sel} => ${new ObjC.Object(ret).toString()}`); }
          catch (e) {}
        }
      });
    });
  } catch (e) { log('IDENTIFIER', 'hook skipped: ' + e); }

  // --- Keychain lookups (read-only) ---
  try {
    const SecItemCopyMatching = Module.findGlobalExportByName('SecItemCopyMatching');
    if (SecItemCopyMatching) {
      Interceptor.attach(SecItemCopyMatching, {
        onEnter: function () { log('KEYCHAIN', 'SecItemCopyMatching (keychain read)'); }
      });
    }
  } catch (e) {}

  // --- Low-level fingerprint reads: sysctl / uname (read-only) ---
  try {
    ['sysctlbyname', 'uname'].forEach(function (fn) {
      const p = Module.findGlobalExportByName(fn);
      if (!p) return;
      Interceptor.attach(p, {
        onEnter: function (args) {
          if (fn === 'sysctlbyname') {
            try { log('FINGERPRINT', `sysctlbyname("${args[0].readUtf8String()}")`); }
            catch (e) { log('FINGERPRINT', 'sysctlbyname(?)'); }
          } else {
            log('FINGERPRINT', 'uname()');
          }
        }
      });
    });
  } catch (e) {}

  // --- Network interface enumeration: log that it happens (read-only) ---
  try {
    const getifaddrs = Module.findGlobalExportByName('getifaddrs');
    if (getifaddrs) {
      Interceptor.attach(getifaddrs, {
        onEnter: function () { log('NETWORK', 'getifaddrs (interface scan)'); }
      });
    }
  } catch (e) {}

  // --- Outbound requests: what URLs TikTok hits (read-only) ---
  try {
    const NSURLSession = ObjC.classes.NSURLSession;
    const sel = '- dataTaskWithRequest:completionHandler:';
    if (NSURLSession[sel]) {
      Interceptor.attach(NSURLSession[sel].implementation, {
        onEnter: function (args) {
          try {
            const req = new ObjC.Object(args[2]);
            log('REQUEST', `${req.HTTPMethod()} ${req.URL().absoluteString()}`);
          } catch (e) {}
        }
      });
    }
  } catch (e) { log('REQUEST', 'hook skipped: ' + e); }

  console.log('\n[+] observe.js attached — read-only logging active. Ctrl+C to stop.\n');
}
