/*
 * SpringBoard only. Turn the backlight on so screenshots and taps land.
 * Compiled with frida-objc-bridge.
 */
'use strict';

import ObjC from 'frida-objc-bridge';

rpc.exports = {
  wake: function () {
    const out = { ok: false, tried: [], error: null };
    function tryCall(label, fn) {
      try {
        const r = fn();
        out.tried.push({ label: label, ok: true, result: String(r) });
        return true;
      } catch (e) {
        out.tried.push({ label: label, ok: false, error: String(e) });
        return false;
      }
    }

    const SBBacklight = ObjC.classes.SBBacklightController;
    const SBLock = ObjC.classes.SBLockScreenManager;
    const SBUserAgent = ObjC.classes.SBUserAgent;

    function go() {
      out.classes = {
        SBBacklightController: !!SBBacklight,
        SBLockScreenManager: !!SBLock,
        SBUserAgent: !!SBUserAgent
      };
      if (SBBacklight) {
        let inst = null;
        tryCall('SBBacklight.sharedInstance', function () {
          inst = SBBacklight.sharedInstance();
          return inst ? inst.$className : 'null';
        });
        if (inst) {
          tryCall('turnOnScreenFullyWithBacklightSource:0', function () {
            inst['turnOnScreenFullyWithBacklightSource:'](0);
            return 'ok';
          });
          tryCall('setBacklightFactor:source:', function () {
            inst['setBacklightFactor:source:'](1.0, 0);
            return 'ok';
          });
        }
      }
      if (SBUserAgent) {
        tryCall('undimScreen', function () {
          SBUserAgent.sharedUserAgent().undimScreen();
          return 'ok';
        });
      }
      if (SBLock) {
        tryCall('isUILocked', function () {
          return String(SBLock.sharedInstance().isUILocked());
        });
        tryCall('unlockUIFromSource:withOptions:', function () {
          SBLock.sharedInstance()['unlockUIFromSource:withOptions:'](0, NULL);
          return 'ok';
        });
      }
    }
    // Run on main, wait so the RPC returns after the work.
    const done = { v: false };
    ObjC.schedule(ObjC.mainQueue, function () {
      go();
      done.v = true;
    });
    const t0 = Date.now();
    while (!done.v && Date.now() - t0 < 2000) { /* spin */ }
    if (!done.v) go();
    out.ok = out.tried.some(function (t) { return t.ok; });
    return out;
  }
};
