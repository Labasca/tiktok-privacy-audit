'use strict';
import ObjC from 'frida-objc-bridge';

rpc.exports = {
  undim: function () {
    const out = { tried: [] };
    const done = { v: true };
    const UA = ObjC.classes.SBUserAgent;
    const BL = ObjC.classes.SBBacklightController;
    const LM = ObjC.classes.SBLockScreenManager;
    function note(k, v) { out.tried.push(k + '=' + v); }
    ObjC.schedule(ObjC.mainQueue, function () {
      try {
        if (UA) { UA.sharedUserAgent().undimScreen(); note('undim', 'ok'); }
      } catch (e) { note('undim', String(e)); }
      try {
        if (BL) { BL.sharedInstance()['turnOnScreenFullyWithBacklightSource:'](0); note('bl', 'ok'); }
      } catch (e) { note('bl', String(e)); }
      try {
        if (LM) note('locked0', String(LM.sharedInstance().isUILocked()));
      } catch (e) { note('locked0', String(e)); }
      if (LM) {
        const inst = LM.sharedInstance();
        [0, 11, 13, 14, 24, 26].forEach(function (src) {
          try {
            inst['unlockUIFromSource:withOptions:'](src, NULL);
            note('unlock' + src, 'ok');
          } catch (e) { note('unlock' + src, String(e)); }
        });
        try {
          inst.attemptUnlockWithPasscode_('');
          note('passEmpty', 'ok');
        } catch (e) {
          try { inst['attemptUnlockWithPasscode:'](''); note('passEmpty2', 'ok'); }
          catch (e2) { note('passEmpty', String(e2)); }
        }
        try { note('locked1', String(inst.isUILocked())); } catch (e) {}
      }
      done.v = true;
    });
    const t0 = Date.now();
    while (!done.v && Date.now() - t0 < 2500) { }
    return out;
  }
};
