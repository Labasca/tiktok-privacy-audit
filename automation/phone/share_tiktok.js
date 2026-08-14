'use strict';
/*
 * Photos.app only. Hand a library video to TikTok without HID.
 * LSApplicationWorkspace opens the file URL with TikTok's bundle id.
 */
import ObjC from 'frida-objc-bridge';

function nsstr(s) {
  return ObjC.classes.NSString.stringWithString_(s);
}

rpc.exports = {
  openInTikTok: function (path) {
    const out = { path: path, tried: [] };
    const url = ObjC.classes.NSURL.fileURLWithPath_(nsstr(path));
    out.url = url.absoluteString().toString();
    const LS = ObjC.classes.LSApplicationWorkspace;
    const WS = LS ? LS.defaultWorkspace() : null;
    out.hasWorkspace = !!WS;

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

    if (WS) {
      tryCall('openSensitiveURL', function () {
        const opts = ObjC.classes.NSMutableDictionary.dictionary();
        opts.setObject_forKey_(
          nsstr('com.zhiliaoapp.musically'),
          nsstr('LSApplicationWorkspaceOptionDefaultApplication')
        );
        return WS['openSensitiveURL:withOptions:'](url, opts);
      });
      tryCall('openSensitiveURL_bundle', function () {
        const opts = ObjC.classes.NSMutableDictionary.dictionary();
        opts.setObject_forKey_(
          nsstr('com.zhiliaoapp.musically'),
          nsstr('SBApplicationLaunchBundleID')
        );
        return WS['openSensitiveURL:withOptions:'](url, opts);
      });
      tryCall('openURL', function () {
        return WS['openURL:'](url);
      });
    }
    return out;
  }
};
