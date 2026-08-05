#!/usr/bin/env python3
"""
Live one-shot snapshot of the phone's accessibility + Developer Mode + device
state. READ-ONLY. No Interceptor, no hot hooks, just cold C-function reads, so
it is categorically not the freeze class.

It attaches to an already-running UIKit app (Settings by default) and calls the
same C functions TikTok would call: the UIAccessibilityIs* cluster and
MobileGestalt MGCopyAnswer(). This both answers "is AssistiveTouch / Developer
Mode on right now" and proves these exact symbols resolve on this iOS build
before we wire them into observe.js.

Usage:  .venv\\Scripts\\python.exe snapshot_state.py
"""
import sys
import time

import frida

CANDIDATES = ["Settings", "Sileo", "Shadowrocket", "App Store", "Photos"]

JS = r"""
'use strict';
function gexp(n){ return (typeof Module.getGlobalExportByName==='function')
  ? (function(){ try { return Module.getGlobalExportByName(n); } catch(e){ return null; } })()
  : Module.findExportByName(null, n); }

var out = { access: {}, gestalt: {}, notes: [] };

// --- UIAccessibility C booleans (device-wide accessibility state) ---
var A11Y = [
  ['AssistiveTouch','UIAccessibilityIsAssistiveTouchRunning'],
  ['VoiceOver','UIAccessibilityIsVoiceOverRunning'],
  ['SwitchControl','UIAccessibilityIsSwitchControlRunning'],
  ['GuidedAccess','UIAccessibilityIsGuidedAccessEnabled'],
  ['ReduceMotion','UIAccessibilityIsReduceMotionEnabled'],
  ['BoldText','UIAccessibilityIsBoldTextEnabled'],
  ['ReduceTransparency','UIAccessibilityIsReduceTransparencyEnabled'],
  ['InvertColors','UIAccessibilityIsInvertColorsEnabled'],
  ['Grayscale','UIAccessibilityIsGrayscaleEnabled'],
  ['DarkerColors','UIAccessibilityDarkerSystemColorsEnabled'],
  ['ShakeToUndo','UIAccessibilityIsShakeToUndoEnabled'],
  ['MonoAudio','UIAccessibilityIsMonoAudioEnabled'],
  ['ClosedCaptioning','UIAccessibilityIsClosedCaptioningEnabled'],
  ['SpeakScreen','UIAccessibilityIsSpeakScreenEnabled'],
  ['VideoAutoplay','UIAccessibilityIsVideoAutoplayEnabled'],
];
A11Y.forEach(function(pair){
  var p = gexp(pair[1]);
  if (!p) { out.access[pair[0]] = '(symbol not found)'; return; }
  try {
    var f = new NativeFunction(p, 'bool', []);
    out.access[pair[0]] = f() ? 'ON' : 'off';
  } catch(e) { out.access[pair[0]] = 'err:' + e.message; }
});

// --- MobileGestalt reads (Developer Mode + identity + anti-tamper) ---
var mg = gexp('MGCopyAnswer');
var cfCreate = gexp('CFStringCreateWithCString');
var cfDesc   = gexp('CFCopyDescription');
var cfGetC   = gexp('CFStringGetCString');
var cfRelease= gexp('CFRelease');
var kUTF8 = 0x08000100;

function mgRead(key){
  if (!mg || !cfCreate || !cfDesc || !cfGetC) return '(MG unavailable)';
  var MGCopyAnswer = new NativeFunction(mg, 'pointer', ['pointer']);
  var CFStringCreateWithCString = new NativeFunction(cfCreate, 'pointer', ['pointer','pointer','uint']);
  var CFCopyDescription = new NativeFunction(cfDesc, 'pointer', ['pointer']);
  var CFStringGetCString = new NativeFunction(cfGetC, 'bool', ['pointer','pointer','long','uint']);
  var CFRelease = cfRelease ? new NativeFunction(cfRelease, 'void', ['pointer']) : null;

  var keyStr = CFStringCreateWithCString(NULL, Memory.allocUtf8String(key), kUTF8);
  if (keyStr.isNull()) return '(key alloc failed)';
  var ans = MGCopyAnswer(keyStr);
  var res;
  if (ans.isNull()) { res = '(null / not present)'; }
  else {
    var desc = CFCopyDescription(ans);
    var buf = Memory.alloc(1024);
    var ok = CFStringGetCString(desc, buf, 1024, kUTF8);
    res = ok ? buf.readUtf8String() : '(uncopyable)';
    if (CFRelease && !desc.isNull()) CFRelease(desc);
    if (CFRelease) CFRelease(ans);
  }
  if (CFRelease) CFRelease(keyStr);
  return res;
}

var MG_KEYS = [
  ['DeveloperModeStatus','Developer Mode'],
  ['ProductType','Model id'],
  ['ProductVersion','iOS version'],
  ['BuildVersion','Build'],
  ['RegionInfo','Region'],
  ['DeviceColor','Color'],
  ['EffectiveProductionStatusAp','Production-status AP'],
  ['SigningFuse','Signing fuse'],
  ['InternalBuild','Internal build'],
];
MG_KEYS.forEach(function(k){ out.gestalt[k[1] + '  [' + k[0] + ']'] = mgRead(k[0]); });

send(out);
"""


def main():
    dev = frida.get_usb_device(timeout=5)

    # Attach is flaky on this rig, but spawn is reliable. Spawn Settings, resume it
    # so UIKit comes up (the accessibility C funcs need a live UIKit), read the cold
    # values, then kill it. Running a benign app is unrelated to the hot-hook freeze.
    print("  spawning Settings to read live device state, then killing it")
    pid = dev.spawn(["com.apple.Preferences"])
    session = dev.attach(pid)
    dev.resume(pid)
    time.sleep(4.0)  # let UIKit finish launching

    result = {"v": None}
    done = {"f": False}

    def on_message(message, data):
        if message["type"] == "error":
            print("  script error:", message.get("description"))
        else:
            result["v"] = message.get("payload")
        done["f"] = True

    script = session.create_script(JS)
    script.on("message", on_message)
    script.load()
    t0 = time.time()
    while not done["f"] and time.time() - t0 < 20:
        time.sleep(0.05)
    try:
        script.unload()
        session.detach()
    except Exception:
        pass
    try:
        dev.kill(pid)
    except Exception:
        pass

    r = result["v"] or {}
    print("\n" + "=" * 60)
    print("  ACCESSIBILITY STATE (device-wide, what TikTok can read)")
    print("=" * 60)
    for k, v in (r.get("access") or {}).items():
        mark = "  >>" if v == "ON" else "    "
        print(f"{mark} {k:20} {v}")
    print("\n" + "=" * 60)
    print("  MOBILEGESTALT (Developer Mode + device identity)")
    print("=" * 60)
    for k, v in (r.get("gestalt") or {}).items():
        print(f"    {k:42} {v}")
    print("=" * 60)


if __name__ == "__main__":
    main()
