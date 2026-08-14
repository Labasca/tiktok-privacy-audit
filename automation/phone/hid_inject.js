/*
 * IOHID digitizer injection, loaded into SpringBoard.
 *
 * This is the whole point of driving the phone from outside TikTok:
 * IOHIDEventSystemClientDispatchEvent posts into the system event
 * stream. TikTok then sees a UIEvent whose _hidEvent() is non-null,
 * which is the opposite of a UITouch synthesized inside its own
 * process (and the opposite of WebDriverAgent).
 *
 * What we can fill (and what the observer already measures):
 *   majorRadius / minorRadius   via FingerEventWithQuality
 *   pressure                    tipPressure
 *   several samples per tap     we emit N child events before lift
 *   built-in / display-integrated flags
 *
 * What we cannot honestly promise:
 *   that UIKit will report coalescedTouches the way a real digitizer
 *   does, or that majorRadius will survive in points the way a thumb
 *   does. The observer's -Touch probe is the measurement. This file
 *   just makes the best HID event we can and records what we sent.
 *
 * NativeFunction only. Frida 17 dropped the ObjC global; this script
 * does not need it, so it does not need frida-compile.
 */
'use strict';

function exp(name) {
  try { return Module.getGlobalExportByName(name); } catch (e) { return null; }
}

var IOHIDEventCreateDigitizerEvent = new NativeFunction(
  exp('IOHIDEventCreateDigitizerEvent'),
  'pointer', ['pointer','uint64','int','uint32','uint32','uint32','uint32',
              'float','float','float','float','float','bool','bool','int']);
var IOHIDEventCreateDigitizerFingerEvent = new NativeFunction(
  exp('IOHIDEventCreateDigitizerFingerEvent'),
  'pointer', ['pointer','uint64','uint32','uint32','uint32',
              'float','float','float','float','float','bool','bool','int']);
var IOHIDEventCreateDigitizerFingerEventWithQuality = new NativeFunction(
  exp('IOHIDEventCreateDigitizerFingerEventWithQuality'),
  'pointer', ['pointer','uint64','uint32','uint32','uint32',
              'float','float','float','float','float',
              'float','float','float','float','float','float',
              'bool','bool','int']);
var IOHIDEventAppendEvent = new NativeFunction(exp('IOHIDEventAppendEvent'), 'void', ['pointer','pointer']);
var IOHIDEventSetIntegerValue = new NativeFunction(exp('IOHIDEventSetIntegerValue'), 'void', ['pointer','int','int64']);
var IOHIDEventSetFloatValue = new NativeFunction(exp('IOHIDEventSetFloatValue'), 'void', ['pointer','int','float']);
var IOHIDEventSetSenderID = new NativeFunction(exp('IOHIDEventSetSenderID'), 'void', ['pointer','uint64']);
var IOHIDEventSystemClientCreate = new NativeFunction(exp('IOHIDEventSystemClientCreate'), 'pointer', ['pointer']);
var IOHIDEventSystemClientCreateWithType = exp('IOHIDEventSystemClientCreateWithType')
  ? new NativeFunction(exp('IOHIDEventSystemClientCreateWithType'), 'pointer', ['pointer','int','pointer'])
  : null;
var IOHIDEventSystemClientDispatchEvent = new NativeFunction(exp('IOHIDEventSystemClientDispatchEvent'), 'void', ['pointer','pointer']);
var IOHIDEventSystemClientScheduleWithRunLoop = exp('IOHIDEventSystemClientScheduleWithRunLoop')
  ? new NativeFunction(exp('IOHIDEventSystemClientScheduleWithRunLoop'), 'void', ['pointer','pointer','pointer'])
  : null;
var CFRunLoopGetMain = new NativeFunction(exp('CFRunLoopGetMain'), 'pointer', []);
var kCFRunLoopDefaultMode = Module.getGlobalExportByName('kCFRunLoopDefaultMode').readPointer();
var CFRelease = new NativeFunction(exp('CFRelease'), 'void', ['pointer']);
var mach_absolute_time = new NativeFunction(exp('mach_absolute_time'), 'uint64', []);

// IOHIDEventField: (type << 16) | index. Digitizer = 11.
var kDigitizerX = 0x000b0000;
var kDigitizerY = 0x000b0001;
var kDigitizerMajorRadius = 0x000b0014;
var kDigitizerMinorRadius = 0x000b0015;
var kDigitizerIsDisplayIntegrated = 0x000b0019;
// Generic built-in flag, used by SimulateTouch / zxtouch.
// NULL-type field 31. 0x4001f was wrong and the events went nowhere.
var kIsBuiltIn = 0x0000001f;

// Hand transducer, event-mask bits: Range=1 Touch=2 Position=4 Identity=32
var MASK_DOWN = 1 | 2 | 32;
var MASK_MOVE = 2 | 4;
var MASK_UP   = 1 | 2 | 32;

// Type 0 (admin) is the constructor that actually returns a client
// on this phone. A bare Create() looked non-null in ping() and still
// delivered nothing.
var client = IOHIDEventSystemClientCreateWithType
  ? IOHIDEventSystemClientCreateWithType(ptr(0), 0, ptr(0))
  : IOHIDEventSystemClientCreate(ptr(0));
if (IOHIDEventSystemClientScheduleWithRunLoop && client && !client.isNull()) {
  IOHIDEventSystemClientScheduleWithRunLoop(client, CFRunLoopGetMain(), kCFRunLoopDefaultMode);
}
var senderId = uint64('0x8000000817319375');
var last = { x: 0.5, y: 0.5, down: false };

function dispatch(x, y, touch, mask, opts) {
  opts = opts || {};
  var pressure = (opts.pressure !== undefined) ? opts.pressure : (touch ? 0.55 : 0);
  var major = (opts.major !== undefined) ? opts.major : 0.008;
  var minor = (opts.minor !== undefined) ? opts.minor : 0.007;
  var ts = mach_absolute_time();

  var parent = IOHIDEventCreateDigitizerEvent(
    ptr(0), ts, 3 /* hand */, 0, 0, mask, 0,
    x, y, 0, 0, 0, 1, touch ? 1 : 0, 0);
  IOHIDEventSetIntegerValue(parent, kIsBuiltIn, 1);
  IOHIDEventSetIntegerValue(parent, kDigitizerIsDisplayIntegrated, 1);

  var child = IOHIDEventCreateDigitizerFingerEvent(
    ptr(0), ts, 1, 3, mask,
    x, y, 0, pressure, 0,
    touch ? 1 : 0, touch ? 1 : 0, 0);
  IOHIDEventSetFloatValue(child, kDigitizerX, x);
  IOHIDEventSetFloatValue(child, kDigitizerY, y);
  IOHIDEventSetFloatValue(child, kDigitizerMajorRadius, major);
  IOHIDEventSetFloatValue(child, kDigitizerMinorRadius, minor);
  IOHIDEventAppendEvent(parent, child);
  IOHIDEventSetSenderID(parent, senderId);
  IOHIDEventSystemClientDispatchEvent(client, parent);
  CFRelease(child);
  CFRelease(parent);
}

function sleepMs(ms) {
  var end = Date.now() + ms;
  while (Date.now() < end) { /* busy: SpringBoard's JS thread is fine for <30ms */ }
}

var IOHIDEventCreateKeyboardEvent = exp('IOHIDEventCreateKeyboardEvent')
  ? new NativeFunction(exp('IOHIDEventCreateKeyboardEvent'),
      'pointer', ['pointer','uint64','uint16','uint16','bool','int'])
  : null;

rpc.exports = {
  ping: function () {
    return {
      ok: !client.isNull(),
      sender: senderId.toString(),
      last: last,
    };
  },
  setSender: function (hex) {
    senderId = uint64(hex);
    return senderId.toString();
  },
  down: function (x, y, opts) {
    last = { x: x, y: y, down: true };
    dispatch(x, y, true, MASK_DOWN, opts || {});
    return last;
  },
  move: function (x, y, opts) {
    last = { x: x, y: y, down: true };
    dispatch(x, y, true, MASK_MOVE, opts || {});
    return last;
  },
  up: function (x, y, opts) {
    x = (x === undefined || x === null) ? last.x : x;
    y = (y === undefined || y === null) ? last.y : y;
    last = { x: x, y: y, down: false };
    dispatch(x, y, false, MASK_UP, opts || {});
    return last;
  },
  tap: function (x, y, opts) {
    opts = opts || {};
    var hold = (opts.hold_ms !== undefined) ? opts.hold_ms : 70;
    var samples = (opts.samples !== undefined) ? opts.samples : 3;
    dispatch(x, y, true, MASK_DOWN, opts);
    for (var i = 1; i < samples; i++) {
      sleepMs(Math.max(4, Math.floor(hold / samples)));
      // sub-pixel jitter so UIKit has more than one sample to coalesce
      var jx = x + (i % 2 === 0 ? 0.0004 : -0.0004);
      var jy = y + (i % 2 === 0 ? -0.0003 : 0.0003);
      dispatch(jx, jy, true, MASK_MOVE, opts);
    }
    sleepMs(8);
    dispatch(x, y, false, MASK_UP, opts);
    last = { x: x, y: y, down: false };
    return { x: x, y: y, samples: samples, hold_ms: hold, major: opts.major || 0.008 };
  },
  key: function (page, usage, down) {
    if (!IOHIDEventCreateKeyboardEvent) return { ok: false, error: 'no keyboard event' };
    var ts = mach_absolute_time();
    var ev = IOHIDEventCreateKeyboardEvent(ptr(0), ts, page, usage, down ? 1 : 0, 0);
    IOHIDEventSetSenderID(ev, senderId);
    IOHIDEventSystemClientDispatchEvent(client, ev);
    CFRelease(ev);
    return { ok: true, page: page, usage: usage, down: !!down };
  },
  swipe: function (x1, y1, x2, y2, opts) {
    opts = opts || {};
    var ms = (opts.ms !== undefined) ? opts.ms : 280;
    var steps = (opts.steps !== undefined) ? opts.steps : 14;
    dispatch(x1, y1, true, MASK_DOWN, opts);
    for (var i = 1; i <= steps; i++) {
      var t = i / steps;
      sleepMs(Math.max(4, Math.floor(ms / steps)));
      dispatch(x1 + (x2 - x1) * t, y1 + (y2 - y1) * t, true, MASK_MOVE, opts);
    }
    dispatch(x2, y2, false, MASK_UP, opts);
    last = { x: x2, y: y2, down: false };
    return { x1: x1, y1: y1, x2: x2, y2: y2, steps: steps, ms: ms };
  }
};
