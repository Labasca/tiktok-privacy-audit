/*
 * One-shot HID experiments. NativeFunction only. Loaded into whoever
 * we are trying as a host (SpringBoard or a root helper). Not TikTok.
 */
'use strict';

function exp(n) {
  try { return Module.getGlobalExportByName(n); } catch (e) { return null; }
}

function ensureIOKit() {
  if (exp('IOHIDEventSystemClientDispatchEvent')) return 'already';
  var paths = [
    '/System/Library/Frameworks/IOKit.framework/IOKit',
    '/System/Library/Frameworks/IOKit.framework/Versions/A/IOKit',
  ];
  for (var i = 0; i < paths.length; i++) {
    try { Module.load(paths[i]); return paths[i]; } catch (e) {}
  }
  return 'missing';
}

var loaded = ensureIOKit();

function NF(name, ret, args) {
  var p = exp(name);
  if (!p) return null;
  return new NativeFunction(p, ret, args);
}

var createEv = NF('IOHIDEventCreateDigitizerEvent', 'pointer',
  ['pointer','uint64','int','uint32','uint32','uint32','uint32',
   'float','float','float','float','float','bool','bool','int']);
var createFinger = NF('IOHIDEventCreateDigitizerFingerEvent', 'pointer',
  ['pointer','uint64','uint32','uint32','uint32',
   'float','float','float','float','float','bool','bool','int']);
var append = NF('IOHIDEventAppendEvent', 'void', ['pointer','pointer']);
var setInt = NF('IOHIDEventSetIntegerValue', 'void', ['pointer','int','int64']);
var setSender = NF('IOHIDEventSetSenderID', 'void', ['pointer','uint64']);
var mkClientTyped = NF('IOHIDEventSystemClientCreateWithType', 'pointer', ['pointer','int','pointer']);
var mkClientPlain = NF('IOHIDEventSystemClientCreate', 'pointer', ['pointer']);
var mkSimple = NF('IOHIDEventSystemClientCreateSimpleClient', 'pointer', ['pointer']);
var dispatch = NF('IOHIDEventSystemClientDispatchEvent', 'void', ['pointer','pointer']);
var now = NF('mach_absolute_time', 'uint64', []);
var rel = NF('CFRelease', 'void', ['pointer']);
var sched = NF('IOHIDEventSystemClientScheduleWithRunLoop', 'void', ['pointer','pointer','pointer']);
var CFRunLoopGetMain = NF('CFRunLoopGetMain', 'pointer', []);
var GSSendEvent = NF('GSSendEvent', 'void', ['pointer','uint32']);
var GSGetPurple = NF('GSGetPurpleSystemEventPort', 'uint32', []);
var sendFocused = NF('BKSHIDEventSendToFocusedProcess', 'void', ['pointer']);
var sendToApp = NF('BKSHIDEventSendToApplicationWithBundleIDAndPid', 'void', ['pointer','pointer','int']);
var cfstr = NF('CFStringCreateWithCString', 'pointer', ['pointer','pointer','uint32']);

function makeClient() {
  var c = null;
  var how = [];
  if (mkClientTyped) {
    for (var typ = 0; typ <= 4; typ++) {
      try {
        c = mkClientTyped(ptr(0), typ, ptr(0));
        if (c && !c.isNull()) { how.push('typed-'+typ); break; }
      } catch (e) { how.push('typed-'+typ+'-err'); }
    }
  }
  if ((!c || c.isNull()) && mkClientPlain) {
    try { c = mkClientPlain(ptr(0)); if (c && !c.isNull()) how.push('plain'); } catch (e) { how.push('plain-err'); }
  }
  if ((!c || c.isNull()) && mkSimple) {
    try { c = mkSimple(ptr(0)); if (c && !c.isNull()) how.push('simple'); } catch (e) { how.push('simple-err'); }
  }
  if (c && !c.isNull() && sched && CFRunLoopGetMain) {
    try {
      var mode = Module.getGlobalExportByName('kCFRunLoopDefaultMode').readPointer();
      sched(c, CFRunLoopGetMain(), mode);
      how.push('scheduled');
    } catch (e) { how.push('sched-err'); }
  }
  return { c: c, how: how };
}

var made = makeClient();
var client = made.c;

function sendDigitizer(x, y, touch, mask, senderHex) {
  if (!createEv || !createFinger || !dispatch || !client || client.isNull()) {
    return 'no-client';
  }
  var ts = now();
  var parent = createEv(ptr(0), ts, 3, 1, 3, mask, 0, x, y, 0, 0, 0, 1, touch ? 1 : 0, 0);
  setInt(parent, 0x1f, 1);
  setInt(parent, 0xb0019, 1);
  var child = createFinger(ptr(0), ts, 1, 3, mask, x, y, 0, 0.5, 0, touch ? 1 : 0, touch ? 1 : 0, 0);
  append(parent, child);
  if (senderHex) setSender(parent, uint64(senderHex));
  dispatch(client, parent);
  rel(child);
  rel(parent);
  return 'sent';
}

rpc.exports = {
  info: function () {
    return {
      loaded: loaded,
      hasCreate: !!createEv,
      hasDispatch: !!dispatch,
      hasClient: !!(client && !client.isNull()),
      how: made.how,
      hasGS: !!GSSendEvent,
      hasPurple: !!GSGetPurple,
      hasFocused: !!sendFocused,
      hasToApp: !!sendToApp,
    };
  },
  tap: function (x, y, senderHex) {
    sendDigitizer(x, y, 1, 1|2|32, senderHex);
    sendDigitizer(x, y, 1, 2|4, senderHex);
    sendDigitizer(x, y, 0, 1|2|32, senderHex);
    return { x: x, y: y, sender: senderHex || 'none' };
  },
  tapMasks: function (x, y, senderHex) {
    sendDigitizer(x, y, 1, 3, senderHex);
    sendDigitizer(x, y, 0, 2, senderHex);
    return { x: x, y: y, pair: '3/2' };
  },
  tapFocused: function (x, y, senderHex) {
    if (!sendFocused || !createEv) return { ok: false, error: 'no BKS send' };
    function one(touch, mask) {
      var ts = now();
      var parent = createEv(ptr(0), ts, 3, 1, 3, mask, 0, x, y, 0, 0, 0, 1, touch ? 1 : 0, 0);
      setInt(parent, 0x1f, 1);
      setInt(parent, 0xb0019, 1);
      var child = createFinger(ptr(0), ts, 1, 3, mask, x, y, 0, 0.5, 0, touch ? 1 : 0, touch ? 1 : 0, 0);
      append(parent, child);
      if (senderHex) setSender(parent, uint64(senderHex));
      sendFocused(parent);
      rel(child);
      rel(parent);
    }
    one(1, 1|2|32);
    one(1, 2|4);
    one(0, 1|2|32);
    return { ok: true, via: 'focused', x: x, y: y };
  },
  tapApp: function (x, y, bundle, pid, senderHex) {
    if (!sendToApp || !cfstr) return { ok: false, error: 'no BKS sendToApp' };
    var name = Memory.allocUtf8String(bundle);
    var bid = cfstr(ptr(0), name, 0x08000100);
    function one(touch, mask) {
      var ts = now();
      var parent = createEv(ptr(0), ts, 3, 1, 3, mask, 0, x, y, 0, 0, 0, 1, touch ? 1 : 0, 0);
      setInt(parent, 0x1f, 1);
      setInt(parent, 0xb0019, 1);
      var child = createFinger(ptr(0), ts, 1, 3, mask, x, y, 0, 0.5, 0, touch ? 1 : 0, touch ? 1 : 0, 0);
      append(parent, child);
      if (senderHex) setSender(parent, uint64(senderHex));
      sendToApp(parent, bid, pid);
      rel(child);
      rel(parent);
    }
    one(1, 1|2|32);
    one(1, 2|4);
    one(0, 1|2|32);
    if (rel && bid && !bid.isNull()) rel(bid);
    return { ok: true, via: 'app', bundle: bundle, pid: pid, x: x, y: y };
  },
  gsTap: function (x, y, typeDown, typeUp, locOff) {
    if (!GSSendEvent || !GSGetPurple) return { ok: false, error: 'no GS' };
    var port = GSGetPurple();
    var rec = Memory.alloc(0x200);
    for (var i = 0; i < 0x200; i += 8) rec.add(i).writeU64(uint64(0));
    rec.add(0).writeU32(typeDown);
    rec.add(locOff).writeFloat(x);
    rec.add(locOff + 4).writeFloat(y);
    GSSendEvent(rec, port);
    rec.add(0).writeU32(typeUp);
    GSSendEvent(rec, port);
    return { ok: true, via: 'gs', port: port, typeDown: typeDown, locOff: locOff };
  },
};
