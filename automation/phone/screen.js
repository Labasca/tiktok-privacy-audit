/*
 * Full-screen snapshot from SpringBoard. Not TikTok.
 *
 * The frontmost app is on screen; we snapshot the display, we do not
 * attach to it. That is how the poster watches the glass without
 * entering TikTok's process or reading its obfuscated view tree.
 *
 * Needs frida-compile (UIImage / UIImagePNGRepresentation).
 */
'use strict';

import ObjC from 'frida-objc-bridge';

function pngOfImage(img) {
  if (!img || img.isNull()) return null;
  const UIImagePNGRepresentation = new NativeFunction(
    Module.getGlobalExportByName('UIImagePNGRepresentation'),
    'pointer', ['pointer']);
  const data = new ObjC.Object(UIImagePNGRepresentation(img));
  if (!data || data.isNull()) return null;
  const n = Number(data.length());
  if (!(n > 0) || n > 12 * 1024 * 1024) return null;
  return { bytes: n, png: data.bytes().readByteArray(n) };
}

rpc.exports = {
  ping: function () {
    let create = null;
    try { create = Module.getGlobalExportByName('_UICreateScreenUIImage'); } catch (e) {}
    return {
      ok: true,
      create: !!create,
      uikit: !!ObjC.classes.UIImage,
    };
  },

  tapNorm: function (x, y) {
    // Dispatch on the main run loop. Events sent from Frida's JS
    // thread were accepted by IOHID and ignored by the digitizer.
    const create = new NativeFunction(
      Module.getGlobalExportByName('IOHIDEventCreateDigitizerEvent'),
      'pointer', ['pointer','uint64','int','uint32','uint32','uint32','uint32',
                  'float','float','float','float','float','bool','bool','int']);
    const finger = new NativeFunction(
      Module.getGlobalExportByName('IOHIDEventCreateDigitizerFingerEvent'),
      'pointer', ['pointer','uint64','uint32','uint32','uint32',
                  'float','float','float','float','float','bool','bool','int']);
    const append = new NativeFunction(Module.getGlobalExportByName('IOHIDEventAppendEvent'), 'void', ['pointer','pointer']);
    const setInt = new NativeFunction(Module.getGlobalExportByName('IOHIDEventSetIntegerValue'), 'void', ['pointer','int','int64']);
    const setSender = new NativeFunction(Module.getGlobalExportByName('IOHIDEventSetSenderID'), 'void', ['pointer','uint64']);
    const mkClient = new NativeFunction(Module.getGlobalExportByName('IOHIDEventSystemClientCreateWithType'), 'pointer', ['pointer','int','pointer']);
    const dispatch = new NativeFunction(Module.getGlobalExportByName('IOHIDEventSystemClientDispatchEvent'), 'void', ['pointer','pointer']);
    const now = new NativeFunction(Module.getGlobalExportByName('mach_absolute_time'), 'uint64', []);
    const rel = new NativeFunction(Module.getGlobalExportByName('CFRelease'), 'void', ['pointer']);
    const client = mkClient(ptr(0), 0, ptr(0));
    const sender = uint64('0x8000000817319375');
    function fire(touch, mask) {
      const ts = now();
      const parent = create(ptr(0), ts, 3, 0, 0, mask, 0, x, y, 0, 0, 0, 1, touch ? 1 : 0, 0);
      setInt(parent, 0x1f, 1);
      setInt(parent, 0xb0019, 1);
      const child = finger(ptr(0), ts, 1, 3, mask, x, y, 0, 0.5, 0, touch ? 1 : 0, touch ? 1 : 0, 0);
      append(parent, child);
      setSender(parent, sender);
      dispatch(client, parent);
      rel(child);
      rel(parent);
    }
    const enqueue = ObjC.classes.UIApplication.sharedApplication()
      && ObjC.classes.UIApplication.sharedApplication()['_enqueueHIDEvent:'];
    ObjC.schedule(ObjC.mainQueue, function () {
      function fire2(touch, mask) {
        const ts = now();
        const parent = create(ptr(0), ts, 3, 1, 3, mask, 0, x, y, 0, 0, 0, 1, touch ? 1 : 0, 0);
        setInt(parent, 0x1f, 1);
        setInt(parent, 0xb0019, 1);
        const child = finger(ptr(0), ts, 1, 3, mask, x, y, 0, 0.5, 0, touch ? 1 : 0, touch ? 1 : 0, 0);
        append(parent, child);
        setSender(parent, sender);
        if (enqueue) {
          try { ObjC.classes.UIApplication.sharedApplication()._enqueueHIDEvent_(parent); }
          catch (e) { dispatch(client, parent); }
        } else {
          dispatch(client, parent);
        }
        rel(child);
        rel(parent);
      }
      fire2(true, 1|2|32);
      fire2(true, 2|4);
      fire2(false, 1|2|32);
    });
    return { scheduled: true, x: x, y: y, enqueue: !!enqueue };
  },

  snapshot: function () {
    const createPtr = Module.getGlobalExportByName('_UICreateScreenUIImage');
    const create = new NativeFunction(createPtr, 'pointer', []);
    const img = create();
    if (img.isNull()) return { ok: false, error: '_UICreateScreenUIImage returned nil' };
    const wrapped = new ObjC.Object(img);
    const got = pngOfImage(wrapped);
    if (!got) return { ok: false, error: 'PNG encode failed' };
    send({ ok: true, bytes: got.bytes }, got.png);
    return { ok: true, bytes: got.bytes };
  },
};
