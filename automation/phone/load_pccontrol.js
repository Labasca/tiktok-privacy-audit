/*
 * SpringBoard only. dlopen ZXTouch's HID server if ElleKit did not.
 */
'use strict';

var PATHS = [
  '/var/jb/usr/lib/TweakInject/pccontrol.dylib',
  '/private/preboot/0B399BFFD6F198DB6595DB968476B0C62A7DC82A23B0E6AEC83519716061BF2B386F5F26AFFD0EF3FBF02522D95A0CE3/jb-l4r2dXnW/procursus/usr/lib/TweakInject/pccontrol.dylib'
];

rpc.exports = {
  status: function () {
    var mod = Process.findModuleByName('pccontrol.dylib');
    if (!mod) return { loaded: false };
    function u8(name) {
      try { return mod.getExportByName(name).readU8(); } catch (e) { return String(e); }
    }
    function ptrv(name) {
      try { return mod.getExportByName(name).readPointer().toString(); } catch (e) { return String(e); }
    }
    return {
      loaded: true,
      path: mod.path,
      isInitializedSuccess: u8('isInitializedSuccess'),
      socketRef: ptrv('socketRef'),
      daemonSock: ptrv('daemonSock'),
      senderID: (function () {
        try { return mod.getExportByName('senderID').readU64().toString(); } catch (e) { return String(e); }
      })()
    };
  },
  startSocket: function () {
    var mod = Process.findModuleByName('pccontrol.dylib');
    if (!mod) return { error: 'not loaded' };
    var socketServer = new NativeFunction(mod.getExportByName('_Z12socketServerv'), 'void', []);
    var getq = new NativeFunction(
      Module.getGlobalExportByName('dispatch_get_global_queue'),
      'pointer', ['long', 'ulong']
    );
    var asyncf = new NativeFunction(
      Module.getGlobalExportByName('dispatch_async_f'),
      'void', ['pointer', 'pointer', 'pointer']
    );
    var cb = new NativeCallback(function (_ctx) {
      socketServer();
    }, 'void', ['pointer']);
    asyncf(getq(0, 0), ptr(0), cb);
    return { ok: true, queued: true };
  },
  load: function () {
    function start(mod) {
      var started = [];
      function callExp(name) {
        try {
          var addr = mod.getExportByName(name);
          var fn = new NativeFunction(addr, 'void', []);
          fn();
          started.push({ name: name, ok: true });
        } catch (e) {
          started.push({ name: name, ok: false, error: String(e) });
        }
      }
      callExp('_Z4initv');
      return started;
    }
    var already = Process.findModuleByName('pccontrol.dylib');
    if (already) {
      return {
        ok: true, already: true, path: already.path,
        base: already.base.toString(), started: start(already)
      };
    }
    var dlopen = new NativeFunction(
      Module.getGlobalExportByName('dlopen'),
      'pointer', ['pointer', 'int']
    );
    var dlerror = new NativeFunction(
      Module.getGlobalExportByName('dlerror'),
      'pointer', []
    );
    var tried = [];
    for (var i = 0; i < PATHS.length; i++) {
      var p = PATHS[i];
      var handle = dlopen(Memory.allocUtf8String(p), 2); // RTLD_NOW
      var err = dlerror();
      var rec = {
        path: p,
        handle: handle.isNull() ? null : handle.toString(),
        error: err.isNull() ? null : err.readUtf8String()
      };
      tried.push(rec);
      var mod = Process.findModuleByName('pccontrol.dylib');
      if (mod) {
        return {
          ok: true, already: false, path: mod.path,
          base: mod.base.toString(), tried: tried, started: start(mod)
        };
      }
    }
    return { ok: false, tried: tried };
  }
};
