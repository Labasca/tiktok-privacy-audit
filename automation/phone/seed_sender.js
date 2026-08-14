/*
 * SpringBoard only. Inspect pccontrol + IOHID, plant a digitizer sender ID.
 */
'use strict';

function exp(name) {
  try { return Module.getGlobalExportByName(name); } catch (e) { return null; }
}

function hex(n) {
  if (n === null || n === undefined) return 'null';
  try { return '0x' + BigInt(n).toString(16); } catch (e) { return String(n); }
}

function listIOHID() {
  var names = [];
  Process.enumerateModules().forEach(function (m) {
    if (m.name.indexOf('IOKit') === -1 && m.name.indexOf('IOHID') === -1 &&
        m.name.indexOf('HID') === -1) return;
    try {
      m.enumerateExports().forEach(function (e) {
        if (e.name && e.name.indexOf('IOHID') !== -1) names.push(m.name + '!' + e.name);
      });
    } catch (err) {}
  });
  return names.sort();
}

rpc.exports = {
  inspect: function () {
    var report = { modules: [], iohid: [], symbols: [], error: null };
    Process.enumerateModules().forEach(function (m) {
      if (/pccontrol|appdelegate|ellekit|TweakInject|substrate/i.test(m.name + m.path)) {
        report.modules.push({ name: m.name, base: hex(m.base), path: m.path, size: m.size });
      }
    });
    var mod = Process.findModuleByName('pccontrol.dylib');
    if (!mod) {
      report.error = 'pccontrol.dylib not loaded';
      return report;
    }
    try {
      mod.enumerateSymbols().forEach(function (s) {
        if (s.name && /sender|Sender|initTouch|postIOHID|performTouch/i.test(s.name)) {
          report.symbols.push({ name: s.name, addr: hex(s.address), type: s.type });
        }
      });
    } catch (e) {
      report.symErr = String(e);
    }
    try {
      mod.enumerateExports().forEach(function (e) {
        report.symbols.push({ name: 'export:' + e.name, addr: hex(e.address), type: e.type });
      });
    } catch (e) {
      report.expErr = String(e);
    }
    report.iohid = listIOHID();
    return report;
  },

  readSender: function () {
    var addr = Process.findModuleByName('pccontrol.dylib').getExportByName('senderID');
    return { ptr: hex(addr), value: hex(addr.readU64()) };
  },

  plant: function (idHex) {
    var addr = Process.findModuleByName('pccontrol.dylib').getExportByName('senderID');
    var before = hex(addr.readU64());
    addr.writeU64(uint64(idHex));
    return { ok: true, ptr: hex(addr), before: before, after: hex(addr.readU64()) };
  },

  discover: function () {
    var report = { services: [], picked: null, senderBefore: null, senderAfter: null, error: null };
    var senderAddr = Process.findModuleByName('pccontrol.dylib').getExportByName('senderID');
    report.senderBefore = senderAddr.readU64().toString();
    try {
      var getDoc = new NativeFunction(
        Process.findModuleByName('pccontrol.dylib').getExportByName('_Z15getDocumentRootv'),
        'pointer', []
      );
      var doc = getDoc();
      if (!doc.isNull()) {
        // NSString *
        var ns = new ObjC.Object(doc);
        report.documentRoot = ns.toString();
      }
    } catch (e) {
      report.documentRootErr = String(e);
    }

    var kCFAllocatorDefault = Module.getGlobalExportByName('kCFAllocatorDefault').readPointer();
    var create = new NativeFunction(exp('IOHIDEventSystemClientCreate'), 'pointer', ['pointer']);
    var createTyped = exp('IOHIDEventSystemClientCreateWithType')
      ? new NativeFunction(exp('IOHIDEventSystemClientCreateWithType'), 'pointer', ['pointer', 'int', 'pointer'])
      : null;
    var copy = new NativeFunction(exp('IOHIDEventSystemClientCopyServices'), 'pointer', ['pointer']);
    var schedule = new NativeFunction(exp('IOHIDEventSystemClientScheduleWithRunLoop'), 'void', ['pointer', 'pointer', 'pointer']);
    var mainLoop = new NativeFunction(exp('CFRunLoopGetMain'), 'pointer', []);
    var defaultMode = Module.getGlobalExportByName('kCFRunLoopDefaultMode').readPointer();
    var arrCount = new NativeFunction(exp('CFArrayGetCount'), 'long', ['pointer']);
    var arrAt = new NativeFunction(exp('CFArrayGetValueAtIndex'), 'pointer', ['pointer', 'long']);
    var conforms = new NativeFunction(exp('IOHIDServiceClientConformsTo'), 'bool', ['pointer', 'uint32', 'uint32']);
    var getReg = new NativeFunction(exp('IOHIDServiceClientGetRegistryID'), 'uint64', ['pointer']);
    var copyProp = new NativeFunction(exp('IOHIDServiceClientCopyProperty'), 'pointer', ['pointer', 'pointer']);
    var cfRelease = new NativeFunction(exp('CFRelease'), 'void', ['pointer']);
    var cfStr = new NativeFunction(exp('CFStringCreateWithCString'), 'pointer', ['pointer', 'pointer', 'uint32']);
    var cfGetType = new NativeFunction(exp('CFGetTypeID'), 'ulong', ['pointer']);
    var numType = new NativeFunction(exp('CFNumberGetTypeID'), 'ulong', [])();
    var strType = new NativeFunction(exp('CFStringGetTypeID'), 'ulong', [])();
    var numVal = new NativeFunction(exp('CFNumberGetValue'), 'bool', ['pointer', 'int', 'pointer']);
    var strGet = new NativeFunction(exp('CFStringGetCString'), 'bool', ['pointer', 'pointer', 'long', 'uint32']);

    function readProp(svc, key) {
      var ks = cfStr(kCFAllocatorDefault, Memory.allocUtf8String(key), 0x08000100);
      var val = copyProp(svc, ks);
      cfRelease(ks);
      if (val.isNull()) return null;
      var tid = Number(cfGetType(val));
      var out = null;
      if (tid === Number(numType)) {
        var buf = Memory.alloc(8);
        if (numVal(val, 4, buf)) out = Number(buf.readS64());
      } else if (tid === Number(strType)) {
        var sbuf = Memory.alloc(256);
        if (strGet(val, sbuf, 256, 0x08000100)) out = sbuf.readUtf8String();
      }
      cfRelease(val);
      return out;
    }

    var pickedRid = null;
    function collect(client, tag) {
      if (client.isNull()) return;
      var services = copy(client);
      if (services.isNull()) return;
      var n = Number(arrCount(services));
      for (var i = 0; i < n; i++) {
        var svc = arrAt(services, i);
        if (svc.isNull()) continue;
        var rid = getReg(svc);
        var rec = {
          tag: tag,
          index: i,
          registry: rid.toString(),
          registryHex: '0x' + rid.toString(16),
          product: readProp(svc, 'Product'),
          transport: readProp(svc, 'Transport'),
          usagePage: readProp(svc, 'PrimaryUsagePage'),
          usage: readProp(svc, 'PrimaryUsage'),
          digitizer: false,
          touchScreen: false
        };
        try { rec.digitizer = !!conforms(svc, 0x0d, 0); } catch (e) {}
        try { rec.touchScreen = !!conforms(svc, 0x0d, 0x04); } catch (e) {}
        try { rec.touchPad = !!conforms(svc, 0x0d, 0x05); } catch (e) {}
        // Prefer the real SPI digitizer over AssistiveTouch's virtual one.
        var isReal = rec.touchScreen && rec.transport === 'SPI';
        var isAny = rec.touchScreen || rec.usagePage === 13;
        report.services.push(rec);
        if (isReal) { report.picked = rec; pickedRid = rid; }
        else if (!pickedRid && isAny && rec.transport !== 'AXPIFingerTransport') {
          report.picked = rec;
          pickedRid = rid;
        }
      }
      cfRelease(services);
    }

    var client = create(kCFAllocatorDefault);
    collect(client, 'create');
    if (createTyped) {
      var typed = createTyped(kCFAllocatorDefault, 0, ptr(0));
      if (!typed.isNull()) {
        schedule(typed, mainLoop(), defaultMode);
        collect(typed, 'typed0');
      }
    }

    if (pickedRid) {
      senderAddr.writeU64(pickedRid);
      var after = senderAddr.readU64();
      report.senderAfter = after.toString();
      report.senderAfterHex = '0x' + after.toString(16);
    } else {
      report.error = 'no digitizer service found';
    }
    return report;
  }
};
