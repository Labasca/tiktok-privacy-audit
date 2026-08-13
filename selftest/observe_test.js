/*
 * observe_test.js  -  run the phone-side script on a laptop, with no phone.
 *
 * observe.js has never executed anywhere except inside TikTok, which is a
 * terrible place to find out that a walk throws on the first nil it meets. The
 * hooks cannot be tested there without burning an account and a post, so this
 * runs the REAL observe.js source against a stubbed Objective-C bridge and
 * calls the handlers by hand with the shapes an iPhone actually returns.
 *
 * What this DOES prove: the tag walks terminate, name their fields, survive nil
 * and binary values, respect their budgets, and that the drain waits for a file
 * to stop growing before parsing it. What it CANNOT prove: that the selectors
 * exist on TikTok's build, or that the real frameworks return what the stubs
 * return. Those need the phone. This exists so that when the phone run fails,
 * it fails for a reason that is actually about the phone.
 *
 * The batch it captures is written to selftest/batch.json in exactly the wire
 * format the driver consumes, so the python side can replay it and the two
 * halves are tested against one shared fixture rather than two guesses.
 *
 *   node selftest/observe_test.js
 *
 * Exit code is 0 on pass, 1 on failure. No network, no USB, no device.
 */
'use strict';
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const ROOT = path.join(__dirname, '..');
// OBSERVE_SRC points the harness at a different copy of the source. It exists
// for mutation checks: break a line in a copy, confirm this suite goes red. A
// suite that has never been seen to fail is not evidence of anything.
const SRC = process.env.OBSERVE_SRC || path.join(ROOT, 'observe.js');

// ---------------------------------------------------------------------------
// assertions
// ---------------------------------------------------------------------------
let passed = 0;
const failures = [];

function ok(cond, what) {
  if (cond) { passed++; return true; }
  failures.push(what);
  return false;
}
function eq(actual, expected, what) {
  return ok(actual === expected, what + '  (got ' + JSON.stringify(actual) +
            ', wanted ' + JSON.stringify(expected) + ')');
}

// ---------------------------------------------------------------------------
// fake Objective-C values
//
// Only the methods observe.js actually calls. Anything it does not call is
// deliberately absent: a stub that answers every message would hide the exact
// class of bug this is here to catch, which is code assuming a method exists.
// ---------------------------------------------------------------------------
function nsstr(s) {
  return { $className: 'NSString', toString: () => s, isNull: () => false };
}
function nsnum(n) {
  return { $className: 'NSNumber', toString: () => String(n),
           valueOf: () => n, isNull: () => false };
}
function nsdata(len) {
  return { $className: 'NSConcreteData', length: () => len,
           toString: () => '<binary>', isNull: () => false };
}
function nsarr(items) {
  return { $className: 'NSArray', isNull: () => false,
           count: () => items.length,
           objectAtIndex_: (i) => items[i] };
}
// pairs: [[keyString, value], ...]. Key lookup goes through String() because
// walkImageTags keeps the key OBJECT and looks up with it, not with the name.
function nsdict(pairs) {
  return {
    $className: 'NSDictionary', isNull: () => false,
    allKeys: () => nsarr(pairs.map((p) => nsstr(p[0]))),
    objectForKey_: (k) => {
      const s = String(k);
      const hit = pairs.find((p) => p[0] === s);
      return hit ? hit[1] : null;
    },
  };
}
function avitem(identifier, keySpace, key, value) {
  return {
    $className: 'AVMetadataItem', isNull: () => false,
    identifier: () => (identifier ? nsstr(identifier) : null),
    keySpace: () => (keySpace ? nsstr(keySpace) : null),
    key: () => (key ? nsstr(key) : null),
    value: () => value,
  };
}
function nsurl(p) {
  return {
    $className: 'NSURL', isNull: () => false,
    path: () => nsstr(p),
    lastPathComponent: () => nsstr(p.split('/').pop()),
    isFileURL: () => true,
  };
}
// An NSData carrying real bytes, so the base64 the script produces can be
// decoded on the python side and compared against what went in.
function nsbody(text) {
  const buf = Buffer.from(text, 'utf8');
  return {
    $className: 'NSConcreteData', isNull: () => false,
    __text: text,
    length: () => buf.length,
    base64EncodedStringWithOptions_: () => nsstr(buf.toString('base64')),
    toString: () => '<data>',
  };
}
function httpurl(scheme, host, p) {
  return {
    $className: 'NSURL', isNull: () => false,
    scheme: () => nsstr(scheme),
    host: () => nsstr(host),
    path: () => nsstr(p),
    absoluteString: () => nsstr(scheme + '://' + host + p),
    lastPathComponent: () => nsstr(p.split('/').pop()),
    isFileURL: () => false,
  };
}
let _reqN = 0;
function nsrequest(url, method, headers, body) {
  return {
    $className: 'NSMutableURLRequest', isNull: () => false,
    // reportRequest dedupes on the request's address, so the fake needs a
    // stable identity per object: same object means same request.
    handle: { __req: ++_reqN, toString() { return '0x' + (0x2800 + this.__req).toString(16); } },
    URL: () => url,
    HTTPMethod: () => nsstr(method),
    allHTTPHeaderFields: () => nsdict(headers.map((h) => [h, nsstr('x')])),
    HTTPBody: () => body,
  };
}

// ---------------------------------------------------------------------------
// the fixture: one iPhone-recorded clip, as the frameworks would describe it
// ---------------------------------------------------------------------------
const NATIVE_QT = [
  avitem('mdta/com.apple.quicktime.make', 'mdta', 'com.apple.quicktime.make', nsstr('Apple')),
  avitem('mdta/com.apple.quicktime.model', 'mdta', 'com.apple.quicktime.model', nsstr('iPhone X')),
  avitem('mdta/com.apple.quicktime.software', 'mdta', 'com.apple.quicktime.software', nsstr('16.7.16')),
  avitem('mdta/com.apple.quicktime.creationdate', 'mdta', 'com.apple.quicktime.creationdate',
         nsstr('2026-08-11T14:02:31+0300')),
  avitem('mdta/com.apple.quicktime.location.ISO6709', 'mdta',
         'com.apple.quicktime.location.ISO6709', nsstr('+54.6872+025.2797+096.500/')),
  avitem('mdta/com.apple.quicktime.content.identifier', 'mdta',
         'com.apple.quicktime.content.identifier', nsstr('B8C1E0F2-3A4D-4E5F-9A0B-1C2D3E4F5A6B')),
  // the two shapes that have historically broken walks: no identifier at all,
  // and a binary value that must never be stringified
  avitem(null, 'mdta', 'com.apple.quicktime.live-photo.auto', nsnum(1)),
  avitem('mdta/com.apple.quicktime.maker-data', 'mdta', 'maker-data', nsdata(4096)),
  avitem(null, null, null, null),
];

const EXIF_DICT = nsdict([
  ['PixelWidth', nsnum(4032)],
  ['PixelHeight', nsnum(3024)],
  ['ColorModel', nsstr('RGB')],
  ['{TIFF}', nsdict([
    ['Make', nsstr('Apple')],
    ['Model', nsstr('iPhone X')],
    ['Software', nsstr('16.7.16')],
    ['DateTime', nsstr('2026:08:11 14:02:31')],
  ])],
  ['{Exif}', nsdict([
    ['DateTimeOriginal', nsstr('2026:08:11 14:02:31')],
    ['LensModel', nsstr('iPhone X back dual camera 4mm f/1.8')],
    ['ISOSpeedRatings', nsnum(25)],
    ['OffsetTime', nsstr('+03:00')],
  ])],
  ['{GPS}', nsdict([
    ['Latitude', nsnum(54.6872)],
    ['Longitude', nsnum(25.2797)],
    ['LatitudeRef', nsstr('N')],
  ])],
  ['{MakerApple}', nsdict([
    ['1', nsnum(11)],
    ['3', nsdata(2048)],
  ])],
  // present, must be reported as a block that was deliberately NOT opened
  ['{JFIF}', nsdict([['Version', nsstr('1.01')]])],
]);

// ---------------------------------------------------------------------------
// the stubbed bridge
// ---------------------------------------------------------------------------
const hooks = new Map();          // 'Class|selector' or 'sym:name' -> [handlers]
const sent = [];                  // everything send() was given
let flushFn = null;               // whatever setInterval was handed

function tok(cls, sel) {
  const key = cls + '|' + sel;
  return { __tok: SHARED_IMPL[key] || key, isNull: () => false,
           toString() { return '0x' + (SHARED_IMPL[key] || key); } };
}
function sym(name) { return { __sym: name, isNull: () => false }; }

function fire(key, phase, arg) {
  const hs = hooks.get(key);
  if (!hs || !hs.length) return false;
  let ran = false;
  for (const h of hs) {
    const fn = h[phase];
    if (typeof fn !== 'function') continue;
    // each interception gets its own `this`, which is where onEnter stashes
    // state for onLeave
    fn.call(h.__ctx || (h.__ctx = {}), arg);
    ran = true;
  }
  return ran;
}

/* RE-ENTRANCY.
 *
 * This is the property the drain lives or dies on. Interceptor.attach traps a
 * function for EVERY caller, including observe.js itself, so when the drain
 * opens a file with the same frameworks it is watching, its own reads come
 * back through its own hooks. Without _selfRead the report counts the rig's
 * curiosity as TikTok's behaviour and every number in it is inflated.
 *
 * A stub that just returns a value cannot expose that, so these calls fire the
 * registered handlers first, exactly as the real trap would. Any call the drain
 * makes through a hooked symbol has to go through here or the guard is being
 * tested against nothing. */
function reentrant(key, ret) {
  fire(key, 'onLeave', ret);
  return ret;
}

// Only these selectors exist. mediaHook checks $ownMethods, so a selector left
// out here is reported as "not implemented by this class", which is the same
// path a missing selector takes on a real build.
// -resume is implemented once on the base class and inherited, so Frida hands
// back the SAME implementation address for all three names. That is what caused
// three listeners on one function and tripled every request count, and a stub
// that gave each class its own address could never have shown it.
const SHARED_IMPL = {
  '__NSCFLocalSessionTask|- resume': 'sharedResume',
  '__NSCFURLSessionTask|- resume': 'sharedResume',
  'NSURLSessionTask|- resume': 'sharedResume',
};

const MOCK_METHODS = {
  __NSCFLocalSessionTask: ['- resume'],
  __NSCFURLSessionTask: ['- resume'],
  NSURLSessionTask: ['- resume'],
  AVURLAsset: ['- initWithURL:options:', '- commonMetadata', '- metadata'],
  AVAsset: ['- commonMetadata', '- metadata'],
  AVAssetTrack: ['- formatDescriptions'],
  AVAssetExportSession: ['- setOutputURL:', '- setMetadata:'],
  AVAssetWriter: ['- setOutputURL:', '- setMetadata:', '- initWithURL:fileType:error:'],
  PHAsset: ['- location', '- creationDate', '- modificationDate', '- localIdentifier',
            '- sourceType', '- mediaSubtypes', '- pixelWidth', '- pixelHeight',
            '- burstIdentifier', '- playbackStyle'],
  PHObject: ['- localIdentifier'],
  PHAssetResource: ['- originalFilename', '- uniformTypeIdentifier'],
  NSFileManager: ['- attributesOfItemAtPath:error:'],
  NSURLSession: ['- uploadTaskWithRequest:fromData:', '- uploadTaskWithRequest:fromFile:',
                 '- uploadTaskWithRequest:fromData:completionHandler:',
                 '- uploadTaskWithRequest:fromFile:completionHandler:',
                 '- uploadTaskWithStreamedRequest:'],
};

// The publish call, as close to the real shape as matters here: a JSON body on
// the endpoint that carries the post's own description of itself. The python
// side decodes this back out of bodies/ and compares it byte for byte.
const PUBLISH_BODY = JSON.stringify({
  aweme_type: 0,
  video_id: 'v0f044gc0000abcdef',
  text: 'testing the rig',
  poi_data: null,
  upload_source: 'camera_roll',
});

// Class-level methods the drain calls directly rather than through a hook.
const FS = {
  // path -> the sequence of sizes successive stats return. A growing export is
  // the case the drain has to get right, so the fixture grows.
  '/private/var/mobile/Containers/Data/Application/AA/tmp/trim.MOV': [8_412_331],
  '/private/var/mobile/Containers/Data/Application/AA/tmp/export.mp4': [0, 1_200_000, 3_355_120, 3_355_120],
  '/private/var/mobile/Containers/Data/Application/AA/tmp/upload.mp4': [3_355_120],
  // a slideshow arm, so the image branch of the drain is exercised too
  '/private/var/mobile/Containers/Data/Application/AA/tmp/slide1.HEIC': [2_118_004],
};
const fsCursor = {};

function statSize(p) {
  const seq = FS[p];
  if (!seq) return null;
  const i = Math.min(fsCursor[p] || 0, seq.length - 1);
  fsCursor[p] = (fsCursor[p] || 0) + 1;
  return seq[i];
}

const FM_HOOK = 'NSFileManager|- attributesOfItemAtPath:error:';
const CLASS_STATICS = {
  NSFileManager: {
    defaultManager: () => ({
      attributesOfItemAtPath_error_: (p) => {
        const size = statSize(String(p));
        if (size === null) return null;
        const d = nsdict([['NSFileSize', size],
                          ['NSFileCreationDate', nsstr('2026-08-11 11:02:31 +0000')],
                          ['NSFileModificationDate', nsstr('2026-08-11 11:02:33 +0000')]]);
        // the drain stats files through a selector it has itself hooked
        fire(FM_HOOK, 'onEnter', [null, null, nsstr(String(p))]);
        return reentrant(FM_HOOK, d);
      },
    }),
  },
  NSURL: { fileURLWithPath_: (p) => nsurl(String(p)) },
  NSString: {
    alloc: () => ({ initWithData_encoding_: (d) => nsstr(d.__text || '') }),
  },
  AVURLAsset: {
    URLAssetWithURL_options_: () => ({
      $className: 'AVURLAsset', isNull: () => false,
      // both of these are hooked, so the drain's own calls re-enter
      commonMetadata: () => reentrant('AVURLAsset|- commonMetadata',
                                      nsarr(NATIVE_QT.slice(0, 4))),
      metadata: () => reentrant('AVURLAsset|- metadata', nsarr(NATIVE_QT)),
      availableMetadataFormats: () => nsarr([nsstr('com.apple.quicktime.mdta')]),
      metadataForFormat_: () => nsarr(NATIVE_QT.slice(4)),
    }),
  },
};

function makeClass(name) {
  const own = MOCK_METHODS[name] || [];
  const statics = CLASS_STATICS[name] || {};
  return new Proxy({}, {
    get(_t, prop) {
      if (prop === '$ownMethods') return own;
      if (prop === '$className') return name;
      if (typeof prop !== 'string') return undefined;
      if (Object.prototype.hasOwnProperty.call(statics, prop)) return statics[prop];
      if (own.indexOf(prop) !== -1) return { implementation: tok(name, prop) };
      return undefined;
    },
    has() { return true; },
  });
}

const classCache = {};
const ObjCStub = {
  available: true,
  classes: new Proxy({}, {
    get(_t, name) {
      if (typeof name !== 'string') return undefined;
      if (!(name in classCache)) classCache[name] = makeClass(name);
      return classCache[name];
    },
    has() { return true; },
  }),
  // the bridge hands back the same wrapper for an object it already wraps,
  // which is all the new code needs from it
  Object: function (x) { return x; },
};

// Symbols the drain and the XMP walk build NativeFunctions from. Everything
// else resolves too, so probes register exactly as they would on a device.
const NATIVE_IMPL = {
  CGImageSourceCreateWithURL: () => ({ __cgsrc: true, isNull: () => false }),
  // hooked as an export, so the drain's own property read re-enters too
  CGImageSourceCopyPropertiesAtIndex: () =>
    reentrant('sym:CGImageSourceCopyPropertiesAtIndex',
              Object.assign({}, EXIF_DICT, { isNull: () => false })),
  CGImageMetadataCopyTags: () => nsarr([
    { handle: { __xmp: 0 }, isNull: () => false },
    { handle: { __xmp: 1 }, isNull: () => false },
  ]),
  CGImageMetadataTagCopyPrefix: (h) => nsstr(h.__xmp === 0 ? 'xmp' : 'c2pa'),
  CGImageMetadataTagCopyName: (h) => nsstr(h.__xmp === 0 ? 'CreatorTool' : 'ClaimGenerator'),
  CMFormatDescriptionGetMediaSubType: () => 0x61766331, // 'avc1'
};

const sandbox = {
  console,
  Date,
  Math,
  JSON,
  Map,
  Set,
  Number,
  String,
  Boolean,
  Array,
  Object,
  Error,
  RegExp,
  Uint8Array,
  parseInt,
  parseFloat,
  isNaN,
  globalThis: null,

  __ObjC: ObjCStub,

  Interceptor: {
    attach(target, handlers) {
      const key = target && target.__tok ? target.__tok
                : target && target.__sym ? 'sym:' + target.__sym
                : String(target);
      if (!hooks.has(key)) hooks.set(key, []);
      hooks.get(key).push(handlers);
      return { detach() {} };
    },
    detachAll() {},
  },
  Module: {
    findGlobalExportByName: (name) => sym(name),
  },
  NativeFunction: function (p, ret, args) {
    const impl = NATIVE_IMPL[p && p.__sym];
    return function () {
      if (!impl) return { isNull: () => true };
      return impl.apply(null, arguments);
    };
  },
  ptr: (x) => ({ __ptr: x, isNull: () => x === 0 }),
  NULL: { __ptr: 0, isNull: () => true },
  send: (payload) => { sent.push(payload); },
  rpc: {},
  setInterval: (fn) => { flushFn = fn; return 1; },
  setTimeout: () => 2,
  clearInterval: () => {},
};
sandbox.globalThis = sandbox;

// ---------------------------------------------------------------------------
// load the real source
//
// One line is rewritten: the bridge import, which resolves to a package that
// only exists inside Frida. Everything else executes exactly as shipped, and
// the rewrite is asserted to have matched so this cannot silently test nothing.
// ---------------------------------------------------------------------------
let src = fs.readFileSync(SRC, 'utf8');
const before = src;
src = src.replace(/^import\s+ObjC\s+from\s+['"]frida-objc-bridge['"];?\s*$/m,
                  'const ObjC = __ObjC;');
if (src === before) {
  console.error('FATAL: could not rewrite the frida-objc-bridge import. '
              + 'observe.js changed shape; fix this harness before trusting it.');
  process.exit(1);
}

const ctx = vm.createContext(sandbox);
try {
  vm.runInContext(src, ctx, { filename: 'observe.js', timeout: 20000 });
} catch (e) {
  console.error('FATAL: observe.js threw while loading:\n  ' + (e && e.stack || e));
  process.exit(1);
}

// ---------------------------------------------------------------------------
// drive the hooks
// ---------------------------------------------------------------------------
const TMP = '/private/var/mobile/Containers/Data/Application/AA/tmp/';

ok(hooks.size > 0, 'hooks were registered at load');
ok(sent.length === 0, 'nothing was sent before the first flush');

// --- the video path -------------------------------------------------------
ok(fire('AVURLAsset|- initWithURL:options:', 'onEnter',
        [null, null, nsurl(TMP + 'trim.MOV')]),
   'AVURLAsset initWithURL:options: was hooked');

ok(fire('AVURLAsset|- metadata', 'onLeave', nsarr(NATIVE_QT)),
   'AVURLAsset -metadata was hooked');

ok(fire('AVAssetTrack|- formatDescriptions', 'onLeave',
        nsarr([{ handle: { fd: 1 }, isNull: () => false }])),
   'AVAssetTrack -formatDescriptions was hooked');

// --- the library's opinion of the item ------------------------------------
ok(fire('PHAsset|- sourceType', 'onLeave', { toUInt32: () => 1, isNull: () => false }),
   'PHAsset -sourceType was hooked');
ok(fire('PHAsset|- mediaSubtypes', 'onLeave', { toUInt32: () => 8, isNull: () => false }),
   'PHAsset -mediaSubtypes was hooked');
ok(fire('PHAssetResource|- originalFilename', 'onLeave', nsstr('IMG_0042.MOV')),
   'PHAssetResource -originalFilename was hooked');
ok(fire('PHAsset|- pixelWidth', 'onLeave', { toUInt32: () => 1080, isNull: () => false }),
   'PHAsset -pixelWidth was hooked');
ok(fire('PHAsset|- burstIdentifier', 'onLeave', { isNull: () => true }),
   'PHAsset -burstIdentifier was hooked');

// --- the image path -------------------------------------------------------
ok(fire('sym:CGImageSourceCopyPropertiesAtIndex', 'onLeave',
        Object.assign({}, EXIF_DICT, { isNull: () => false })),
   'CGImageSourceCopyPropertiesAtIndex was hooked');
ok(fire('sym:CGImageSourceCopyMetadataAtIndex', 'onLeave', { isNull: () => false }),
   'CGImageSourceCopyMetadataAtIndex (XMP) was hooked');

// --- the export, and what TikTok writes into it ---------------------------
ok(fire('AVAssetWriter|- setOutputURL:', 'onEnter', [null, null, nsurl(TMP + 'export.mp4')]),
   'AVAssetWriter -setOutputURL: was hooked');
ok(fire('AVAssetWriter|- setMetadata:', 'onEnter',
        [null, null, nsarr([NATIVE_QT[0], NATIVE_QT[1]])]),
   'AVAssetWriter -setMetadata: was hooked');

// --- file attributes ------------------------------------------------------
const fmHook = 'NSFileManager|- attributesOfItemAtPath:error:';
fire(fmHook, 'onEnter', [null, null, nsstr(TMP + 'trim.MOV')]);
ok(fire(fmHook, 'onLeave', nsdict([['NSFileSize', 8412331],
                                   ['NSFileCreationDate', nsstr('2026-08-11 11:02:31 +0000')]])),
   'NSFileManager attributesOfItemAtPath: was hooked');

// a non-media path must be ignored entirely
fire(fmHook, 'onEnter', [null, null, nsstr('/var/mobile/Library/Caches/db.sqlite')]);
fire(fmHook, 'onLeave', nsdict([['NSFileSize', 99]]));

// --- the upload, which is what queues the outgoing artifact ---------------
const upKeys = [...hooks.keys()].filter((k) => k.indexOf('uploadTaskWith') !== -1);
ok(upKeys.length > 0, 'an upload task selector was hooked');

// ONE request object, submitted twice below. That is what a device does: the
// factory hook sees the request being built and the -resume hook sees the task
// carrying it, both wanted, because either alone misses traffic. Counting it
// once per hook made every REQUEST, HEADER and BODY number about double the
// truth, and a 30s smoke run wrote 6 body files holding 2 distinct payloads.
const PUBLISH_REQ = nsrequest(
  httpurl('https', 'api16-normal-c-useast1a.tiktokv.com', '/aweme/v1/aweme/post/'),
  'POST', ['Cookie', 'X-Argus', 'X-Gorgon', 'Content-Type'], nsbody(PUBLISH_BODY));

ok(fire('NSURLSession|- uploadTaskWithRequest:fromFile:', 'onEnter',
        [null, null, PUBLISH_REQ, nsurl(TMP + 'upload.mp4')]),
   'NSURLSession uploadTaskWithRequest:fromFile: was hooked');

// a slideshow post uploads images, which is what sends the drain down its
// image branch rather than the AVAsset one
fire('NSURLSession|- uploadTaskWithRequest:fromFile:', 'onEnter', [
  null, null,
  nsrequest(httpurl('https', 'api16-normal-c-useast1a.tiktokv.com', '/aweme/v1/upload/image/'),
            'POST', ['Content-Type'], null),
  nsurl(TMP + 'slide1.HEIC'),
]);

// the second sighting of the SAME request, standing in for -resume
fire('NSURLSession|- uploadTaskWithRequest:fromFile:', 'onEnter',
     [null, null, PUBLISH_REQ, nsurl(TMP + 'upload.mp4')]);

// A RETRY: a brand new request object carrying byte-identical content. The
// request-address dedupe cannot catch this one, which is why the body store
// keeps its own content check.
const RETRY_REQ = nsrequest(
  httpurl('https', 'api16-normal-c-useast1a.tiktokv.com', '/aweme/v1/aweme/post/'),
  'POST', ['Cookie', 'X-Argus'], nsbody(PUBLISH_BODY));
fire('NSURLSession|- uploadTaskWithRequest:fromFile:', 'onEnter',
     [null, null, RETRY_REQ, nsurl(TMP + 'upload.mp4')]);

// a body over the per-body ceiling must be refused loudly, not truncated
fire('NSURLSession|- uploadTaskWithRequest:fromData:', 'onEnter', [
  null, null,
  nsrequest(httpurl('https', 'api16-normal-c-useast1a.tiktokv.com', '/aweme/v1/upload/huge/'),
            'POST', ['Content-Type'], nsbody('X'.repeat(300 * 1024))),
  nsbody('X'.repeat(300 * 1024)),
]);

// a non-http scheme must be dropped before anything is recorded
fire('NSURLSession|- uploadTaskWithRequest:fromData:', 'onEnter', [
  null, null,
  nsrequest({ $className: 'NSURL', isNull: () => false,
              scheme: () => nsstr('data'), host: () => nsstr(''),
              path: () => nsstr(''), absoluteString: () => nsstr('data:image/png;base64,AA'),
              isFileURL: () => false },
            'GET', [], null),
  nsbody('ignored'),
]);

// --- mark, then flush -----------------------------------------------------
ok(typeof ctx.rpc.exports.mark === 'function', 'rpc.exports.mark exists');
ctx.rpc.exports.mark('post-1');

ok(typeof flushFn === 'function', 'the flush timer was installed');
// several ticks: the drain does one file per tick and re-queues a file whose
// size is still changing, so a growing export needs more than one pass
for (let i = 0; i < 12; i++) flushFn();

// ---------------------------------------------------------------------------
// inspect what came out
// ---------------------------------------------------------------------------
const rows = [];
for (const p of sent) for (const r of (p.b || [])) rows.push(r);

const byCat = {};
for (const r of rows) (byCat[r[0]] = byCat[r[0]] || []).push(r);

function tag(name) {
  return (byCat.MEDIA_TAG || []).find((r) => r[1] === name);
}
function tagVal(name) {
  const t = tag(name);
  return t ? t[2] : undefined;
}

// only ONE listener may sit on the shared -resume implementation, however many
// class names resolve to it
eq((hooks.get('sharedResume') || []).length, 1,
   'three task classes sharing one -resume implementation are hooked once');
ok((byCat.RIG || []).some((r) => /shared -resume implementation/.test(r[1] || '')),
   'the shared implementation is reported rather than silently skipped');

ok(rows.length > 0, 'the flush produced a batch');
ok((byCat.MEDIA_TAG || []).length > 0, 'MEDIA_TAG rows were produced');

// the whole point of reading identifier instead of commonKey
eq(tagVal('video metadata mdta/com.apple.quicktime.make'), 'Apple',
   'QuickTime make is named and valued');
eq(tagVal('video metadata mdta/com.apple.quicktime.model'), 'iPhone X',
   'QuickTime model is named and valued');
ok(tag('video metadata mdta/com.apple.quicktime.location.ISO6709'),
   'the QuickTime geotag is named in full');
ok(tag('video metadata mdta/com.apple.quicktime.content.identifier'),
   'the content identifier is named in full');

// an item with no identifier must fall back to keySpace/key, not vanish
ok(tag('video metadata mdta/com.apple.quicktime.live-photo.auto'),
   'an item without an identifier falls back to keySpace/key');
// and one with nothing at all must still produce a row rather than throwing
ok((byCat.MEDIA_TAG || []).some((r) => r[1].indexOf('unnamed field') !== -1),
   'a completely anonymous metadata item still produces a row');
// binary values are reported by size, never stringified
ok(/bytes of data/.test(tagVal('video metadata mdta/com.apple.quicktime.maker-data') || ''),
   'a binary value is reported as a byte count');

// sub-dictionaries: the gap that made last session useless
eq(tagVal('image {TIFF} Make'), 'Apple', 'the TIFF sub-dictionary is walked');
eq(tagVal('image {Exif} DateTimeOriginal'), '2026:08:11 14:02:31',
   'the Exif sub-dictionary is walked');
eq(tagVal('image {GPS} LatitudeRef'), 'N', 'the GPS sub-dictionary is walked');
ok(tag('image {MakerApple} 3'), 'the MakerApple sub-dictionary is walked');
eq(tagVal('image PixelWidth'), '4032', 'top-level image fields are still recorded');
// a block that is not on the deep list is named but explicitly not opened
eq(tagVal('image {JFIF}'), '(block, not opened)',
   'an unlisted block is reported as present but unopened');
ok(!tag('image {JFIF} Version'), 'an unlisted block is genuinely not walked');

// the library side
eq(tagVal('library sourceType'), 'user library', 'sourceType is decoded to a name');
eq(tagVal('library mediaSubtypes'), 'LIVE PHOTO', 'the Live Photo flag is decoded');
eq(tagVal('resource originalFilename'), 'IMG_0042.MOV', 'the original filename is recorded');
eq(tagVal('library pixelWidth'), '1080', 'an integer property is read from the register');
eq(tagVal('library burstIdentifier'), 'absent', 'a nil object property reads as absent');

// codec and XMP
eq(tagVal('track codec'), 'avc1', 'the codec fourcc is decoded');
ok(tag('XMP xmp:CreatorTool'), 'XMP tags are named with their prefix');
ok(tag('XMP c2pa:ClaimGenerator'), 'a C2PA claim in XMP is named');

// what TikTok wrote into its own export
ok((byCat.MEDIA_TAG || []).some((r) => r[1].indexOf('written into the export') === 0),
   'metadata written into the export is captured separately');

// file attribute filtering
ok((byCat.MEDIA_TAG || []).some((r) => r[1] === 'file size'), 'media file size is recorded');
ok(!(byCat.MEDIA_TAG || []).some((r) => (r[2] || '').indexOf('db.sqlite') !== -1),
   'a non-media file is not recorded');

// the drain: both ends of the post, and the growing export handled correctly
const files = byCat.MEDIA_FILE || [];
ok(files.some((r) => r[1] === 'INPUT'), 'the input file was dumped');
ok(files.some((r) => r[1] === 'OUTPUT'), 'the encoder output was dumped');
const outRow = files.find((r) => r[1] === 'OUTPUT');
ok(outRow && /3355120 bytes/.test(outRow[2] || ''),
   'the export was parsed at its FINAL size, not while it was still growing');
ok(!files.some((r) => /never settled/.test(r[1])),
   'no file was abandoned as never settling');
ok((byCat.MEDIA_TAG || []).some((r) => r[1].indexOf('INPUT ') === 0),
   'the input file dump produced tags');
ok((byCat.MEDIA_TAG || []).some((r) => r[1].indexOf('OUTPUT ') === 0),
   'the output file dump produced tags');

ok((byCat.MEDIA_TAG || []).some((r) => r[1].indexOf('UPLOADED {TIFF} Make') === 0),
   'the image branch of the drain walks sub-dictionaries too');

// --- re-entrancy ----------------------------------------------------------
// The drain opens files with the very frameworks the hooks are attached to, so
// its own reads come back through its own hooks. The stub fires those handlers
// exactly as a real trap would, which means these counts go up the moment the
// guard stops working.
//
// Exactly one live video metadata read was fired by hand above. Everything
// beyond that is the rig watching itself.
const liveVideoReads = (byCat.MEDIA_META || [])
  .filter((r) => r[1] === 'video metadata block')
  .reduce((n, r) => n + r[3], 0);
eq(liveVideoReads, 1,
   'the self-read guard held for video: the drain did not log its own reads');

// one image property read was fired by hand; the drain parses two files
const liveImageReads = (byCat.MEDIA_META || [])
  .filter((r) => r[1] === 'image metadata block')
  .reduce((n, r) => n + r[3], 0);
eq(liveImageReads, 1,
   'the self-read guard held for images: the drain did not log its own reads');

// the drain stats every file it parses, through a selector it has hooked. Only
// the one attribute read fired by hand should appear.
const fileSizeRows = (byCat.MEDIA_TAG || []).filter((r) => r[1] === 'file size');
const fileSizeReads = fileSizeRows.reduce((n, r) => n + r[3], 0);
eq(fileSizeReads, 1,
   'the self-read guard held for file attributes: the drain\'s own stats are '
   + 'not counted as TikTok\'s');

ok(files.some((r) => r[1] === 'UPLOADED'), 'the uploaded artifact was dumped');

// --- request bodies -------------------------------------------------------
const blobs = [];
for (const p of sent) for (const b of (p.blobs || [])) blobs.push(b);
ok(blobs.length >= 1, 'a request body was captured whole');
const publish = blobs.find((b) => b.n.indexOf('/aweme/v1/aweme/post/') !== -1);
ok(publish, 'the publish call body was captured');

// the publish body was submitted twice above and must be stored once
const publishCopies = blobs.filter((b) => b.n.indexOf('/aweme/v1/aweme/post/') !== -1);
eq(publishCopies.length, 1,
   'an identical body arriving twice is stored once, not once per code path');
const uniq = new Set(blobs.map((b) => b.b));
eq(uniq.size, blobs.length, 'every stored body is a distinct payload');

// and the same request seen twice must be COUNTED once, which is the part that
// decides whether the report's request numbers mean anything
const publishReqRows = (byCat.REQUEST || [])
  .filter((r) => (r[2] || '').indexOf('/aweme/v1/aweme/post/') !== -1);
eq(publishReqRows.length, 1, 'the publish request produced exactly one REQUEST row');
// the original was seen twice (deduped to 1) and the retry is a genuinely
// separate request, so the row must count 2 rather than 3
eq(publishReqRows[0] && publishReqRows[0][3], 2,
   'one request seen by two hooks counts once, but a real retry still counts');
ok((byCat.BODY || []).some((r) => /identical body seen again/.test(r[2] || '')),
   'the retry\'s identical body is reported rather than stored a second time');

// two DIFFERENT requests to the same endpoint must still count as two
const imageReqRows = (byCat.REQUEST || [])
  .filter((r) => (r[2] || '').indexOf('/aweme/v1/upload/image/') !== -1);
eq(imageReqRows.length, 1, 'the image upload is its own request row');
if (publish) {
  eq(Buffer.from(publish.b, 'base64').toString('utf8'), PUBLISH_BODY,
     'the captured body round-trips byte for byte through base64');
  ok(publish.n.indexOf('POST') !== -1, 'the captured body is labelled with its method');
}
ok(!blobs.some((b) => b.n.indexOf('/upload/huge/') !== -1),
   'a body over the per-body ceiling is refused rather than truncated');
ok((byCat.BODY || []).some((r) => /too large to capture/.test(r[2] || '')),
   'the oversized body is reported rather than dropped silently');
ok(!(byCat.REQUEST || []).some((r) => /^data:/.test(r[2] || '')),
   'a data: URL is dropped before it is recorded as a request');
ok((byCat.HEADER || []).some((r) => r[1] === 'X-Argus'),
   'request header names are recorded');

// the mark
ok((byCat.MARK || []).some((r) => r[1] === 'post-1'), 'rpc mark lands in the batch');

// budgets and ceilings
ok(rows.length < 3000, 'the batch stayed well under the distinct-row ceiling');
const capped = sent.some((p) => p.capped);
ok(!capped, 'nothing hit a cap on a single realistic post');

// ---------------------------------------------------------------------------
// hand the batch to the python side
// ---------------------------------------------------------------------------
const outPath = path.join(__dirname, 'batch.json');
fs.writeFileSync(outPath, JSON.stringify({
  note: 'produced by selftest/observe_test.js from the real observe.js source',
  batches: sent,
}, null, 1));

console.log('');
console.log('  observe.js  ' + passed + ' checks passed, ' + failures.length + ' failed');
console.log('  hooks registered: ' + hooks.size + ', rows emitted: ' + rows.length);
console.log('  batch written to ' + path.relative(ROOT, outPath));
if (failures.length) {
  console.log('');
  for (const f of failures) console.log('  FAIL  ' + f);
  process.exit(1);
}
process.exit(0);
