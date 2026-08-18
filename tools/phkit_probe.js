// Calls PhotoKit's own import path from inside a process that already holds
// photo-library permission, so we learn what Photos does to a stamped file on
// the door an app actually uses.
import ObjC from 'frida-objc-bridge';

function post(stage, detail) { send({ stage: stage, detail: String(detail) }); }

// Photos has a separate creation request per media type, and the image one is
// the untested half: video came back byte-identical, stills may not.
function requestFor(kind, url) {
  const R = ObjC.classes.PHAssetCreationRequest;
  return kind === 'image'
    ? R.creationRequestForAssetFromImageAtFileURL_(url)
    : R.creationRequestForAssetFromVideoAtFileURL_(url);
}

function urlFor(path) {
  return ObjC.classes.NSURL.fileURLWithPath_(
    ObjC.classes.NSString.stringWithUTF8String_(Memory.allocUtf8String(path)));
}

// One performChanges for the whole set: Photos applies it as a single
// transaction, so either every arm lands or none does and the library is not
// left half-populated between runs.
function runImportBatch(paths, kind) {
try {
  const PHPhotoLibrary = ObjC.classes.PHPhotoLibrary;
  if (!PHPhotoLibrary || !ObjC.classes.PHAssetCreationRequest) {
    post('error', 'PhotoKit classes not present in this process');
    return;
  }
  post('auth', PHPhotoLibrary.authorizationStatus());   // 3 authorized, 4 limited
  const lib = PHPhotoLibrary.sharedPhotoLibrary();
  const ids = [];

  const changes = new ObjC.Block({
    retType: 'void', argTypes: [],
    implementation: function () {
      for (let i = 0; i < paths.length; i++) {
        try {
          const url = urlFor(paths[i]);
          const req = requestFor(kind, url);
          if (req === null) { post('error', 'nil request for ' + paths[i]); continue; }
          const ph = req.placeholderForCreatedAsset();
          if (ph !== null) {
            const id = ph.localIdentifier().toString();
            ids.push(id);
            post('placeholder', paths[i] + '  ->  ' + id);
          }
        } catch (e) { post('error', paths[i] + ': ' + e.message); }
      }
    }
  });
  const done = new ObjC.Block({
    retType: 'void', argTypes: ['bool', 'object'],
    implementation: function (ok, err) {
      post('result', ok ? 'success' : 'failed');
      if (!ok && err !== null) {
        try { post('error', err.localizedDescription().toString()); } catch (e) {}
      }
      post('identifiers', ids.join(','));
    }
  });
  lib.performChanges_completionHandler_(changes, done);
  post('submitted', paths.length + ' file(s) waiting on the completion handler');
} catch (e) { post('error', e.message); }
}

function runImport(PATH) { runImportBatch([PATH], 'video'); }

function appDirs() {
  const NSHomeDirectory = new NativeFunction(
    Module.getGlobalExportByName('NSHomeDirectory'), 'pointer', []);
  const home = new ObjC.Object(NSHomeDirectory()).toString();
  return { home: home, tmp: home + '/tmp', docs: home + '/Documents' };
}


// Putting three hundred files into somebody's real camera roll is only
// acceptable if they come out again, so deletion is part of the tool.
function deleteAssets(ids) {
try {
  const lib = ObjC.classes.PHPhotoLibrary.sharedPhotoLibrary();
  const arr = ObjC.classes.NSMutableArray.alloc().init();
  for (let i = 0; i < ids.length; i++) {
    arr.addObject_(ObjC.classes.NSString.stringWithUTF8String_(
      Memory.allocUtf8String(ids[i])));
  }
  const fetched = ObjC.classes.PHAsset
    .fetchAssetsWithLocalIdentifiers_options_(arr, NULL);
  post('found', fetched.count() + ' of ' + ids.length + ' still in the library');
  const changes = new ObjC.Block({
    retType: 'void', argTypes: [],
    implementation: function () {
      try { ObjC.classes.PHAssetChangeRequest.deleteAssets_(fetched); }
      catch (e) { post('error', 'inside performChanges: ' + e.message); }
    }
  });
  const done = new ObjC.Block({
    retType: 'void', argTypes: ['bool', 'object'],
    implementation: function (ok, err) {
      post('result', ok ? 'success' : 'failed');
      if (!ok && err !== null) {
        try { post('error', err.localizedDescription().toString()); } catch (e) {}
      }
    }
  });
  lib.performChanges_completionHandler_(changes, done);
  post('submitted', 'deletion queued -- iOS will ask the user to confirm');
} catch (e) { post('error', e.message); }
}

rpc.exports = {
  runImport: runImport,
  runImportBatch: runImportBatch,
  deleteAssets: deleteAssets,
  appDirs: appDirs
};
