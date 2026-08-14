/*
 * PhotoKit import, loaded into Photos.app — never into TikTok.
 *
 * PHAssetCreationRequest.addResourceWithType:fileURL:options: with
 * shouldMoveFile = NO is how you put original bytes in the library.
 * Dropping a file in DCIM and hoping the indexer keeps them is the
 * thing this replaces: the indexer is free to transcode, strip, or
 * rewrite, and that rewrite would be indistinguishable from a TikTok
 * rewrite in the stamping matrix.
 *
 * The import is the experiment. We return the localIdentifier and the
 * PHAssetResource fileSize / UTI so the host can compare them to the
 * bytes it pushed. Agreement is a measurement, not an assumption.
 *
 * Needs frida-compile (import ObjC from 'frida-objc-bridge').
 */
'use strict';

import ObjC from 'frida-objc-bridge';

function asString(v) {
  if (v === undefined || v === null) return null;
  try { return v.toString(); } catch (e) { return null; }
}

function kindToType(path, kind) {
  if (kind === 'video') return 2;
  if (kind === 'photo' || kind === 'image') return 1;
  const ext = (path.split('.').pop() || '').toLowerCase();
  if (['mov', 'mp4', 'm4v', '3gp', 'avi'].indexOf(ext) >= 0) return 2;
  return 1;
}

function newestIdent(mediaType) {
  const PHAsset = ObjC.classes.PHAsset;
  const PHFetchOptions = ObjC.classes.PHFetchOptions;
  const opts = PHFetchOptions.alloc().init();
  try {
    const sd = ObjC.classes.NSSortDescriptor.sortDescriptorWithKey_ascending_('creationDate', false);
    opts.setSortDescriptors_(ObjC.classes.NSArray.arrayWithObject_(sd));
    opts.setFetchLimit_(1);
  } catch (e) {}
  const r = PHAsset.fetchAssetsWithMediaType_options_(mediaType, opts);
  if (!r || r.count() === 0) return null;
  return asString(r.objectAtIndex_(0).localIdentifier());
}

function measureIdent(ident) {
  const PHAsset = ObjC.classes.PHAsset;
  const PHAssetResource = ObjC.classes.PHAssetResource;
  const arr = ObjC.classes.NSArray.arrayWithObject_(ident);
  const r = PHAsset.fetchAssetsWithLocalIdentifiers_options_(arr, NULL);
  if (!r || r.count() === 0) return { ok: false, error: 'asset not found', localIdentifier: ident };
  const a = r.objectAtIndex_(0);
  const out = {
    ok: true,
    localIdentifier: asString(a.localIdentifier()),
    mediaType: Number(a.mediaType()),
    pixelWidth: Number(a.pixelWidth()),
    pixelHeight: Number(a.pixelHeight()),
    duration: Number(a.duration()),
    creationDate: asString(a.creationDate()),
    modificationDate: asString(a.modificationDate()),
    resources: [],
  };
  try {
    const loc = a.location();
    if (loc && !loc.isNull()) {
      const c = loc.coordinate();
      out.location = { lat: c.latitude, lon: c.longitude };
    }
  } catch (e) {}
  try {
    const resources = PHAssetResource.assetResourcesForAsset_(a);
    const n = Number(resources.count());
    for (let i = 0; i < n; i++) {
      const res = resources.objectAtIndex_(i);
      const row = {
        type: Number(res.type()),
        uti: asString(res.uniformTypeIdentifier()),
        originalFilename: asString(res.originalFilename()),
      };
      try { row.fileSize = Number(res.valueForKey_('fileSize')); } catch (e) {}
      out.resources.push(row);
    }
  } catch (e) {
    out.resourceError = e.message;
  }
  return out;
}

rpc.exports = {
  ping: function () {
    return {
      ok: true,
      photos: !!ObjC.classes.PHPhotoLibrary,
      creation: !!ObjC.classes.PHAssetCreationRequest,
    };
  },

  importFile: function (path, kind) {
    // PHAssetCreationRequest.performChanges* takes a Block. On this
    // phone (A11 / iOS 16.7.16 / Frida 17.16.4) that Block, even empty,
    // terminates Photos.app the moment PhotoKit copies it. Measured:
    // an empty performChangesAndWait_error_ is enough to kill the
    // process. So we cannot use the creation-request API from Frida.
    //
    // UIImageWriteToSavedPhotosAlbum / UISaveVideoAtPathToSavedPhotosAlbum
    // are C functions and take a NULL completion. They go through the
    // same library, but they are not the original-bytes API. The
    // measurement below is what tells you whether the bytes survived.
    const type = kindToType(path, kind || 'auto');
    const fm = ObjC.classes.NSFileManager.defaultManager();
    if (!fm.fileExistsAtPath_(path)) {
      return { ok: false, error: 'file not on phone: ' + path, path: path };
    }
    // PHAsset fetchAssets* also terminates Photos.app on this build
    // (measured: a one-line fetch of the newest image is enough). Do
    // not talk to PHAsset from this process. The host measures the
    // DCIM directory over SSH after we return.
    try {
      if (type === 2) {
        const fn = new NativeFunction(
          Module.getGlobalExportByName('UISaveVideoAtPathToSavedPhotosAlbum'),
          'void', ['pointer', 'pointer', 'pointer', 'pointer']);
        const nsPath = ObjC.classes.NSString.stringWithUTF8String_(
          Memory.allocUtf8String(path));
        fn(nsPath, ptr(0), ptr(0), ptr(0));
      } else {
        const img = ObjC.classes.UIImage.imageWithContentsOfFile_(path);
        if (!img || img.isNull()) {
          return { ok: false, error: 'UIImage could not read ' + path, path: path };
        }
        const fn = new NativeFunction(
          Module.getGlobalExportByName('UIImageWriteToSavedPhotosAlbum'),
          'void', ['pointer', 'pointer', 'pointer', 'pointer']);
        fn(img, ptr(0), ptr(0), ptr(0));
      }
    } catch (e) {
      return { ok: false, error: 'save threw: ' + e, path: path, method: 'uikit' };
    }
    return {
      ok: true,
      path: path,
      resourceType: type,
      method: 'uikit-save',
      note: 'PhotoKit (creation request AND PHAsset fetch) terminates Photos.app on this build. UIKit save fired; host measures DCIM.',
    };
  },

  measure: function (ident) {
    return measureIdent(ident);
  },
};
