#!/bin/sh
# Leave exactly one test clip in DCIM so the TikTok picker cannot blend.
export PATH=/var/jb/usr/bin:/var/jb/bin:/usr/bin:/bin

KEEP="${1:-IMG_0021.MOV}"
DCIM=/var/mobile/Media/DCIM/100APPLE
STASH=/var/mobile/Media/poster-inbox/solo-stash
PD=/var/mobile/Media/PhotoData

killall -9 photolibraryd photoanalysisd cameracaptured MobileSlideShow \
  cloudphotod assetsd Camera 2>/dev/null

mkdir -p "$STASH"
cd "$DCIM" || exit 1

# park everything that is not KEEP
for f in IMG_*.MOV IMG_*.MP4 IMG_*.JPG IMG_*.PNG; do
  [ -f "$f" ] || continue
  if [ "$f" != "$KEEP" ]; then
    mv -f "$f" "$STASH/"
  fi
done

# rebuild Photos from the single remaining file
rm -f "$PD/Photos.sqlite" "$PD/Photos.sqlite-wal" "$PD/Photos.sqlite-shm"
rm -f "$PD/cpl_enabled_marker" "$PD/cpl_download_finished_marker"
rm -rf "$PD/CPLAssets" "$PD/Caches" "$PD/Thumbnails" \
  "$PD/AlbumsMetadata" "$PD/Metadata" "$PD/Journals"
if [ ! -d "$PD/CPL" ]; then
  mkdir -p "$PD/CPL"
fi
chmod 000 "$PD/CPL" 2>/dev/null

echo ---DCIM---
ls -la "$DCIM"
echo ---STASH---
ls -la "$STASH"
echo keep="$KEEP"
