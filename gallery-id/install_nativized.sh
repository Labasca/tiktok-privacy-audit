#!/bin/sh
# Recents = only the nativized clip. Everything else goes to stash.
# Mirrors install_canary.sh so arm 9 is comparable to arms 1-8.
export PATH=/var/jb/usr/bin:/var/jb/bin:/usr/bin:/bin

KEEP=IMG_0034.MOV
SRC=/tmp/nativized.mov
DCIM=/var/mobile/Media/DCIM/100APPLE
STASH=/var/mobile/Media/poster-inbox/solo-stash
PD=/var/mobile/Media/PhotoData

killall -9 photolibraryd photoanalysisd cameracaptured MobileSlideShow \
  cloudphotod assetsd Camera 2>/dev/null

mkdir -p "$STASH" "$DCIM"

for f in "$DCIM"/IMG_*.MOV "$DCIM"/IMG_*.MP4 "$DCIM"/IMG_*.JPG "$DCIM"/IMG_*.PNG; do
  [ -f "$f" ] || continue
  mv -f "$f" "$STASH/"
done

if [ ! -f "$SRC" ]; then
  echo "missing $SRC" >&2
  exit 1
fi
cp "$SRC" "$DCIM/$KEEP"
chown mobile:mobile "$DCIM/$KEEP"
chmod 644 "$DCIM/$KEEP"

# rebuild Photos so Recents holds exactly this one item
rm -f "$PD/Photos.sqlite" "$PD/Photos.sqlite-wal" "$PD/Photos.sqlite-shm"
rm -f "$PD/cpl_enabled_marker" "$PD/cpl_download_finished_marker"
rm -rf "$PD/CPLAssets" "$PD/Caches" "$PD/Thumbnails" \
  "$PD/AlbumsMetadata" "$PD/Metadata" "$PD/Journals"
if [ ! -d "$PD/CPL" ]; then
  mkdir -p "$PD/CPL"
fi
chown -R mobile:mobile "$PD" 2>/dev/null

echo "installed $KEEP  $(stat -c %s "$DCIM/$KEEP" 2>/dev/null || wc -c < "$DCIM/$KEEP") bytes"
echo "reboot springboard or relaunch Photos to reindex"
