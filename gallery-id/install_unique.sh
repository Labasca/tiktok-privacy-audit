#!/bin/sh
export PATH=/var/jb/usr/bin:/var/jb/bin:/usr/bin:/bin

killall -9 photolibraryd photoanalysisd cameracaptured MobileSlideShow \
  cloudphotod assetsd Camera 2>/dev/null

DCIM=/var/mobile/Media/DCIM/100APPLE
cd "$DCIM" || exit 1

# drop the identical rainbows and the lookalike desk
rm -f IMG_0006.MOV IMG_0008.MOV IMG_0011.MOV IMG_0012.MOV \
      IMG_0001.PNG IMG_0002.MP4 IMG_0003.MOV IMG_0004.MOV IMG_0007.JPG

# newest first in Recents = post order
if [ -f /tmp/unique-1-clean.mov ]; then
  cp /tmp/unique-1-clean.mov "$DCIM/IMG_0021.MOV"
  touch -t 202608141800.00 "$DCIM/IMG_0021.MOV"
fi
if [ -f /tmp/unique-2-stamped.mov ]; then
  cp /tmp/unique-2-stamped.mov "$DCIM/IMG_0022.MOV"
  touch -t 202608141759.00 "$DCIM/IMG_0022.MOV"
fi
chown mobile:mobile "$DCIM"/IMG_0021.MOV "$DCIM"/IMG_0022.MOV 2>/dev/null
chmod 644 "$DCIM"/IMG_0021.MOV "$DCIM"/IMG_0022.MOV 2>/dev/null

# rebuild Photos from DCIM only
PD=/var/mobile/Media/PhotoData
rm -f "$PD/Photos.sqlite" "$PD/Photos.sqlite-wal" "$PD/Photos.sqlite-shm"
rm -f "$PD/cpl_enabled_marker" "$PD/cpl_download_finished_marker"
rm -rf "$PD/CPLAssets" "$PD/Caches" "$PD/Thumbnails" \
  "$PD/AlbumsMetadata" "$PD/Metadata" "$PD/Journals"
# keep CPL directory locked so iCloud cannot refill
if [ ! -d "$PD/CPL" ]; then
  mkdir -p "$PD/CPL"
fi
chmod 000 "$PD/CPL" 2>/dev/null

echo ---DCIM---
ls -la "$DCIM"
echo done
