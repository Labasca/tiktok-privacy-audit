#!/bin/sh
# Make Photos re-read DCIM. Files are never touched -- only the index is
# dropped, and it rebuilds from whatever is in DCIM right now.
#
# Unlike install_*.sh this stashes nothing, so every clip currently in DCIM
# comes back into the library, including any just added. What does not survive
# is Photos-only state: albums, favourites, edit history.
export PATH=/var/jb/usr/bin:/var/jb/bin:/usr/bin:/bin

DCIM=/var/mobile/Media/DCIM/100APPLE
PD=/var/mobile/Media/PhotoData

echo "---DCIM before (these all come back)---"
ls -la "$DCIM"

killall -9 photolibraryd photoanalysisd cameracaptured MobileSlideShow \
  cloudphotod assetsd Camera 2>/dev/null

# drop the index only. No rm inside DCIM anywhere in this script.
rm -f "$PD/Photos.sqlite" "$PD/Photos.sqlite-wal" "$PD/Photos.sqlite-shm"
rm -f "$PD/cpl_enabled_marker" "$PD/cpl_download_finished_marker"
rm -rf "$PD/CPLAssets" "$PD/Caches" "$PD/Thumbnails" \
  "$PD/AlbumsMetadata" "$PD/Metadata" "$PD/Journals" "$PD/Mutations"

# keep cloudphotod from laying a cloud library over DCIM again
rm -rf "$PD/CPL"
mkdir -p "$PD/CPL"
chmod 000 "$PD/CPL"

chown -R mobile:mobile "$DCIM" 2>/dev/null
chmod 644 "$DCIM"/IMG_* 2>/dev/null

echo "---index dropped---"
ls -la "$PD"/Photos.sqlite* 2>&1
echo "reindex-prepped. Open the Photos app to let it rebuild from DCIM."
