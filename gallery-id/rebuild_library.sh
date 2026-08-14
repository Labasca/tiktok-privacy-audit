#!/bin/sh
export PATH=/var/jb/usr/bin:/var/jb/bin:/usr/bin:/bin

killall -9 photolibraryd photoanalysisd cameracaptured MobileSlideShow \
  cloudphotod mediaplaybackd accountsd 2>/dev/null

# apply edited accounts db (iCloud Photos off on this device)
if [ -f /tmp/Accounts3.sqlite ]; then
  mkdir -p /var/mobile/Media/poster-inbox
  cp /var/mobile/Library/Accounts/Accounts3.sqlite \
    /var/mobile/Media/poster-inbox/Accounts3.sqlite.bak
  cp /tmp/Accounts3.sqlite /var/mobile/Library/Accounts/Accounts3.sqlite
  rm -f /var/mobile/Library/Accounts/Accounts3.sqlite-wal \
        /var/mobile/Library/Accounts/Accounts3.sqlite-shm
  chown mobile:mobile /var/mobile/Library/Accounts/Accounts3.sqlite
  chmod 600 /var/mobile/Library/Accounts/Accounts3.sqlite
fi

# keep only the seven test clips in DCIM
cd /var/mobile/Media/DCIM/100APPLE || exit 1
rm -f IMG_0001.PNG IMG_0002.MP4 IMG_0003.MOV IMG_0004.MOV IMG_0007.JPG \
  IMG_0013.MOV IMG_0014.MOV IMG_0015.MOV IMG_0016.MOV IMG_0017.MOV \
  IMG_0018.MOV IMG_0019.MOV

# wipe local Photos library so it rebuilds from DCIM
PD=/var/mobile/Media/PhotoData
rm -f "$PD/Photos.sqlite" "$PD/Photos.sqlite-wal" "$PD/Photos.sqlite-shm"
rm -f "$PD/cpl_enabled_marker" "$PD/cpl_download_finished_marker"
rm -rf "$PD/CPL" "$PD/CPLAssets" "$PD/Caches" "$PD/Thumbnails" \
  "$PD/AlbumsMetadata" "$PD/Metadata" "$PD/Journals" "$PD/Mutations" \
  "$PD/CameraMetadata" "$PD/FacesMetadata" "$PD/PhotoCloudSharingData" \
  "$PD/private" "$PD/external" "$PD/Videos" "$PD/.Photos_SUPPORT" "$PD/MISC"

echo ---DCIM---
ls -la /var/mobile/Media/DCIM/100APPLE/
echo ---PhotoData left---
ls -la "$PD"
echo done
