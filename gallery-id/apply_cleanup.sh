#!/bin/sh
export PATH=/var/jb/usr/bin:/var/jb/bin:/usr/bin:/bin
rm -f /var/mobile/Media/PhotoData/Photos.sqlite-wal /var/mobile/Media/PhotoData/Photos.sqlite-shm
chown mobile:mobile /var/mobile/Media/PhotoData/Photos.sqlite
chmod 644 /var/mobile/Media/PhotoData/Photos.sqlite
rm -f /var/mobile/Media/PhotoData/cpl_enabled_marker
while IFS= read -r p; do
  if [ -n "$p" ]; then
    rm -f "$p"
  fi
done < /tmp/delete_paths.txt
cd /var/mobile/Media/DCIM/100APPLE || exit 1
rm -f IMG_0001.PNG IMG_0002.MP4 IMG_0003.MOV IMG_0004.MOV IMG_0007.JPG \
  IMG_0013.MOV IMG_0014.MOV IMG_0015.MOV IMG_0016.MOV IMG_0017.MOV \
  IMG_0018.MOV IMG_0019.MOV
echo ---DCIM---
ls -la /var/mobile/Media/DCIM/100APPLE/
echo ---still-present---
while IFS= read -r p; do
  if [ -n "$p" ] && [ -e "$p" ]; then
    echo STILL "$p"
  fi
done < /tmp/delete_paths.txt
echo done
