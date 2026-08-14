#!/bin/sh
export PATH=/var/jb/usr/bin:/var/jb/bin:/usr/bin:/bin
killall -9 photolibraryd photoanalysisd cameracaptured MobileSlideShow \
  cloudphotod assetsd Camera 2>/dev/null
rm -rf /var/mobile/Media/PhotoData/CPL
rm -f /var/mobile/Media/PhotoData/cpl_enabled_marker \
      /var/mobile/Media/PhotoData/cpl_download_finished_marker
# stop cloudphotod from recreating a cloud library on top of DCIM
mkdir -p /var/mobile/Media/PhotoData/CPL
chmod 000 /var/mobile/Media/PhotoData/CPL
echo ---after lock---
ls -la /var/mobile/Media/PhotoData/
echo reindexed-prep
