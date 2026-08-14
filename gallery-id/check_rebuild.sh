#!/bin/sh
export PATH=/var/jb/usr/bin:/var/jb/bin:/usr/bin:/bin
echo ---PhotoData---
ls -la /var/mobile/Media/PhotoData/
echo ---sqlite---
ls -la /var/mobile/Media/PhotoData/Photos.sqlite* 2>&1
echo ---cpl---
ls -la /var/mobile/Media/PhotoData/cpl_enabled_marker 2>&1
echo ---kick assetsd---
killall -9 assetsd photolibraryd 2>/dev/null
echo kicked
