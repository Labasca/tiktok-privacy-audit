#!/bin/sh
export PATH=/var/jb/usr/bin:/var/jb/bin:/usr/bin:/bin:/usr/sbin:/sbin
echo ---ids---
find /var/containers/Bundle/Application -maxdepth 3 -name Info.plist 2>/dev/null | while read p; do
  plutil -key CFBundleIdentifier "$p" 2>/dev/null
done | grep -i youcan || echo no-youcan-installed
echo ---open---
uiopen "itms-apps://apps.apple.com/us/app/youcan/id1660982988"
echo done
