#!/bin/sh
export PATH=/var/jb/usr/bin:/var/jb/bin:/usr/bin:/bin
echo ---prefs---
ls /var/mobile/Library/Preferences/ | grep -i photo
echo ---cloud prefs---
ls /var/mobile/Library/Preferences/ | grep -i cloud
echo ---account prefs---
ls /var/mobile/Library/Preferences/ | grep -i account
echo ---plist exists---
ls -la /var/mobile/Library/Preferences/com.apple.photolibraryd.plist \
  /var/mobile/Library/Preferences/com.apple.cloudphotod.plist \
  /var/mobile/Library/Preferences/com.apple.photos.plist \
  /var/mobile/Library/Preferences/com.apple.Photos.plist \
  /var/mobile/Library/Preferences/MobileMeAccounts.plist 2>&1
echo ---photolibraryd defaults---
defaults read com.apple.photolibraryd 2>&1 | head -80
echo ---cloudphotod defaults---
defaults read com.apple.cloudphotod 2>&1 | head -40
