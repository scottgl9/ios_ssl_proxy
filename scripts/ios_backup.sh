#!/bin/sh
# run this before running ios_cleaner.sh just in case anything needs to be restored
# directories affect (for backup):
# /var/Keychains
# /var/mobile/Library 
# omit /var/mobile/Library/Caches/GeoServices
# omit /var/mobile/Library/Caches/com.apple.keyboards
# omit /var/mobile/Library/LASD
# omit /var/mobile/Library/Caches/com.saurik.Cydia/lists
# omit /var/mobile/Library/Caches/com.apple.springboard.sharedimagecache
# /var/preferences
# /var/root/Library/Preferences
DIRNAME=/var/Backups/$(date +%Y%m%d_%H%M%S)
mkdir -p $DIRNAME
cp -rf /var/Keychains $DIRNAME
cp -rf /var/mobile/Library $DIRNAME
rm -rf $DIRNAME/Library/Caches/GeoServices
rm -rf $DIRNAME/Library/Caches/com.apple.keyboards
rm -rf $DIRNAME/Library/LASD
rm -rf $DIRNAME/Library/Caches/com.saurik.Cydia/lists
rm -rf $DIRNAME/Library/Caches/com.apple.springboard.sharedimagecache
cp -rf /var/preferences $DIRNAME
cp -rf /var/root/Library/Preferences $DIRNAME
