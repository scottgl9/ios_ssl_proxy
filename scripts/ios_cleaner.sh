#!/bin/sh

rm -f /var/Keychains/*.db*
rm -f /var/Keychains/*.sqlite*
rm -f /var/root/Library/Preferences/com.apple.coreservices.appleidauthenticationinfo.plist
rm -f /var/mobile/Library/AccountNotifications/*.sqlite*
rm -f /var/mobile/Library/Accounts/*.sqlite*
rm -f /var/mobile/Library/AddressBook/*.sqlite*
find /var/mobile/Library/Caches -name "Cache.db*"  -exec rm {} \;
rm -rf /var/mobile/Library/DataAccess/*
rm -f /var/mobile/Library/Health/*.sqlite*
rm -f /var/mobile/Library/IdentityServices/ids*
rm -f /var/mobile/Library/ApplePushService/aps.*
rm -f /var/mobile/Library/Preferences/com.apple.accounts*.plist
rm -f /var/mobile/Library/Preferences/com.apple.assistant*.plist
rm -f /var/mobile/Library/Preferences/com.apple.CoreDuet*.plist
rm -f /var/mobile/Library/Preferences/com.apple.gamed*.plist
rm -f /var/mobile/Library/Preferences/com.apple.identityservices*
rm -f /var/mobile/Library/Preferences/com.apple.imservice*
rm -f /var/mobile/Library/Preferences/com.apple.ids.*
rm -f /var/mobile/Library/Preferences/com.apple.icloud.*
rm -f /var/mobile/Library/Preferences/com.apple.mobile.ldpair.plist
rm -f /var/mobile/Library/Preferences/com.apple.seld.plist
rm -f /var/mobile/Library/Preferences/ProtectedCloudKeySyncing.plist

rm -f /var/mobile/Library/SyncedPreferences/com.apple.cloudrecents.*
rm -f /var/mobile/Library/SyncedPreferences/com.apple.cmfsyncagent.plist
rm -f /var/mobile/Library/SyncedPreferences/com.apple.sbd*
rm -f /var/mobile/Library/SyncedPreferences/com.apple.security.cloudkeychainproxy3.plist
rm -f /var/mobile/Library/SyncedPreferences/com.apple.syncedpreferences.plist
rm -rf /var/mobile/Library/Caches/com.apple.*
rm -f /var/preferences/com.apple.security.cloudkeychainproxy3.keysToRegister.plist
