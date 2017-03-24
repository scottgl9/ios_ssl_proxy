#!/bin/sh

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

#killall -9 akd apsd cloudd accountsd securityd pkd findmydeviced fmfd fmflocatord identityservicesd seld keybagd
killall -9 akd accountsd syncdefaultsd AppleIDAuthAgent aosnotifyd apsd assetsd calaccessd configd cloudd CloudKeychainProxy dataaccessd familynotificationd findmydeviced fmfd fmflocatord identityservices identityservicesd ind IDSKeychainSyncingProxy keybagd locationd mapspushd nanoregistryd passd pkd securityd seld tccd Preferences
rm -f `find /var/mobile/Containers/Data/Application -name com.apple.mobileme.fmip1 | grep Caches/com.apple.mobileme.fmip1`/Cache.db*
rm -f `find /var/mobile/Containers/Data/Application -name com.apple.mobileme.fmf1 | grep Caches/com.apple.mobileme.fmf1`/Cache.db*
rm -f `find /var/mobile/Containers/Data/Application -name com.apple.mobileme.fmf1.plist`
rm -f `find /var/mobile/Containers/Data/Application -name com.apple.mobileme.fmip1.plist`
rm -f /var/Keychains/keychain-2.db*
rm -f /var/root/Library/Preferences/com.apple.coreservices.appleidauthenticationinfo.plist
rm -f /var/mobile/Library/AccountNotifications/*.sqlite*
rm -f /var/mobile/Library/Accounts/*.sqlite*
rm -f /var/mobile/Library/AddressBook/*.sqlite*

# delete certain cache files only
find /var/mobile/Library/Caches -name "Cache.db*"  -exec rm {} \;
rm -rf /var/mobile/Library/Caches/CloudKit/*
rm -rf /var/mobile/Library/Caches/com.apple.accountsd/*
rm -rf /var/mobile/Library/Caches/com.apple.akd/*
rm -rf var/mobile/Library/Caches/com.apple.dataaccess.dataaccessd/*
rm -rf /var/mobile/Library/Caches/com.apple.imfoundation.IMRemoteURLConnectionAgent/*
rm -rf /var/mobile/Library/Caches/com.apple.passd/fsCachedData/*
rm -rf /var/mobile/Library/Caches/com.apple.Preferences/*
rm -rf /var/mobile/Library/Caches/com.apple.purplebuddy/*
rm -f /var/mobile/Library/Caches/FamilyCircle/CircleCache.plist

rm -f /var/mobile/Library/Logs/CrashReporter/DiagnosticLogs/Accounts/cdp*
#rm -rf /var/mobile/Library/Caches/PassKit/*
rm -f /var/mobile/Library/ApplePushService/aps.*
rm -rf /var/mobile/Library/DataAccess/*
rm -f /var/mobile/Library/Health/*.sqlite*
rm -f /var/mobile/Library/IdentityServices/ids*
rm -f /var/mobile/Library/ApplePushService/aps.*
rm -rf /var/mobile/Library/com.apple.companionappd/*
rm -rf /var/mobile/Library/com.apple.nsurlsessiond/*
rm -rf /var/mobile/Library/Health/*
rm -rf /var/mobile/Library/locationd/*
rm -rf /var/mobile/Library/Mail/*
rm -rf /var/mobile/Library/Mobile\ Documents/*
rm -rf /var/mobile/Library/MusicLibrary/*
rm -rf /var/mobile/Library/Notes/notes.sqlite*
rm -rf /var/mobile/Library/Safari/*

rm -f /var/mobile/Library/Preferences/com.apple.AOS*
rm -f /var/mobile/Library/Preferences/com.apple.apsd.plist
rm -f /var/mobile/Library/Preferences/com.apple.accounts*
rm -f /var/mobile/Library/Preferences/com.apple.assistant*
rm -f /var/mobile/Library/Preferences/com.apple.bird.plist
rm -f /var/mobile/Library/Preferences/com.apple.coreduet*
rm -f /var/mobile/Library/Preferences/com.apple.corerecents.recentsd.plist
rm -f /var/mobile/Library/Preferences/com.apple.dataaccess*.plist
rm -f /var/mobile/Library/Preferences/com.apple.gamed*.plist
rm -f /var/mobile/Library/Preferences/com.apple.identityservices*
rm -f /var/mobile/Library/Preferences/com.apple.imservice*
rm -f /var/mobile/Library/Preferences/com.apple.ids.*
rm -f /var/mobile/Library/Preferences/com.apple.icloud.*
rm -f /var/mobile/Library/Preferences/com.apple.lasd.plist
rm -f /var/mobile/Library/Preferences/com.apple.mobile.*
rm -f /var/mobile/Library/Preferences/com.apple.seld.*
rm -f /var/mobile/Library/Preferences/ProtectedCloudKeySyncing.plist
rm -f /var/mobile/Library/Preferences/kbd.plist

rm -f /var/mobile/Library/SyncedPreferences/com.apple.cloudrecents.*
rm -f /var/mobile/Library/SyncedPreferences/com.apple.cmfsyncagent.plist
rm -f /var/mobile/Library/SyncedPreferences/com.apple.sbd*
rm -f /var/mobile/Library/SyncedPreferences/com.apple.security.cloudkeychainproxy3.plist
rm -f /var/mobile/Library/SyncedPreferences/com.apple.syncedpreferences.plist

rm -f /var/mobile/Media/PhotoData/Photos.sqlite*

rm -f /var/preferences/SystemConfiguration/com.apple.accounts.exists.plist
rm -f /var/preferences/com.apple.security.cloudkeychainproxy3.keysToRegister.plist

rm -rf /var/root/Library/Lockdown
killall -9 akd accountsd syncdefaultsd AppleIDAuthAgent aosnotifyd apsd assetsd calaccessd configd cloudd CloudKeychainProxy dataaccessd familynotificationd findmydeviced fmfd fmflocatord identityservices identityservicesd ind IDSKeychainSyncingProxy keybagd locationd mapspushd nanoregistryd passd pkd securityd seld tccd Preferences
reboot

