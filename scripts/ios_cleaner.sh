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
launchctl unload -w /System/Library/LaunchDaemons/com.apple.apsd.plist
launchctl unload -w /System/Library/LaunchDaemons/com.apple.cloudd.plist
launchctl unload -w /System/Library/LaunchDaemons/com.apple.security.CircleJoinRequested.plist
launchctl unload -w /System/Library/LaunchDaemons/com.apple.cmfsyncagent.plist
launchctl unload -w /System/Library/LaunchDaemons/com.apple.familycircled.plist
launchctl unload -w /System/Library/LaunchDaemons/com.apple.idamd.plist
launchctl unload -w /System/Library/LaunchDaemons/com.apple.lskdd.plist
launchctl unload -w /System/Library/LaunchDaemons/com.apple.nanobackupd.plist
launchctl unload -w /System/Library/LaunchDaemons/com.apple.syncdefaultsd.plist
killall -9 absd akd accountsd activationd aggregated askpermissiond assetsd atc backupd syncdefaultsd AppleIDAuthAgent aosnotifyd apsd AssetCacheLocatorService assetsd assistantd bird calaccessd CallHistorySyncHelper cfprefsd cdpd configd cloudd CloudKeychainProxy cmfsyncagent coreauthd dataaccessd familynotificationd fairplayd.H2 findmydeviced fmfd fmflocatord geod identityservices identityservicesd imagent ind IDSKeychainSyncingProxy IDSRemoteURLConnectionAgent IMDMessageServicesAgent itunescloudd itunesstored keybagd lskdd lockdown locationd mapspushd mobileactivationd MobileMail nanoregistryd networkd notifyd nsurlsessiond nsurlstoraged online-auth-agent OTAPKIAssetTool passd pfd pkd profiled routined sbd securityd syncdefaultsd seld tccd Preferences
rm -f `find /private/var/mobile/Containers/Data/Application -name com.apple.mobileme.fmip1 | grep Caches/com.apple.mobileme.fmip1`/Cache.db*
rm -f `find /private/var/mobile/Containers/Data/Application -name com.apple.mobileme.fmf1 | grep Caches/com.apple.mobileme.fmf1`/Cache.db*
rm -f `find /private/var/mobile/Containers/Data/Application -name com.apple.mobileme.fmf1.plist`
rm -f `find /private/var/mobile/Containers/Data/Application -name com.apple.mobileme.fmip1.plist`
find /private/var -name "Cache.db*" -exec rm {} \;

rm -f /private/var/Keychains/keychain-2.db*
rm -f /private/var/root/Library/Preferences/com.apple.coreservices.appleidauthenticationinfo.plist
rm -f /private/var/mobile/Library/AccountNotifications/*.sqlite*
rm -f /private/var/mobile/Library/Accounts/*.sqlite*
rm -f /private/var/mobile/Library/AddressBook/*.sqlite*

# delete certain cache files only
#find /private/var/mobile/Library/Caches -name "Cache.db*"  -exec rm {} \;
rm -rf /private/var/mobile/Library/Caches/CloudKit/*
rm -rf /private/var/mobile/Library/Caches/com.apple.accountsd/*
rm -rf /private/var/mobile/Library/Caches/com.apple.akd/*
rm -rf /private/var/mobile/Library/Caches/com.apple.dataaccess.dataaccessd/*
rm -rf /private/var/mobile/Library/Caches/com.apple.imfoundation.IMRemoteURLConnectionAgent/*
rm -rf /private/var/mobile/Library/Caches/com.apple.passd/fsCachedData/*
rm -rf /private/var/mobile/Library/Caches/com.apple.Preferences/*
rm -rf /private/var/mobile/Library/Caches/com.apple.purplebuddy/*
rm -f /private/var/mobile/Library/Caches/FamilyCircle/CircleCache.plist

rm -f /private/var/mobile/Library/Logs/CrashReporter/DiagnosticLogs/Accounts/cdp*
#rm -rf /private/var/mobile/Library/Caches/PassKit/*
rm -f /private/var/mobile/Library/ApplePushService/aps.*
rm -f /private/var/mobile/Library/Application\ Support/com.apple.ProtectedCloudStorage/*


rm -f /private/var/mobile/Library/Health/*.sqlite*
rm -f /private/var/mobile/Library/IdentityServices/ids*
rm -f /private/var/mobile/Library/ApplePushService/aps.*
rm -rf /private/var/mobile/Library/Calendar/*
rm -rf /private/var/mobile/Library/com.apple.itunesstored/*
rm -rf /private/var/mobile/Library/com.apple.companionappd/*
rm -rf /private/var/mobile/Library/com.apple.nsurlsessiond/*
rm -rf /private/var/mobile/Library/DataAccess/*
rm -rf /private/var/mobile/Library/Health/*
rm -rf /private/var/mobile/Library/homed/*
rm -f /private/var/mobile/Library/LASD/*
rm -f /private/var/mobile/Library/locationd/*
rm -f /private/var/mobile/Library/Logs/CrashReporter/*.ips*
rm -f /private/var/mobile/Library/MediaStream/albumshare/personID.plist
rm -rf /private/var/mobile/Library/Mail/*
rm -rf /private/var/mobile/Library/Mobile\ Documents/*
rm -rf /private/var/mobile/Library/MusicLibrary/*
rm -f /private/var/mobile/Library/News/*
rm -rf /private/var/mobile/Library/Notes/notes.sqlite*
rm -rf /private/var/mobile/Library/Safari/*
rm -f /private/var/mobile/Library/Preferences/com.apple.AOS*
rm -f /private/var/mobile/Library/Preferences/com.apple.apsd.plist
rm -f /private/var/mobile/Library/Preferences/com.apple.accounts*
rm -f /private/var/mobile/Library/Preferences/com.apple.assistant*
rm -f /private/var/mobile/Library/Preferences/com.apple.bird.plist
rm -f /private/var/mobile/Library/Preferences/com.apple.calaccessd.plist
rm -f /private/var/mobile/Library/Preferences/com.apple.security.CircleJoinRequested.plist
rm -f /private/var/mobile/Library/Preferences/com.apple.cmfsyncagent.plist
rm -f /private/var/mobile/Library/Preferences/com.apple.coreduet*
rm -f /private/var/mobile/Library/Preferences/com.apple.corerecents.recentsd.plist
rm -f /private/var/mobile/Library/Preferences/com.apple.dataaccess*.plist
rm -f /private/var/mobile/Library/Preferences/com.apple.gamed*.plist
rm -f /private/var/mobile/Library/Preferences/com.apple.identityservices*
rm -f /private/var/mobile/Library/Preferences/com.apple.imessage.bag.plist
rm -f /private/var/mobile/Library/Preferences/com.apple.imservice*
rm -f /private/var/mobile/Library/Preferences/com.apple.ids.*
rm -f /private/var/mobile/Library/Preferences/com.apple.icloud.*
rm -f /private/var/mobile/Library/Preferences/com.apple.itunesstored.plist
rm -f /private/var/mobile/Library/Preferences/com.apple.lasd.plist
rm -f /private/var/mobile/Library/Preferences/com.apple.mobile.*
rm -f /private/var/mobile/Library/Preferences/com.apple.mobile.ld*.plist
rm -f /private/var/mobile/Library/Preferences/com.apple.routined.plist
rm -f /private/var/mobile/Library/Preferences/com.apple.passd.plist
rm -f /private/var/mobile/Library/Preferences/com.apple.seld.*
rm -f /private/var/mobile/Library/Preferences/ProtectedCloudKeySyncing.plist
rm -f /private/var/mobile/Library/Preferences/kbd.plist

rm -f /private/var/mobile/Library/SyncedPreferences/com.apple.cloudrecents.*
rm -f /private/var/mobile/Library/SyncedPreferences/com.apple.cmfsyncagent.plist
rm -f /private/var/mobile/Library/SyncedPreferences/com.apple.sbd*
rm -f /private/var/mobile/Library/SyncedPreferences/com.apple.security.cloudkeychainproxy3.plist
rm -f /private/var/mobile/Library/SyncedPreferences/com.apple.syncedpreferences.plist

rm -f /private/var/mobile/Media/PhotoData/Photos.sqlite*

rm -f /private/var/preferences/SystemConfiguration/com.apple.accounts.exists.plist
rm -f /private/var/preferences/com.apple.security.cloudkeychainproxy3.keysToRegister.plist
#rm -rf /private/var/root/Library/Lockdown
sync
launchctl load -w /System/Library/LaunchDaemons/com.apple.apsd.plist
killall -9 absd akd accountsd activationd aggregated askpermissiond assetsd atc backupd syncdefaultsd AppleIDAuthAgent aosnotifyd apsd AssetCacheLocatorService assetsd assistantd bird calaccessd CallHistorySyncHelper cfprefsd cdpd configd cloudd CloudKeychainProxy cmfsyncagent coreauthd dataaccessd familynotificationd fairplayd.H2 findmydeviced fmfd fmflocatord geod identityservices identityservicesd imagent ind IDSKeychainSyncingProxy IDSRemoteURLConnectionAgent IMDMessageServicesAgent itunescloudd itunesstored keybagd lskdd lockdown locationd mapspushd mobileactivationd MobileMail nanoregistryd networkd notifyd nsurlsessiond nsurlstoraged online-auth-agent OTAPKIAssetTool passd pfd pkd profiled routined sbd securityd syncdefaultsd seld tccd Preferences backboardd SpringBoard
