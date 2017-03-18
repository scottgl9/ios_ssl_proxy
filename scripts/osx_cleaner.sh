#!/bin/sh

#killall -9 akd apsd pkd findmydeviced fmfd fmflocatord identityservicesd seld
rm -f ~/Library/Accounts/*.sqlite*
rm -f ~/Library/AddressBook/*.sqlite*
# delete ccertain cache files only
find ~/Library/Caches -name "Cache.db*"  -exec rm {} \;
rm -rf ~/Library/Caches/CloudKit/*
rm -f ~/Library/Caches/FamilyCircle/*
rm -rf ~/Library/Caches/com.apple.accountsd/*
rm -rf ~/Library/Caches/com.apple.akd/*
rm -rf ~/Library/Caches/com.apple.imfoundation.IMRemoteURLConnectionAgent/*
rm -rf ~/Library/Caches/com.apple.Preferences/*
rm -rf ~/Library/Caches/com.apple.purplebuddy/*
rm -rf ~/Library/Caches/*
rm -f ~/Library/ApplePushService/aps.*
rm -rf ~/Library/DataAccess/*
rm -f ~/Library/Health/*.sqlite*
rm -f ~/Library/IdentityServices/ids*
rm -f ~/Library/ApplePushService/aps.*
rm -rf ~/Library/com.apple.companionappd/*
rm -rf ~/Library/com.apple.nsurlsessiond/*
rm -rf ~/Library/Health/*
rm -rf ~/Library/locationd/*
rm -rf ~/Library/Mail/*
rm -rf ~/Library/Mobile\ Documents/*
rm -rf ~/Library/MusicLibrary/*
rm -rf ~/Library/Safari/*
rm -f ~/Library/Preferences/com.apple.*
rm -f ~/Library/SyncedPreferences/*
