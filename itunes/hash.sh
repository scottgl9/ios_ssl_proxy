#!/bin/bash
PATHSTR=`echo -n $1 | sed 's/.\/HomeDomain\//HomeDomain-/g' | sed 's/.\/RootDomain\//RootDomain-/g' | sed 's/.\/WirelessDomain\//WirelessDomain-/g'`
PATHSTR=`echo -n $PATHSTR | sed 's/System\/Library/Library/g'`
PATHSTR=`echo -n $PATHSTR | sed 's/.\/SystemPreferencesDomain\//SystemPreferencesDomain-/g'`
PATHSTR=`echo -n $PATHSTR | sed 's/.\/MobileDeviceDomain\//MobileDeviceDomain-/g'`
PATHSTR=`echo -n $PATHSTR | sed 's/.\/SysSharedContainerDomain-systemgroup.com.apple.configurationprofiles\//SysSharedContainerDomain-systemgroup.com.apple.configurationprofiles-/g'`
PATHSTR=`echo -n $PATHSTR | sed 's/.\/KeychainDomain\//KeychainDomain-/g'`
echo "`echo -n $PATHSTR | sha1sum | awk '{print $1}'` $PATHSTR"
