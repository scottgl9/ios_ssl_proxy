# Notes on FairPlay

If this file is removed, then nothing will pair with the device over USB. Says that it is unable to save activation record:
/private/var/mobile/Library/FairPlay/iTunes_Control/iTunes/IC-Info.sidt

If this file is removed, then it will be recreated on device reboot:
/private/var/mobile/Media/iTunes_Control/iTunes/IC-Info.sidv

if the following file is removed, then iTunes says that it is unable to show the summary panel for the given device:
/private/var/mobile/Library/FairPlay/iTunes_Control/iTunes/IC-Info.sisv

Note that IC-Info.sisv exactly matches FairPlayKeyData plist item which is received by the device as a response from the server during activation.
