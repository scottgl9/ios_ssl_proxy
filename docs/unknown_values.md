## Purpose of this document is to document various values associated with devices / accounts, and indicating changes and what causes the value to change:

### APNS
Description: Apple Push Service Notification device token
Changes on software version update: YES
Changes on sign-in of an alternate icloud ID: NO
Changes on factory reset: YES

Searching through the filesystem on the iphone 5c for the APN push token came up with these files having it stored:
Binary file /var/mobile/Containers/Data/Application/E0C6A3BA-CFB8-4585-BFD9-89AA277E4572/Library/Caches/com.apple.mobileme.fmip1/Cache.db matches
Binary file /var/mobile/Containers/Data/Application/E0C6A3BA-CFB8-4585-BFD9-89AA277E4572/Library/Caches/com.apple.mobileme.fmip1/Cache.db-wal matches
Binary file /var/mobile/Library/Caches/com.apple.icloud.findmydeviced/Cache.db-wal matches
Binary file /var/mobile/Library/Caches/com.apple.icloud.fmfd/Cache.db-wal matches
Binary file /var/mobile/Library/Caches/com.apple.mediastream.mstreamd/Cache.db matches
Binary file /var/mobile/Library/Passes/PaymentWebServiceContext.archive matches

## NOTE: iPhone 5 doesn't have a MobileEquipmentIdentifier if it is the GSM version, so if the device being spoofed has an MEID, make sure and insert MEID

### ADSID - advertising Identifier (used by ASIdentifierManager class)
Description: value which seems to be static UUID per account, appears to be same for any iOS device
Changes on software version update: NO
Changes on sign-in of an alternate icloud ID: YES
Changes on factory reset: NO
NOTE: occurs in HomeDomain/System/Library/Accounts/Accounts3.sqlite
Example from setup.icloud.com from my iPhone 6s+ (scottgl@gmail.com): X-Apple-ADSID: 000919-05-b45534a8-fa23-4dfa-9ff7-0fcfa37c3d3
From iPhone 3gs (scottgl@gmail.com):

	<key>aDsID</key>
	<string>000919-05-b45534a8-fa23-4dfa-9ff7-0fcfa37c3d34</string>

Searching through the filesystem on the iphone 5c for the ADSID came up with these files having it stored:
Binary file /var/mobile/Library/Accounts/Accounts3.sqlite-wal matches
Binary file /var/mobile/Library/Caches/com.apple.akd/Cache.db-wal matches

### X-Apple-AL-ID
Header from tbsc.apple.com:
X-Apple-AL-ID: 0F885791-FBCE-4269-A7B3-A84F24F895E7
Also sent as header in request for host pXX-fmip.icloud.com: https://p15-fmip.icloud.com/fmipservice/findme/280584859/87cda23a7230769ef6aa1ded8a99a5d3e65b9d42/identityV3Session

### AIDVRecordIdentifier
Appears in requests to identity.apple.com

### backupDeviceUUID
Description: Used to associate an account's iCloud backup system to a given device. Value seems to be unique per device for all iCloud accounts
Changes on software version update: unknown
Changes on sign-in of an alternate icloud ID: YES
Changes on factory reset: NO
Example from setup.icloud.com from my iPhone 6s+:

	<key>backupDeviceUUID</key>
	<string>D:d9614827b8f0bfd998267f638bccff0acb597f8f</string>

Searching through the filesystem on the iphone 5c for the backupDeviceUUID came up with these files having it stored:
Binary file /var/mobile/Library/Caches/com.apple.Preferences/Cache.db matches
Binary file /var/mobile/Library/Caches/com.apple.Preferences/Cache.db-wal matches


### NOTE: backupDeviceUUID is 20 bytes in length, and is a SHA1 hash of the following:

	v2 = self;
	v3 = objc_msgSend(self->_deviceClass, "hash");
	v4 = (unsigned int)v3 ^ (unsigned int)objc_msgSend(v2->_productType, "hash");
	v5 = v4 ^ (unsigned int)objc_msgSend(v2->_serialNumber, "hash");
	v6 = v5 ^ (unsigned int)objc_msgSend(v2->_deviceColor, "hash");
	v7 = v6 ^ (unsigned int)objc_msgSend(v2->_hardwareModel, "hash");
	v8 = v7 ^ (unsigned int)objc_msgSend(v2->_marketingName, "hash");
	return (unsigned int)objc_msgSend(v2->_deviceEnclosureColor, "hash") ^ v8;

### client-id
Description: Seems to be unique account identifier UUID per device, unsure if it changes per account (used on setup.icloud.com)
Changes on factory reset: YES
Example from setup.icloud.com from my iPhone 6s+:

	<?xml version="1.0" encoding="UTF-8"?>
	<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
	<plist version="1.0">
	<dict>
			<key>protocolVersion</key>
			<string>1.0</string>
			<key>userInfo</key>
			<dict>
					<key>client-id</key>
					<string>D70BEEC5-A8F1-45FE-AF2D-7B0AAC650214</string>
					<key>language</key>
					<string>en-US</string>
					<key>timezone</key>
					<string>America/Chicago</string>
			</dict>
	</dict>
	</plist>

An actual login using a given client-id seems occur as follows on post to https://setup.icloud.com/setup/iosbuddy/loginDelegates:

	POST https://setup.icloud.com/setup/iosbuddy/loginDelegates
	X-Apple-I-MD-RINFO: 17106176
	Accept: */*
	X-MMe-Country: US^M
	X-MMe-Language: en-US
	Accept-Language: en-us
	X-Apple-I-MD-M: 7uFG2/ZgB6SmF5r93yaqedoq+ruy3Y45vpgp4qHYpB3kNCkwFwm3Bsl/laowBDtoqwyN8rEUiE80nVbL
	X-Apple-I-Client-Time: 2017-03-01T18:47:31Z
	X-Apple-ADSID: 000212-08-f5449f96-92bb-4b99-a369-861baf06299c
	X-Apple-I-MD: AAAABQAAABB3JkBapI3UddXSpJgKjxxgAAAAAw==
	Content-Type: text/plist
	User-Agent: accountsd/113 CFNetwork/808.3 Darwin/16.3.0
	X-MMe-Client-Info: <iPhone8,2> <iPhone OS;10.2.1;14D27> <com.apple.AppleAccount/1.0 (com.apple.accountsd/113)>
	Device-UDID: 87cda23a7230769ef6aa1ded8a99a5d3e65b9d42
	Content-length: 805
	Host: setup.icloud.com
	Accept-Encoding: gzip, deflate
	<?xml version="1.0" encoding="UTF-8"?>
	<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
	<plist version="1.0">
	<dict>
			<key>apple-id</key>
			<string>houstoncrondor@icloud.com</string>
			<key>client-id</key>
			<string>D70BEEC5-A8F1-45FE-AF2D-7B0AAC650214</string>
			<key>delegates</key>
			<dict>
					<key>com.apple.gamecenter</key>
					<dict/>
					<key>com.apple.mobileme</key>
					<dict/>
					<key>com.apple.private.ids</key>
					<dict>
							<key>protocol-version</key>
							<string>4</string>
					</dict>
			</dict>
			<key>password</key>
			<string>GcmsSIpP0idTNzoYLe+Xjc/qCd0I+oSGuAOGDJLHSEZnf2EjiaNzquP3gdvc0tA2QlbJQZk06s26SMp0hppTHyyHaoy7D/f3iWJFuzPBwCySZtfdd9dZT0cVOkN8/i6df+GQnlvu4DGOGmi1OUPqObDAD4AQbMtZDakFp3zpLJvLhhr8akZzZr4DnuWiMt1grRiK1Jc=PET</string>
	</dict>
	</plist>

### machineUUID (appears in identity.apple.com), is the same value as AccountUUID:

	<member><name>machineUUID</name><value><string>B831A40E-2238-4F86-BF36-EC85A35D8E01</string></value></member>


### Searching through the iphone 5c's filesystem for signed out icloud users email address was found in the following files:

Binary file /var/mobile/Containers/Data/Application/1654E2CA-7BAE-41A2-9812-F48A94F8D32B/Library/Preferences/com.apple.MailAccount-ExtProperties.plist matches
Binary file /var/mobile/Containers/Data/Application/5BA5BFA6-8510-46C9-89DE-4BDF1B233246/Documents/state.sqlite-wal matches
Binary file /var/mobile/Containers/Data/Application/5BA5BFA6-8510-46C9-89DE-4BDF1B233246/Library/Caches/com.apple.mobileme.fmf1/Cache.db matches
Binary file /var/mobile/Containers/Data/Application/5BA5BFA6-8510-46C9-89DE-4BDF1B233246/Library/Preferences/com.apple.mobileme.fmf1.plist matches
Binary file /var/mobile/Containers/Data/Application/E0C6A3BA-CFB8-4585-BFD9-89AA277E4572/Documents/FMIP.sqlite-wal matches
Binary file /var/mobile/Containers/Data/Application/E0C6A3BA-CFB8-4585-BFD9-89AA277E4572/Library/Caches/com.apple.mobileme.fmip1/Cache.db matches
Binary file /var/mobile/Containers/Data/Application/E0C6A3BA-CFB8-4585-BFD9-89AA277E4572/Library/Caches/com.apple.mobileme.fmip1/Cache.db-wal matches
Binary file /var/mobile/Containers/Data/Application/E0C6A3BA-CFB8-4585-BFD9-89AA277E4572/Library/Preferences/com.apple.mobileme.fmip1.plist matches
Binary file /var/mobile/Library/Accounts/Accounts3.sqlite-wal matches
Binary file /var/mobile/Library/Caches/com.apple.akd/Cache.db-wal matches
Binary file /var/mobile/Library/Caches/com.apple.icloud.findmydeviced/Cache.db-wal matches
Binary file /var/mobile/Library/Caches/com.apple.icloud.fmfd/Cache.db-wal matches
Binary file /var/mobile/Library/Mail/Envelope Index matches
Binary file /var/mobile/Library/Mail/Envelope Index-wal matches
Binary file /var/mobile/Library/Mail/Protected Index-wal matches
Binary file /var/mobile/Library/Notes/notes.sqlite-wal matches
Binary file /var/mobile/Library/Spotlight/CoreSpotlight/NSFileProtectionComplete/index.spotlightV2/dbStr-2.map.data matches
Binary file /var/mobile/Library/Suggestions/snippets.db-wal matches
Binary file /var/root/Library/Preferences/com.apple.coreservices.appleidauthenticationinfo.plist matches
Binary file /var/wireless/Library/Preferences/com.apple.commcenter.callservices.plist matches
