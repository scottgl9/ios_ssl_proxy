## Purpose of this document is to document various values associated with devices / accounts, and indicating changes and what causes the value to change:

### APNS
Description: Apple Push Service Notification device token
Changes on software version update: YES
Changes on sign-in of an alternate icloud ID: NO
Changes on factory reset: unknown

### ADSID - advertising Identifier (used by ASIdentifierManager class)
Description: value which seems to be static UUID per account, appears to be same for any iOS device
Changes on software version update: NO
Changes on sign-in of an alternate icloud ID: YES
Changes on factory reset: unknown
NOTE: occurs in HomeDomain/System/Library/Accounts/Accounts3.sqlite
Example from setup.icloud.com from my iPhone 6s+ (scottgl@gmail.com): X-Apple-ADSID: 000919-05-b45534a8-fa23-4dfa-9ff7-0fcfa37c3d3
From iPhone 3gs (scottgl@gmail.com):

	<key>aDsID</key>
	<string>000919-05-b45534a8-fa23-4dfa-9ff7-0fcfa37c3d34</string>


### backupDeviceUUID
Description: Used to associate an account's iCloud backup system to a given device. Value seems to be unique per device for all iCloud accounts
Changes on software version update: unknown
Changes on sign-in of an alternate icloud ID: NO
Changes on factory reset: unknown
Example from setup.icloud.com from my iPhone 6s+:

	<key>backupDeviceUUID</key>
	<string>D:d9614827b8f0bfd998267f638bccff0acb597f8f</string>

### client-id
Description: Seems to be unique account identifier UUID per device, unsure if it changes per account (used on setup.icloud.com)
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

