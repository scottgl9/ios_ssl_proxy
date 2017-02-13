# Device Apple Push Service Notification Token research (APNS):

## APNS token can be found on device at:

/var/mobile/Library/Preferences/com.apple.seld.plist

## In the case of my iphone 6s plus, the APNS token is:

F88298E7B3DEAC94E84A7EB2CE98476F7764F65D6C657DAEAB63FCC8F96630B2

## The token appears in the following URLs:
fmipmobile.icloud.com:
	"apsToken":"F88298E7B3DEAC94E84A7EB2CE98476F7764F65D6C657DAEAB63FCC8F96630B2"

gsas.apple.com:
	<key>ptkn</key>
	<string>F88298E7B3DEAC94E84A7EB2CE98476F7764F65D6C657DAEAB63FCC8F96630B2</string>

p15-caldav.icloud.com (pXX-caldav.icloud.com):
	X-Apple-DAV-Pushtoken: f88298e7b3deac94e84a7eb2ce98476f7764f65d6c657daeab63fcc8f96630b2
	POST https://p15-caldav.icloud.com/mm/sub?token=f88298e7b3deac94e84a7eb2ce98476f7764f65d6c657daeab63fcc8f96630b2&key=280584859-1474a3d96c

p15-keyvalueservice.icloud.com:
	<key>apns-token</key>
	<data>
	+IKY57PerJToSn6yzphHb3dk9l1sZX2uq2P8yPlmMLI=
	</data>

p15-fmip.icloud.com (pXX-fmip.icloud.com):
	aps-token":"F88298E7B3DEAC94E84A7EB2CE98476F7764F65D6C657DAEAB63FCC8F96630B2"


## APNS token shows up in syslog as:

"publicToken" => <data: 0x10043add0>: { length = 32 bytes, contents = 0xf88298e7b3deac94e84a7eb2ce98476f7764f65d6c657dae... }
APSProtocolToken = <f88298e7 b3deac94 e84a7eb2 ce98476f 7764f65d 6c657dae ab63fcc8 f96630b2>;

## Also like the following:

Feb  2 16:28:29 iPhone FindMyiPhone(FMCore)[1496] <Info>: Received updated APS token <private> for environment production
    APSProtocolCommand = 10;
    APSProtocolMessageExpiry = "1970-01-01 18:12:15 +0000";
    APSProtocolMessageID = <00000000>;
    APSProtocolMessageTimestamp = 1486074511127271684;
    APSProtocolPayload = <7b227365 72766572 436f6e74 65787422 3a7b2274 61705365 6e645453 223a2232 3031372d 30322d30 32543232 3a32383a 33312e30 37355a22 2c227461 7053656e 64436f6e 74657874 223a2266 6d697022 7d7d>;
    APSProtocolToken = <f88298e7 b3deac94 e84a7eb2 ce98476f 7764f65d 6c657dae ab63fcc8 f96630b2>;
    APSProtocolTopicHash = <79afbbad c8f8142d 144202ed 12106d5c d3f88f1a>;

## The file /var/mobile/Library/Preferences/com.apple.seld.plist looks like the following:

	<?xml version="1.0" encoding="UTF-8"?>
	<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
	<plist version="1.0">
	<dict>
			<key>APNTokenUpdateInfo</key>
			<data>
			+IKY57PerJToSn6yzphHb3dk9l1sZX2uq2P8yPlmMLI=
			</data>
			<key>SecureElementSequenceCounter</key>
			<integer>2140</integer>
			<key>JCOPUpdateInfo</key>
			<dict>
					<key>seAppletStateMap</key>
					<string>0008</string>
					<key>osUpdateInfo</key>
					<string>085C</string>
			</dict>
			<key>APNToken</key>
			<data>
			+IKY57PerJToSn6yzphHb3dk9l1sZX2uq2P8yPlmMLI=
			</data>
	</dict>
	</plist>


## NOTE: Something strange that I noticed is that the APNS token is actually different for fmf related data:

p15-fmfmobile.icloud.com:
"apsToken":"16C4F883BB993D9819896A595FBE1D0C952E1410434B52A5C5ACF459A5B00EA9"   (for my iphone 6s plus)

## the above seems to also manifest itself in the syslog as follows:

	Feb  2 16:33:41 iPhone SpringBoard(UserNotificationsServer)[828] <Notice>: [com.apple.mobileme.fmf1] Request per-app token with token identifier 2F1AC4AB-3C41-4FE2-A30E-487EBA4B6799
			"identifier" => <string: 0x10321c730> { length = 36, contents = "2F1AC4AB-3C41-4FE2-A30E-487EBA4B6799" }
			"token" => <data: 0x10321e2c0>: { length = 32 bytes, contents = 0x16c4f883bb993d9819896a595fbe1d0c952e1410434b52a5... }
			"topic" => <string: 0x10320b890> { length = 23, contents = "com.apple.mobileme.fmf1" }
			"message-type" => <int64: 0x103206e40>: 33
	}>

