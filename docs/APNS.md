# Device Apple Push Service Notification Token research (APNS):

## From searching through the filesystem on the iphone 5c for the APS token 0da7f16bce990c4591e054286f071c142db8b8aad665afd552d2e0fbe9497b80, the following files has the token:

Binary file /var/mobile/Containers/Data/Application/E0C6A3BA-CFB8-4585-BFD9-89AA277E4572/Library/Caches/com.apple.mobileme.fmip1/Cache.db matches
Binary file /var/mobile/Containers/Data/Application/E0C6A3BA-CFB8-4585-BFD9-89AA277E4572/Library/Caches/com.apple.mobileme.fmip1/Cache.db-wal matches
Binary file /var/mobile/Library/Caches/com.apple.icloud.findmydeviced/Cache.db-wal matches
Binary file /var/mobile/Library/Caches/com.apple.icloud.fmfd/Cache.db-wal matches
Binary file /var/mobile/Library/Caches/com.apple.mediastream.mstreamd/Cache.db matches
Binary file /var/mobile/Library/Passes/PaymentWebServiceContext.archive matches


## Attempting to intercept APNs on port 5223:

syslog output when generating cert default method:
Mar 23 17:26:09 Scott-Glovers-iPhone UserEventAgent[23] <Error>: Probe message failed 
Mar 23 17:26:09 Scott-Glovers-iPhone apsd[870] <Error>:  SecTrustEvaluate  [leaf SSLHostname] 
Mar 23 17:26:09 Scott-Glovers-iPhone apsd[870] <Error>:  SecTrustEvaluate  [leaf AnchorApple CheckIntermediateMarkerOid CheckLeafMarkerOid SSLHostname] 
Mar 23 17:26:09 Scott-Glovers-iPhone apsd[870] <Warning>: 2017-03-23 17:26:09 -0500 apsd[870]: Failed to validate certificate chain for courier.push.apple.com. 
Mar 23 17:26:09 Scott-Glovers-iPhone apsd[870] <Notice>: 2017-03-23 17:26:09 -0500 apsd[870]: Failed to validate certificate chain for courier.push.apple.com. 
Mar 23 17:26:09 Scott-Glovers-iPhone apsd[870] <Warning>: 2017-03-23 17:26:09 -0500 apsd[870]: Untrusted peer, closing connection immediately 
Mar 23 17:26:09 Scott-Glovers-iPhone apsd[870] <Notice>: 2017-03-23 17:26:09 -0500 apsd[870]: Untrusted peer, closing connection immediately 


## APNS token can be found on device at:

/var/mobile/Library/Preferences/com.apple.seld.plist

https://support.apple.com/en-us/HT203609
TCP port 5223 to communicate with APNs.
TCP port 2195 to send notifications to APNs.
TCP port 2196 for the APNs feedback service.
TCP port 443 is required during device activation, and afterwards for fallback (on Wi-Fi only) if devices can't reach APNs on port 5223.

APNS:

If I understand their docs correctly, deviceToken is unique to device.
It is requested by iOS (or Mac OSX >10.7) when an app makes a request to register itself with APNS.
deviceToken is basically an encrypted deviceID and possibly some other info (not specific to app).
From this, we can easily see that all apps share deviceToken on a device and uninstalling followed by re-installation should not change deviceToken.


## Push Token creation research:
Here are a few lines from syslog after factory resetting an iOS device:

Mar 17 17:25:39 iPad securityd[88] <Notice>: inserted <cert,rowid=2,cdat=2017-03-18 00:25:39 +0000,mdat=2017-03-18 00:25:39 +0000,ctyp=3,cenc=3,labl=APSClientIdentity,alis=null,subj=312D302B0603550403162444323433333032352D414333412D343238342D384132422D443243393645384138353642310B3009060355040613025553310B30090603550408130243413112301006035504071309435550455254494E4F31133011060355040A130A4150504C4520494E432E310F300D060355040B13064950484F4E45,issr=310B300906035504061302555331133011060355040A130A4150504C4520494E432E31153013060355040B130C4150504C45204950484F4E45311F301D060355040313164150504C45204950484F4E4520444556494345204341,slnr=019949F3F7E3F76C2F18,skid=6C94E49E0B217188DB71C31B0E7513A961168E36,pkhh=6C94E49E0B217188DB71C31B0E7513A961168E36,data=0548:030000800B000000...|372e54d82c3c03fa,agrp=com.apple.apsd,pdmn=dku,sync=0,tomb=0,sha1=0A2226A9A197288D54F4F89D9666C2EA30347D22,vwht=null,tkid=null,v_Data=<?>,v_pk=135C136C9CDA4BB181E2EBB967DAD7BE8866044C,accc=null,u_Tomb=null,musr=>
Mar 17 17:25:39 iPad securityd[88] <Notice>: inserted <keys,rowid=12,cdat=2017-03-18 00:25:39 +0000,mdat=2017-03-18 00:25:39 +0000,kcls=1,labl=APSClientIdentity,alis=null,perm=1,priv=1,modi=1,klbl=6C94E49E0B217188DB71C31B0E7513A961168E36,atag=,crtr=0,type=42,bsiz=1024,esiz=1024,sdat=2001-01-01 00:00:00 +0000,edat=2001-01-01 00:00:00 +0000,sens=0,asen=0,extr=1,next=0,encr=0,decr=1,drve=0,sign=1,vrfy=0,snrc=0,vyrc=0,wrap=0,unwp=1,data=049d:030000800B000000...|8e0ed12abcd3ec44,agrp=com.apple.apsd,pdmn=dku,sync=0,tomb=0,sha1=B666BE63415128797CE2795F04F13823D7A972DF,vwht=null,tkid=null,v_Data=<?>,v_pk=5B91939826DCDF39C124B54F4D30219052C419EB,accc=null,u_Tomb=null,musr=>
Mar 17 17:27:43 iPad apsd(PersistentConnection)[85] <Notice>: 2017-03-17 17:27:43 -0700 apsd[85]: Nonce: <00000001 5aded014 18d5f4c7 e221bc68 eb>    Signed: <01015080 f2759ae3 fbec4d6b bb7b7f6d 7da3bc2b 3eb381ed 683ffe05 92f0bf73 5619f02f f1cf7cd2 ba99916a 3a148534 56fb825c 28de0ac4 ded81ae5 f103dae0 ba1d2ce5 65a911ff 1ab1ee73 dc12731f b718cf25 5118f7ba ca8f5a04 7e8cfaf8 91ae05af 1fab6b10 a11a82d8 afa9b531 320027dd 7029d9c5 af2e204a 40dd81d7 13d7>   Result: 1
Mar 17 17:27:43 iPad symptomsd(SymptomEvaluator)[113] <Notice>: Appending a new journal record in memory, record = <ff7ecc58 00000000 62626238 63386237 66306562 31363935 2d366362 30666232 31323131 36386362 32000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 02ff0132 00000000>, pending records = 80 bytes
Mar 17 17:27:43 iPad apsd(PersistentConnection)[85] <Notice>: 2017-03-17 17:27:43 -0700 apsd[85]: <APSCourier: 0x15572440>: Outstanding data received: <083c0180 4320ff33 49a6610f 3718645b 54243283 613efacd 47dc1237 cd20a800 6918a2ee e4ad04a1 14000585 068308a1 3c000aa5 015aded0 124c0b42 5553> (length 62) onInterface: NonCellular. Connected on 0 interfaces.
    APSProtocolToken = <ff3349a6 610f3718 645b5424 3283613e facd47dc 1237cd20 a8006918 a2eee4ad>;
Mar 17 17:27:43 iPad apsd(PersistentConnection)[85] <Notice>: 2017-03-17 17:27:43 -0700 apsd[85]: <APSCourier: 0x15572440>: Received public token '<ff3349a6 610f3718 645b5424 3283613e facd47dc 1237cd20 a8006918 a2eee4ad>'
Mar 17 17:27:43 iPad securityd[88] <Notice>: inserted <genp,rowid=19,cdat=2017-03-18 00:27:43 +0000,mdat=2017-03-18 00:27:43 +0000,desc=null,icmt=null,crtr=null,type=null,scrp=null,labl=null,alis=null,invi=null,nega=null,cusi=null,prot=null,acct=,svce=push.apple.com,gena=null,data=011a:030000800B000000...|404387c9f58221f7,agrp=com.apple.apsd,pdmn=dku,sync=0,tomb=0,sha1=BA1CC2D2622234030A3CA1C118E158F301B1323E,vwht=null,tkid=null,v_Data=<?>,v_pk=678284F6A47CA808B1B52071D044EB6E0E63AF9B,accc=null,u_Tomb=null,musr=>

### NOTE: I found this link to the source code for securityd here: https://opensource.apple.com/source/Security/Security-55471/sec/securityd/SecItemServer.c




### NOTE: The APN token is 32 bytes in length, so might be a SHA256 checksum of some unknown data (HMAC-SHA256)
### APNs generates device token using the unique device certificate (may be using provisioning profile)

## In the case of my iphone 6s plus, the APNS token is:

F88298E7B3DEAC94E84A7EB2CE98476F7764F65D6C657DAEAB63FCC8F96630B2

## in the case of the iPad Pro, the APNs token is:
BD05858D4974AA81D9BF04725437FAFCA19F1B705994C4E239F223F4CC41C0E1

## The token appears in the following URLs:
### setup.icloud.com:
                <key>pushToken</key>
                <string>BD05858D4974AA81D9BF04725437FAFCA19F1B705994C4E239F223F4CC41C0E1</string>

### fmipmobile.icloud.com:
	"apsToken":"F88298E7B3DEAC94E84A7EB2CE98476F7764F65D6C657DAEAB63FCC8F96630B2"

### p15-fmip.icloud.com (pXX-fmip.icloud.com):
        aps-token":"F88298E7B3DEAC94E84A7EB2CE98476F7764F65D6C657DAEAB63FCC8F96630B2"

### p62-fmip.icloud.com (from ipad):
	aps-token":"bd05858d4974aa81d9bf04725437fafca19f1b705994c4e239f223f4cc41c0e1"

### p62-fmf.icloud.com (pXX-fmf.icloud.com):
	{"deviceContext":{"deviceTS":"2017-02-15T01:08:52.554Z","cause":"PasscodeStateChanged"},"deviceInfo":{"locationServicesEnabled":true,"deviceClass":"iPad","passcodeIsSet":true,"isChargerConnected":true,"smlLS":true,"deviceName":"iPhone","deviceColor":"#e4e7e8","allPushTokens":["bd05858d4974aa81d9bf04725437fafca19f1b705994c4e239f223f4cc41c0e1"],"fmf":true,"fenceMonitoringCapable":true,"productType":"iPad6,3","locale":"en\_US","aps-token":"bd05858d4974aa81d9bf04725437fafca19f1b705994c4e239f223f4cc41c0e1","udid":"ae3484a9b45603653aed233a0c3f884a546f3c23","fmfVersion":"526","batteryStatus":"Charging","platform":"iphoneos","serialNumber":"DMPS75LGH1MV","timezone":"America\/Chicago","isInternal":false,"batteryLevel":0.31,"fmfRestrictions":false,"fmfBuildVersion":"5.0","enclosureColor":"#e4c1b9","buildVersion":"13G34","productVersion":"9.3.3"}}

### gsas.apple.com:
	<key>ptkn</key>
	<string>F88298E7B3DEAC94E84A7EB2CE98476F7764F65D6C657DAEAB63FCC8F96630B2</string>

### p62-bookmarks.icloud.com (pXX-bookmarks.icloud.com):
	POST https://p62-bookmarks.icloud.com/10730014885/mm/push/register?token=bd05858d4974aa81d9bf04725437fafca19f1b705994c4e239f223f4cc41c0e1&key=10730014885

### p15-caldav.icloud.com (pXX-caldav.icloud.com):
	X-Apple-DAV-Pushtoken: f88298e7b3deac94e84a7eb2ce98476f7764f65d6c657daeab63fcc8f96630b2
	POST https://p15-caldav.icloud.com/mm/sub?token=f88298e7b3deac94e84a7eb2ce98476f7764f65d6c657daeab63fcc8f96630b2&key=280584859-1474a3d96c

### p15-keyvalueservice.icloud.com (pXX-keyvalueservice.icloud.com):
	<key>apns-token</key>
	<data>
	+IKY57PerJToSn6yzphHb3dk9l1sZX2uq2P8yPlmMLI=
	</data>

### p62-sharedstreams.icloud.com (pXX-sharedstreams.icloud.com):
x-apple-mme-sharedstreams-client-token: bd05858d4974aa81d9bf04725437fafca19f1b705994c4e239f223f4cc41c0e1

### p15-streams.icloud.com (pXX-streams.icloud.com):
x-apple-mme-streams-client-token: 98e265e6326d5bc040566ccb2d9a07c88d0937125d44937ead4dfcdb4e3c690f^M

this is very interesting since the client-token is the apns for my iphone 6s+ (from pXX-streams.icloud.com):
	<plist version="1.0">
	<dict>
                <key>streamid</key>
                <string>280584859</string>

                <key>devices</key>
                <array>
                        <dict>
                                <key>client-info</key>
                                <string>&lt;iPhone8,2&gt;&lt;iOS;10.2.1;14D27&gt;&lt;com.apple.CoreMediaStream/2.0 (com.apple.mediastream.mstreamd/2.0)&gt;</string>

                                <key>apiversion</key>
                                <string>kfjVrXr0t5Dl</string>

                                <key>deviceid</key>
                                <string>934a4ff7c85b80d7c92cf7790eec4f6c0d207560</string>

                                <key>client-token</key>
                                <string>5d62dd1296e36fa52ed26cb36a746bbbe205e9b00c2fca3bfc400f527adb5be8</string>

                                <key>timestamp</key>
                                <string>1486619895069</string>

                        </dict>
                </array>

                <key>ctag</key>
                <string>FT=-@RU=31757d0e-5b89-4155-8b52-7b99bb8aded6@S=4381</string>

                <key>parttype</key>
                <string>stream-metadata-begin</string>

	</dict>
	</plist>

## All occurrences of APNS token in syslog output:

	"publicToken" => <data: 0x100730650>: { length = 32 bytes, contents = 0xa3fb33840076736deb790d05a45c49ff26cd1e3e75411bbf... } 
	"<HMDDevice, Identifier = 0990CEE0-3C71-5EE0-A0D9-57B361417A5F, Name = Scott's iPhone, Version = 3.1.0, Keychain Sync = YES, Cloud Data Sync = YES, Resident Capable = NO, RemoteGateway = NO, Destination = token:A3FB33840076736DEB790D05A45C49FF26CD1E3E75411BBF6CFDD0DFFF66BE8F/mailto:scottgl@gmail.com>" 
	Mar  9 21:31:05 Scotts-iPhone homed(HomeKitDaemon)[147] <Info>: Updated current device: <HMDDevice, Identifier = 0990CEE0-3C71-5EE0-A0D9-57B361417A5F, Name = Scott's iPhone, Version = 3.1.0, Keychain Sync = YES, Cloud Data Sync = YES, Resident Capable = NO, RemoteGateway = NO, Destination = token:A3FB33840076736DEB790D05A45C49FF26CD1E3E75411BBF6CFDD0DFFF66BE8F/mailto:scottgl@gmail.com> 
	APSProtocolToken = <a3fb3384 0076736d eb790d05 a45c49ff 26cd1e3e 75411bbf 6cfdd0df ff66be8f>; 
	APSProtocolBaseToken = <a3fb3384 0076736d eb790d05 a45c49ff 26cd1e3e 75411bbf 6cfdd0df ff66be8f>;
	Mar  9 21:40:32 Scotts-iPhone wcd[56] <Notice>: connection: <APSConnection: 0x113e1e8a0>, publicToken: <a3fb3384 0076736d eb790d05 a45c49ff 26cd1e3e 75411bbf 6cfdd0df ff66be8f> 
	Mar  9 21:40:19 Scotts-iPhone watchlistd[140] <Notice>: [WLDPushNotificationController] didReceivePublicToken: <a3fb3384 0076736d eb790d05 a45c49ff 26cd1e3e 75411bbf 6cfdd0df ff66be8f> 
	Mar  9 21:40:35 Scotts-iPhone limitadtrackingd[147] <Notice>: DPID Received public token "<a3fb3384 0076736d eb790d05 a45c49ff 26cd1e3e 75411bbf 6cfdd0df ff66be8f>" on connection <APSConnection: 0x100209070> 

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

