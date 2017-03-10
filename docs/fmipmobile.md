# Research on fmipmobile.icloud.com:

## NOTE: do not need push token when initially connecting to fmipmobile:

	POST https://fmipmobile.icloud.com/fmipservice/device/scottgl@gmail.com/initClient
	X-Apple-Realm-Support: 1.0^M
	X-Apple-I-MD-RINFO: 17106176^M
	Accept: */*^M
	Authorization: Basic c2NvdHRnbEBnbWFpbC5jb206R1hJcUUyaHlIN0l5NnhkcWFheGRqWHVjOVlObVorVVZETFlYcStINUFWdGZWekZSL2taZFF6Z0Y0ZUJYVHkwTDhqdXc3ZjA0Y3Vod0ZFbTh2V2c4eHFseGFzSk8vZmJYbEQ4ZzRHc0MvdXBBMjQ2ZHQ5MzEvZmx4TTA0RXIxMExQT2R0Nms1c1lnQ3dhTVdxTzlqOUZYWVB6V2RQL1JxVVRTOTlGZEZYcWFQTzhZODBTM01QWmRuRVVHb3ZJY0k3TEJSR1JGMHRUcWhCYnlIeDZ2L0hiZE9UZFFmcHdFMVppMXhMWUZvVnZSYTREMktpRERscHFFT0hJUlNkRlo1TWV4MFovcUE9UEVU^M
	Accept-Language: en-us^M
	Content-Type: application/json; charset=utf-8^M
	X-Apple-I-MD-M: 7uFG2/ZgB6SmF5r93yaqedoq+ruy3Y45vpgp4qHYpB3kNCkwFwm3Bsl/laowBDtoqwyN8rEUiE80nVbL^M
	X-Apple-Find-API-Ver: 3.0^M
	X-Apple-I-Client-Time: 2017-02-27T22:07:55Z^M
	X-Apple-I-MD: AAAABQAAABCFxYNU3vZPGrVfv45UmYsXAAAAAw==^M
	X-Apple-AuthScheme: UserIdGuest^M
	User-Agent: FindMyiPhone/500 CFNetwork/808.3 Darwin/16.3.0^M
	Content-length: 370^M
	Host: fmipmobile.icloud.com^M
	Accept-Encoding: gzip, deflate^M
	{
	  "serverContext": {},
	  "clientContext": {
		"clientTimestamp": 509926075067,
		"osBuild": "14D27", 
		"buildVersion": "517",
		"lastSllTimestamp": 0, 
		"geoCountryCode": "US",
		"appVersion": "5.0",
		"push": true, 
		"showSllCount": 0, 
		"inactiveTime": 509926075067,
		"fmly": true,  
		"productType": "iPhone8,2", 
		"deviceUDID": "87cda23a7230769ef6aa1ded8a99a5d3e65b9d42",
		"osVersion": "10.2.1"
	  }
	}


## NOTE: with fmipmobile, the 'mobile seems to indicate the client app. Similar with fmfmobile (find my family) client app.

## In the json request body with URL https://fmipmobile.icloud.com/fmipservice/device/$(DSID)/refreshClient:

clientId under serverContext for example:
	"clientId": "ZGV2aWNlXzI4MDU4NDg1OV8xNDg1OTkwMDcyMTEz"

### the Base64 decoded value of the above is:
	device\_280584859\_1485990072113

## clientId seems to be constructed by appending the prsId value from the request body to the string 'device_', and appended onto that is a timestamp which I need to find where it comes from *TODO*


## When the following URL is used https://fmipmobile.icloud.com/fmipservice/device/scottgl@gmail.com/initClient:

## The response json body contains a list of all devices on the account, and attributes of each device. Here is an example of one of the entries in the response body:

	{  
	   "msg":{  
		  "strobe":false,
		  "userText":false,
		  "playSound":true,
		  "vibrate":true,
		  "createTimestamp":1485661303722,
		  "statusCode":"205"
	   },
	   "canWipeAfterLock":true,
	   "wipeInProgress":false,
	   "lostModeEnabled":false,
	   "activationLocked":false,
	   "passcodeLength":6,
	   "deviceStatus":"203",
	   "deviceColor":"e4e7e8-e4c1b9",
	   "features":{  
		  "MSG":true,
		  "LOC":true,
		  "LLC":false,
		  "CLK":false,
		  "TEU":true,
		  "LMG":false,
		  "SND":true,
		  "CLT":true,
		  "LKL":true,
		  "SVP":false,
		  "LST":true,
		  "LKM":false,
		  "WMG":true,
		  "XRM":false,
		  "PIN":false,
		  "LCK":true,
		  "REM":false,
		  "MCS":false,
		  "CWP":false,
		  "KEY":false,
		  "KPD":false,
		  "WIP":true
	   },
	   "lowPowerMode":false,
	   "rawDeviceModel":"iPhone8,2",
	   "id":"qmryqYQu8JXfewNwtTbsOUD/xFP8k02kqGMbbjbx4VqbAEFmVH9TQaq+ym48hs/y8zjWSiiezezdY6Nb4ELBSvU4KMszVsSfSFWxL6/xukAJKouKHnTvVuHYVNSUzmWV",
	   "remoteLock":null,
	   "isLocating":false,
	   "modelDisplayName":"iPhone",
	   "lostTimestamp":"",
	   "batteryLevel":0.0,
	   "mesg":null,
	   "locationEnabled":true,
	   "lockedTimestamp":null,
	   "locFoundEnabled":true,
	   "snd":{  
		  "createTimestamp":1485661303722,
		  "statusCode":"205"
	   },
	   "fmlyShare":true,
	   "lostDevice":{  
		  "stopLostMode":false,
		  "emailUpdates":true,
		  "userText":true,
		  "sound":false,
		  "ownerNbr":"(346) 312-3284",
		  "text":"Emergency",
		  "createTimestamp":1485676252567,
		  "statusCode":"205"
	   },
	   "lostModeCapable":true,
	   "wipedTimestamp":null,
	   "deviceDisplayName":"iPhone 6s Plus",
	   "prsId":"MTA1NzkzNzg4Njk~",
	   "locationCapable":true,
	   "batteryStatus":"Unknown",
	   "trackingInfo":null,
	   "name":"iPhone",
	   "isMac":false,
	   "thisDevice":false,
	   "deviceClass":"iPhone",
	   "location":null,
	   "deviceModel":"iphone6splus-e4e7e8-e4c1b9",
	   "maxMsgChar":160,
	   "darkWake":false,
	   "remoteWipe":null
	}

## TODO: I really need to figure out how the 'id' field is derived, because I'm pretty sure that if spoofing a locked device, the locked device will show up with the exact same 'id' field:

	"id":"qmryqYQu8JXfewNwtTbsOUD/xFP8k02kqGMbbjbx4VqbAEFmVH9TQaq+ym48hs/y8zjWSiiezezdY6Nb4ELBSvU4KMszVsSfSFWxL6/xukAJKouKHnTvVuHYVNSUzmWV"

## The request body only contains the following for initClient:

	{  
	   "clientContext":{  
		  "push":true,
		  "productType":"iPhone8,2",
		  "geoCountryCode":"US",
		  "fmly":true,
		  "osVersion":"10.2",
		  "inactiveTime":2180,
		  "deviceUDID":"87cda23a7230769ef6aa1ded8a99a5d3e65b9d42",
		  "apsToken":"F88298E7B3DEAC94E84A7EB2CE98476F7764F65D6C657DAEAB63FCC8F96630B2",
		  "lastSllTimestamp":0,
		  "osBuild":"14C92",
		  "appVersion":"6.0",
		  "clientTimestamp":507682871586,
		  "showSllCount":0
	   },
	   "serverContext":{  

	   }
	}

## NOTE: Strangely p15-fmfmobile.icloud.com seems to use a different apsToken value in the request body:

	{  
	   "clientContext":{  
		  "productType":"iPhone8,2",
		  "isAppRestricted":false,
		  "osVersion":"10.2",
		  "lastLoggedInPrsId":"10730014885",
		  "appPushModeAllowed":true,
		  "deviceClass":"iPhone",
		  "apsToken":"16C4F883BB993D9819896A595FBE1D0C952E1410434B52A5C5ACF459A5B00EA9",
		  "appName":"FindMyFriends",
		  "deviceUDID":"87cda23a7230769ef6aa1ded8a99a5d3e65b9d42",
		  "currentTime":1485990037700,
		  "appVersion":"6.0",
		  "pushMode":true,
		  "userInactivityTimeInMS":1
	   }
	}



## This is the request sent when a device is removed via the FMIP app (might be the easiest way to remove a device):
## NOTE: the header field Authorization base64 decoded is 280584859:AQAAAABYwtZbk08UAOpkQSvNKzadKJ766Gjkg60~ (prsId:authToken)

	POST https://fmipmobile.icloud.com/fmipservice/device/280584859/remove
	X-Apple-Realm-Support: 1.0
	X-Apple-I-MD-RINFO: 17106176
	Accept: */*
	Authorization: Basic MjgwNTg0ODU5OkFRQUFBQUJZd3RaYmswOFVBT3BrUVN2Tkt6YWRLSjc2Nkdqa2c2MH4=
	Accept-Language: en-us
	Content-Type: application/json; charset=utf-8
	X-Apple-I-MD-M: 7uFG2/ZgB6SmF5r93yaqedoq+rvAeWh+GUsd91kN4MFTnNxZ7S+ZtriIsvWhzF2ffepBXEW06PD4/aHB
	X-Apple-Find-API-Ver: 3.0
	X-Apple-I-Client-Time: 2017-03-10T16:37:53Z
	X-Apple-I-MD: AAAABQAAABD1v0tqlP38NDrY4Lhu1shyAAAAAw==
	X-Apple-AuthScheme: Guest
	Cookie: NSC_q15-gnjqtfswjdf=ffffffff12ac5f3a45525d5f4f58455e445a4a422971
	User-Agent: FindMyiPhone/500 CFNetwork/808.3 Darwin/16.3.0
	Content-length: 1799
	Host: fmipmobile.icloud.com
	Accept-Encoding: gzip, deflate
	{
	  "device": "8OcuV12vU8lJXLKQF0SeRdHxLlu4uTnGkxpww6dnhfXAVeSf3X4wMeHYVNSUzmWV", 
	  "serverContext": {
		"authToken": "AQAAAABYwtZbk08UAOpkQSvNKzadKJ766Gjkg60~", 
		"maxLocatingTime": 90000, 
		"deviceLoadStatus": "200", 
		"imageBaseUrl": "https://statici.icloud.com", 
		"minTrackLocThresholdInMts": 100, 
		"isHSA": false, 
		"lastSessionExtensionTime": null, 
		"showSllNow": false, 
		"enable2FAFamilyRemove": false, 
		"minCallbackIntervalInMS": 5000, 
		"timezone": {
		  "previousOffset": -25200000, 
		  "currentOffset": -28800000, 
		  "previousTransition": 1478422799999, 
		  "tzCurrentName": "-08:00", 
		  "tzName": "America/Los_Angeles"
		}, 
		"serverTimestamp": 1489163867587, 
		"macCount": 0, 
		"validRegion": true, 
		"sessionLifespan": 900000, 
		"preferredLanguage": "en-us", 
		"maxDeviceLoadTime": 60000, 
		"cloudUser": true, 
		"classicUser": false, 
		"prefsUpdateTime": 1488171233203, 
		"prsId": 280584859, 
		"maxCallbackIntervalInMS": 60000, 
		"useAuthWidget": true, 
		"enableMapStats": true, 
		"trackInfoCacheDurationInSecs": 86400, 
		"info": "WdWG4bBYs9nWOUfQx7Y/9xc5TFKkHIZdbqICX5Y+gL5Oo+te4aW+cnURk8q/tikN", 
		"enable2FAFamilyActions": false, 
		"enable2FAErase": false, 
		"clientId": "ZGV2aWNlXzI4MDU4NDg1OV8xNDg5MTYzNzg5MjM0", 
		"callbackIntervalInMS": 10000
	  }, 
	  "clientContext": {
		"clientTimestamp": 510856673776, 
		"apsToken": "A3FB33840076736DEB790D05A45C49FF26CD1E3E75411BBF6CFDD0DFFF66BE8F", 
		"osBuild": "14D27", 
		"buildVersion": "517", 
		"lastSllTimestamp": 0, 
		"geoCountryCode": "US", 
		"appVersion": "5.0", 
		"push": true, 
		"showSllCount": 0, 
		"inactiveTime": 523, 
		"fmly": true, 
		"productType": "iPhone8,2", 
		"deviceUDID": "87cda23a7230769ef6aa1ded8a99a5d3e65b9d42", 
		"osVersion": "10.2.1", 
		"location": {
		  "floor": null, 
		  "timestamp": 510856590127, 
		  "longitude": -95.61855297801053, 
		  "course": -1, 
		  "horizontalAccuracy": 65, 
		  "latitude": 29.77728398590775, 
		  "speed": -1, 
		  "verticalAccuracy": 10
		}
	  }
	}
	HTTP/1.1 200 OK
	Server: AppleHttpServer/1dad28f
	Date: Fri, 10 Mar 2017 16:37:54 GMT
	Content-Type: application/json;charset=UTF-8
	X-Responding-Instance: fmipservice:11500201:st13p15ic-fmipservice002:8001:17B115:20be063
	X-Responding-Server: st13p15ic-fmipservice002_001
	X-Responding-Partition: p15
	Content-Encoding: gzip
	Vary: Accept-Encoding
	Strict-Transport-Security: max-age=31536000; includeSubDomains
	via: icloudedge:ho11p01ic-ztde011218:7401:17A73:Houston
	X-Apple-Request-UUID: 4de4e7ee-0b00-4c3b-9f7e-97cf11a065cf
	access-control-expose-headers: X-Apple-Request-UUID
	access-control-expose-headers: Via
	Content-Length: 99
	{
	  "serverContext": null, 
	  "alert": null, 
	  "content": [], 
	  "userInfo": null, 
	  "userPreferences": null, 
	  "statusCode": "200"
	}
