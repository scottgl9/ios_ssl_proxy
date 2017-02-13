# Research on fmipmobile.icloud.com:

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
