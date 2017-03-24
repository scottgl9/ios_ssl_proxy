# Research on pXX-fmip.icloud.com (such as p15-fmip.icloud.com:

## In the json request body for URL https://p15-fmip.icloud.com/fmipservice/findme/$(UDID)/qc, the 'mid' field under 'deviceInfo' seems to be very similar to the header field value of X-Apple-I-MD-M:

### MID:
	"mid":         "7uFG2/ZgB6SmF5r93yaqedoq+ruKOeHFqlr+/g8GIhJv84akWFicotj46AtB6A+Svt7ks4Nh+E0/GAeW"
	X-Apple-MD-M for gsa.apple.com seems to match mid:
	X-Apple-MD-M: 7uFG2/ZgB6SmF5r93yaqedoq+ruKOeHFqlr+/g8GIhJv84akWFicotj46AtB6A+Svt7ks4Nh+E0/GAeW


## deviceContext cause list
Here is a list of possible cause strings under deviceContext json for pXX-fmip.icloud.com:
- AccountChange
- AOSRestart
- APSTokenReceived
- locationServiceAuthorizationChanged
- LowBatteryLocateChange

aps-token:
	"aps-token": "F88298E7B3DEAC94E84A7EB2CE98476F7764F65D6C657DAEAB63FCC8F96630B2"
	aps-token is the apple push service token used with various other servers, and is constant for a give device, but it seems that it can change possibly when a device is factory reset (or possibly only when a device is updated?)

## Here is the entire body of the fmip request:

	{  
	   "deviceContext":{  
		  "deviceTS":"2017-01-30T18:54:43.435Z",
		  "cause":"locationServiceAuthorizationChanged"
	   },
	   "deviceInfo":{  
		  "lowPowerMode":false,
		  "region":"LL",
		  "fmipEnableReason":3,
		  "timezone":"America\/Chicago",
		  "platform":"iphoneos",
		  "processId":544,
		  "buildVersion":"14C92",
		  "batteryLevel":0.98,
		  "batteryStatus":"Charging",
		  "lowBatteryLocate":false,
		  "locale":"en_US",
		  "hasSM2":true,
		  "productVersion":"10.2",
		  "deviceColor":"#272728",
		  "hasSM1":true,
		  "nfc":true,
		  "trackingStatus":400,
		  "serialNumber":"F2LS47Z9HFM2",
		  "passcodeConstraint":"simple",
		  "activationLock":true,
		  "isInternal":false,
		  "lostModeEnabled":false,
		  "appleId":"houstoncrondor@icloud.com",
		  "otherDevices":[  

		  ],
		  "productType":"iPhone8,2",
		  "passcodeIsSet":false,
		  "secureElement":true,
		  "model":"MN3E2",
		  "fmipLS":true,
		  "alCapability":4,
		  "collectionStatus":"Complete-MA",
		  "locationServicesEnabled":true,
		  "fmipBuildVersion":"5.0",
		  "aps-token":"AA8DF6187B75F1486A3BA8ED53C72541F04E339E4FF3FED166DA84DB60BDECFD",
		  "deviceName":"iPhone",
		  "hasCellularCapability":true,
		  "findMyiPhone":true,
		  "enclosureColor":"#b9b7ba",
		  "fmipVersion":"517",
		  "isChargerConnected":true,
		  "smlLS":true,
		  "supportsLostModeV2":true,
		  "deviceClass":"iPhone",
		  "udid":"87cda23a7230769ef6aa1ded8a99a5d3e65b9d42"
	   }
	}

## For the iphone 6s+ with serial F2LS47Z9HFM2 here are some unknown fields from the above:

	"alCapability":4
	"fmipLS":true
	"fmipEnableReason":3
	"hasSM1":true
	"hasSM2":true
	"secureElement":true
	"supportsLostModeV2":true
	"smlLS":true


## unregister device iphone 3gs:

	POST https://p15-fmip.icloud.com/fmipservice/findme/280584859/a14f66f0c87e01571e3d1193e2a716809b811380/unregister HTTP/1.1
	Accept-Language: en-us
	X-Apple-PrsId: 280584859
	Accept: */*
	Content-Type: application/json
	X-Apple-Find-API-Ver: 5.0
	Cookie: NSC_q15-gnjqtfswjdf=ffffffff12ac5ed345525d5f4f58455e445a4a422d6a
	Authorization: Basic MjgwNTg0ODU5OkFRQUFBQUJZeEwzV0dHa1BQRDZXTzNEX19HNTRTYWxDbC1iZDhQUX4=
	X-Apple-Realm-Support: 1.0
	User-Agent: MobileMeNotificationClient/5.0 iPhone2,1/10B500
	Content-length: 779
	Host: p15-fmip.icloud.com
	Accept-Encoding: gzip, deflate

	==== COOKIE ====
	NSC_q15-gnjqtfswjdf  ffffffff12ac5ed345525d5f4f58455e445a4a422d6a

	==== BASIC AUTH ====
	280584859:AQAAAABYxL3WGGkPPD6WO3D__G54SalCl-bd8PQ~

	==== REQUEST BODY ====
	{
	  "deviceContext": {
		"deviceTS": "2017-03-12T03:30:20.938Z"
	  }, 
	  "deviceInfo": {
		"deviceName": "iPhone", 
		"trackNotifyEnabled": false, 
		"locale": "en_US", 
		"isInternal": false, 
		"deviceClass": "iPhone", 
		"timezone": "America/Chicago", 
		"locationServicesEnabled": true, 
		"findMyiPhone": false, 
		"fmipBuildVersion": "2.0.3", 
		"fmipVersion": "325", 
		"productVersion": "6.1.6", 
		"isChargerConnected": true, 
		"batteryLevel": 0.5360624, 
		"lang": "en", 
		"passcodeIsSet": true, 
		"buildVersion": "10B500", 
		"lostModeEnabled": false, 
		"trackingStatus": 400, 
		"batteryStatus": "Charging", 
		"aps-token": "e29d46504faadf07f13d53232cc59ad834b8a1ebf5849f2b2088a8a22831f12a", 
		"udid": "a14f66f0c87e01571e3d1193e2a716809b811380", 
		"passcodeConstraint": "fullKeyboard", 
		"deviceColor": "unknown", 
		"productType": "iPhone2,1"
	  }
	}

	HTTP/1.1 200 OK
	Server: AppleHttpServer/1dad28f
	Date: Sun, 12 Mar 2017 03:30:24 GMT
	Content-Type: application/json;charset=UTF-8
	X-Responding-Instance: fmipservice:11500602:st13p15ic-hpaa022244:7002:17B115:20be063
	X-Responding-Server: st13p15ic-hpaa022244_002
	X-Responding-Partition: p15
	Content-Encoding: gzip
	Vary: Accept-Encoding
	Strict-Transport-Security: max-age=31536000; includeSubDomains
	via: icloudedge:da06p00ic-ztde010309:7401:17A73:Dallas
	X-Apple-Request-UUID: 94d63334-ac71-40e0-b967-e217b0c83ddb
	access-control-expose-headers: X-Apple-Request-UUID
	access-control-expose-headers: Via
	Content-Length: 20

