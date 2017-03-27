# Research on pXX-fmip.icloud.com (such as p15-fmip.icloud.com:

## In the json request body for URL https://p15-fmip.icloud.com/fmipservice/findme/$(UDID)/qc, the 'mid' field under 'deviceInfo' seems to be very similar to the header field value of X-Apple-I-MD-M:

### MID:
	"mid":         "7uFG2/ZgB6SmF5r93yaqedoq+ruKOeHFqlr+/g8GIhJv84akWFicotj46AtB6A+Svt7ks4Nh+E0/GAeW"
	X-Apple-MD-M for gsa.apple.com seems to match mid:
	X-Apple-MD-M: 7uFG2/ZgB6SmF5r93yaqedoq+ruKOeHFqlr+/g8GIhJv84akWFicotj46AtB6A+Svt7ks4Nh+E0/GAeW


## deviceContext cause list
Here is a list of possible cause strings under deviceContext json for pXX-fmip.icloud.com:
- AccountAdded
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

## Example of simple unregister from FMIP server (without push token):

POST https://p54-fmip.icloud.com/fmipservice/findme/10973066090/c1ffc3c03997b19d9dcf68fb81f117226539ef6b/unregisterV2
Accept-Language: en-us^M
X-Apple-I-MD: AAAABQAAABBkyBSMGoWJOVsc4SKgnC3+AAAAAw==^M
X-Apple-PrsId: 10973066090^M
X-Apple-I-MD-M: q89pkBhz0ArKwC5hqosqZlVI3OtHK8ZkB0lXvnixV5ksspqjyq4fw2IPQitzBP+9KUNJ7YGMnPeItnqG^M
X-Apple-I-Client-Time: 2017-03-27T03:24:26Z^M
Accept: */*^M
Content-Type: application/json^M
X-Apple-Find-API-Ver: 6.0^M
X-Apple-I-MD-RINFO: 17106176^M
Authorization: Basic MTA5NzMwNjYwOTA6QVFBQUFBQlkySVhxUjlIek1CU2NMdU8xazlwclpTMjVjVGMxRWtBfg==^M
X-Apple-Realm-Support: 1.0^M
User-Agent: FMDClient/6.0 iPhone5,3/13E238^M
Content-length: 397^M
Host: p54-fmip.icloud.com^M
Accept-Encoding: gzip, deflate^M
{
  "imei": "357991051309069",
  "deviceContext": {
    "deviceTS": "2017-03-27T03:24:26.791Z"
  }, 
  "serialNumber": "F78L5D2UFNDD",
  "deviceInfo": {
    "fmipDisableReason": 1, 
    "udid": "c1ffc3c03997b19d9dcf68fb81f117226539ef6b",
    "buildVersion": "13E238",
    "deviceColor": "#3b3b3c", 
    "productVersion": "9.3.1", 
    "productType": "iPhone5,3",
    "deviceClass": "iPhone", 
    "enclosureColor": "#f5f4f7"
  }, 
  "meid": "35799105130906"
}^M
HTTP/1.1 200 OK^M
Server: AppleHttpServer/1dad28f^M
Date: Mon, 27 Mar 2017 03:24:27 GMT^M
Content-Type: application/json;charset=UTF-8^M
X-Responding-Instance: fmipservice:35400503:mr90p54ic-zteg03163301:7003:17B115:58016d5^M
X-Responding-Server: mr90p54ic-zteg03163301_003^M
X-Responding-Partition: p54^M
Content-Encoding: gzip^M
Vary: Accept-Encoding^M
Strict-Transport-Security: max-age=31536000; includeSubDomains^M
Set-Cookie: NSC_q54-gnjqtfswjdf=ffffffff1270193245525d5f4f58455e445a4a422d6b;path=/;secure;httponly^M
via: icloudedge:da06p01ic-ztde010316:7401:17B12:Dallas^M
X-Apple-Request-UUID: 7a1a6c07-0e0d-4f41-be61-290ac51de4f3^M
access-control-expose-headers: X-Apple-Request-UUID^M
access-control-expose-headers: Via^M

