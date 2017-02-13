# Research on pXX-fmip.icloud.com (such as p15-fmip.icloud.com:

## In the json request body for URL https://p15-fmip.icloud.com/fmipservice/findme/$(UDID)/qc, the 'mid' field under 'deviceInfo' seems to be very similar to the header field value of X-Apple-I-MD-M:

MID:
"mid":         "7uFG2/ZgB6SmF5r93yaqedoq+ruKOeHFqlr+/g8GIhJv84akWFicotj46AtB6A+Svt7ks4Nh+E0/GAeW"
X-Apple-I-MD-M: 7uFG2/ZgB6SmF5r93yaqedoq+rugYFfglwmtO8rZlzO2ICtyDYMjk28WsJ7Ao7BMiPcwfupM8nF8zW87

## I still have no idea what 'mid' indicates or how it is generated.


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
