## Research on xp.apple.com

### How to compute the various values from the request body to xp.apple.com:

	systemFsCapacity = round_down(TotalSystemCapacity / (1024 * 1024)) = round_down(3604496384 / (1024 * 1024)) = 3437
	dataFsCapacity = round_down(TotalDataCapacity / (1024 * 1024))
	systemFsFree = round_down(TotalSystemAvailable / (1024 * 1024))
	dataFsFree = TotalDataCapacity - TotalDataAvailable
	storageCapacity = round_down(TotalDiskCapacity / (1024 * 1024)) 

### Here is an example post to xp.apple.com:

	POST https://xp.apple.com/report/2/psr_ota HTTP/1.1
	Content-Type: application/json
	Accept: */*
	Accept-Language: en-us
	Content-Length: 895
	User-Agent: softwareupdated (unknown version) CFNetwork/808.1.4 Darwin/16.1.0
	Host: xp.apple.com
	Accept-Encoding: gzip, deflate

	==== REQUEST BODY ====
	{
	  "events": [
		{
		  "result": "success", 
		  "storageCapacity": 15120, 
		  "eventTime": "1482127806987", 
		  "dataFsCapacity": 11682, 
		  "systemFsFree": 160, 
		  "deviceModel": "N51AP", 
		  "dataFsFree": 10656, 
		  "systemFsCapacity": 3437, 
		  "brainVersion": "14A500", 
		  "uptime": 671, 
		  "targetOSVersion": "14C92", 
		  "currentOSType": "user", 
		  "currentOSVersion": "14B100", 
		  "deviceClass": "iPhone", 
		  "batteryIsCharging": true, 
		  "batteryLevel": 74, 
		  "type": "ota", 
		  "event": "prepareFinished", 
		  "reportVersion": 1
		}, 
		{
		  "currentOSVersion": "14B100", 
		  "storageCapacity": 15120, 
		  "eventTime": "1482127512641", 
		  "dataFsCapacity": 11682, 
		  "systemFsFree": 160, 
		  "deviceModel": "N51AP", 
		  "dataFsFree": 10807, 
		  "systemFsCapacity": 3437, 
		  "brainVersion": "14A500", 
		  "uptime": 377, 
		  "targetOSVersion": "14C92", 
		  "currentOSType": "user", 
		  "purgeableSpace": 0, 
		  "deviceClass": "iPhone", 
		  "batteryIsCharging": true, 
		  "batteryLevel": 73, 
		  "type": "ota", 
		  "event": "prepareStarted", 
		  "reportVersion": 1
		}
	  ], 
	  "clientId": "56657878-104A-49FC-A529-30BAD5888AED"
	}

	HTTP/1.1 200 OK
	Date: Mon, 19 Dec 2016 06:14:12 GMT
	Access-Control-Allow-Origin: *
	Access-Control-Allow-Credentials: true
	Expires: Mon, 19 Dec 2016 06:15:12 GMT
	Cache-Control: private
	Content-Type: application/json;charset=utf-8
	X-Apple-Application-Instance: 204
	X-Apple-Application-Site: ST
	X-Apple-Jingle-Correlation-Key: BJ2R2LQILTRLEVA2UKKJ2347QQ
	apple-timing-app: 0ms
	Content-Length: 2

	==== RESPONSE BODY ====
	{}

