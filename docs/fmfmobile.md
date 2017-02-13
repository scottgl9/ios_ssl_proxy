## Example client initialization for fmfmobile:

	POST https://p15-fmfmobile.icloud.com/fmipservice/friends/fmfd/280584859/87cda23a7230769ef6aa1ded8a99a5d3e65b9d42/initClient
	X-Apple-I-MD-RINFO: 17106176
	X-Apple-Realm-Support: 1.0
	Accept: */*
	Authorization: Basic MjgwNTg0ODU5OkFRQUFBQUJZbE5HODJRTExJS0hPVnBZWTVqNzlyVENLUEJtX0Rzc34=
	Accept-Language: en-us
	X-Apple-I-MD-M: 7uFG2/ZgB6SmF5r93yaqedoq+rugYFfglwmtO8rZlzO2ICtyDYMjk28WsJ7Ao7BMiPcwfupM8nF8zW87
	X-Apple-Find-API-Ver: 3.0
	X-Apple-I-Client-Time: 2017-02-03T18:53:56Z
	X-Apple-I-MD: AAAABQAAABAXiPBks/kTtpXbeowg90RaAAAAAw==
	Content-Type: application/json; charset=utf-8
	User-Agent: FMFD/1.0 iPhone8,2/10.2(14C92)
	X-MMe-Client-Info: <iPhone8,2> <iPhone OS;10.2;14C92> <com.apple.icloud.fmfd/100.000000>
	Content-length: 397
	Host: p15-fmfmobile.icloud.com
	Accept-Encoding: gzip, deflate
	{  
	   "clientContext":{  
		  "productType":"iPhone8,2",
		  "deviceHasPasscode":false,
		  "signedInAs":"scottgl@gmail.com",
		  "osVersion":"10.2",
		  "buildVersion":"14C92",
		  "isFMFAppRemoved":false,
		  "deviceUDID":"87cda23a7230769ef6aa1ded8a99a5d3e65b9d42",
		  "deviceClass":"iPhone",
		  "currentTime":1486148036389,
		  "appName":"fmfd",
		  "apsToken":"e13fe0fbaa3e3e0df21d772dd34846a662a9f0e4e63d5306671d31d4f6c838bd",
		  "timezone":"CST, -21600"
	   }
	}
	HTTP/1.1 200 OK
	Server: AppleHttpServer/3b804a0
	Date: Fri, 03 Feb 2017 18:53:56 GMT
	Content-Type: application/json;charset=UTF-8
	X-Responding-Instance: fmipservice:11500201:st13p15ic-fmipservice002:8001:17A134:03366da
	X-Responding-Server: st13p15ic-fmipservice002_001
	X-Responding-Partition: p15
	Content-Encoding: gzip
	Vary: Accept-Encoding
	Strict-Transport-Security: max-age=31536000; includeSubDomains
	Set-Cookie: NSC_q15-gnjqtfswjdf=ffffffff12ac5f3a45525d5f4f58455e445a4a422971;path=/;secure;httponly
	via: icloudedge:da06p00ic-ztde010333:7401:17A23:Dallas
	X-Apple-Request-UUID: 43f0b2fd-431b-48c7-861b-db85c442b0c1
	access-control-expose-headers: X-Apple-Request-UUID
	access-control-expose-headers: Via
	{  
	   "pendingOffers":[  

	   ],
	   "followers":[  
		  {  
			 "invitationFromHandles":[  
				"stormismokes@gmail.com"
			 ],
			 "expires":0,
			 "personIdHash":"19aa884d94361ba86ec860d82eeee6cdad4a3155f093c350efc3f8f2d9429d47",
			 "expiresByGroupId":{  
				"kFMFGroupIdOneToOne":0
			 },
			 "invitationAcceptedHandles":[  
				"scottgl@gmail.com"
			 ],
			 "offerId":"",
			 "source":"APP_OFFER",
			 "id":"MTA1NzkzNzg4Njk~",
			 "onlyInEvent":false,
			 "updateTimestamp":1482500759144
		  }
	   ],
	   "devices":[  
		  {  
			 "deviceIsFencable":true,
			 "name":"iPhone",
			 "otherDevices":[  

			 ],
			 "id":"ZDE3N2M4NzA0YjA5NjgzZDU2ZjMxYTRiOGFjNDY5NTYxYzE4MjY2NQ~~"
		  },
		  {  
			 "deviceIsFencable":true,
			 "name":"Scott's iPhone",
			 "otherDevices":[  

			 ],
			 "id":"ODdjZGEyM2E3MjMwNzY5ZWY2YWExZGVkOGE5OWE1ZDNlNjViOWQ0Mg~~"
		  }
	   ],
	   "serverContext":{  
		  "minCallbackIntervalInMS":5000,
		  "res":null,
		  "clientId":"ZnJpZW5kcy9mbWZkfn4yODA1ODQ4NTl+fjE0ODYxNDgwMzY5MDY=",
		  "prsId":280584859,
		  "callbackTimeoutIntervalInMS":0,
		  "showAirDropImportViewOniCloudAlert":true,
		  "heartbeatIntervalInSec":543600,
		  "maxCallbackIntervalInMS":60000,
		  "transientDataContext":{  
			 "4":0
		  },
		  "notificationToken":"ggGLB+aGlVe34CyQsav8CqYbR5WjiC6Ignd40FnPKgQ=",
		  "iterationNumber":1
	   },
	   "modelVersion":"1",
	   "fetchStatus":"200",
	   "myInfo":{  
		  "emails":[  
			 "scottgl@gmail.com",
			 "scottgl1107@icloud.com"
		  ],
		  "firstName":"Matthew",
		  "meDeviceId":"ODdjZGEyM2E3MjMwNzY5ZWY2YWExZGVkOGE5OWE1ZDNlNjViOWQ0Mg~~",
		  "imessageSupported":false,
		  "deviceTimeStamp":1486148034747,
		  "deviceId":"ODdjZGEyM2E3MjMwNzY5ZWY2YWExZGVkOGE5OWE1ZDNlNjViOWQ0Mg~~"
	   },
	   "following":[  
		  {  
			 "optedNotToShare":true,
			 "invitationFromHandles":[  
				"scottgl@gmail.com"
			 ],
			 "expires":0,
			 "personIdHash":"19aa884d94361ba86ec860d82eeee6cdad4a3155f093c350efc3f8f2d9429d47",
			 "expiresByGroupId":{  
				"defaultFMF":0,
				"kFMFGroupIdOneToOne":0
			 },
			 "invitationAcceptedHandles":[  
				"stormismokes@gmail.com"
			 ],
			 "source":"APP_OFFER",
			 "id":"MTA1NzkzNzg4Njk~",
			 "onlyInEvent":false,
			 "updateTimestamp":1482277705677,
			 "createTimestamp":1482277705456
		  }
	   ],
	   "dataContext":{  
		  "22":1485921577424,
		  "0":1482500759150,
		  "1":1482500759144,
		  "2":1484397682284,
		  "6":33,
		  "19":1,
		  "8":1486074457970,
		  "9":"E8F0629FBAC195C1D18581ABF30DAB2F",
		  "10":1486148036908
	   },
	   "config":{  
		  "maxFollowers":100,
		  "sendOnlyFMFChannel":false,
		  "userLocateWaitIntervalInMS":100,
		  "maxLocatingIntervalInMS":22000,
		  "showAirDropImportViewOniCloudAlert":true,
		  "maxFriends":100,
		  "familyPhotoCheckIntervalInSecs":345600,
		  "lazyInitTimeoutInSec":543600,
		  "transcriptDelegateStopEnabled":true,
		  "graceInterval401InSec":60,
		  "systemInactivityTimeoutInSec":180,
		  "upsellTimeoutInSec":604800,
		  "maxWaitTimeForRegisterMS":12000,
		  "blockFMFChannel":false,
		  "showAirDropImportAlert":true,
		  "showAirDropImportUseFMFAppAlert":false,
		  "locationTTL":7200000,
		  "maxTriesToRegisterDevice":1,
		  "graceInterval5XXInSec":60,
		  "transcriptDelegateStartEnabled":true
	   },
	   "prefs":{  
		  "allowFriendRequests":"Yes",
		  "fenceNotification":"EVERYONE",
		  "hideLocation":"No",
		  "shouldReceiveEmails":"Yes",
		  "primaryEmail":"scottgl@gmail.com",
		  "favorites":[  
			 {  
				"id":"MTA1NzkzNzg4Njk~",
				"order":0
			 }
		  ]
	   }
	}
