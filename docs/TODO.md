## Fix 500 error since I don't know what length the ECID field should be for a newer device with a longer ECID:

POST https://p54-fmip.icloud.com/fmipservice/findme/10973066090/61dd7b522bb9d7cf78008dd4ae502b634b93e970/identityV3 HTTP/1.1
Accept-Language: en-us
X-Apple-PrsId: 10973066090
X-Apple-I-MD: AAAABQAAABAwJtGKFyRP2hfjnWHeF6u4AAAAAw==
X-Apple-I-MD-M: q89pkBhz0ArKwC5hqosqZlVI3OtHK8ZkB0lXvnixV5ksspqjyq4fw2IPQitzBP+9KUNJ7YGMnPeItnqG
X-Apple-I-Client-Time: 2017-04-06T22:00:38Z
Accept: */*
Content-Type: application/json
X-Apple-Find-API-Ver: 6.0
X-Apple-AL-ID: EA1058C0-31C8-48D9-89C9-238FF1BF40C1
X-Apple-I-MD-RINFO: 17106176
Cookie: NSC_q54-gnjqtfswjdf=3af6a3c879369530b4d6e7863a58f4836f2bb7611b7d0ba6c6775cfda4feca351767fecb
Authorization: Basic MTA5NzMwNjYwOTA6QVFBQUFBQlk1cm5Sb0NDV0VDa2s2c1YybUkzVHkxdHBZLW1xLXdFfg==
X-Apple-Realm-Support: 1.0
User-Agent: FMDClient/6.0 iPhone8,2/13E238
Content-length: 482
Host: p54-fmip.icloud.com
Accept-Encoding: gzip, deflate

==== COOKIE ====
NSC_q54-gnjqtfswjdf  3af6a3c879369530b4d6e7863a58f4836f2bb7611b7d0ba6c6775cfda4feca351767fecb

==== BASIC AUTH ====
10973066090:AQAAAABY5rnRoCCWECkk6sV2mI3Ty1tpY-mq-wE~

==== REQUEST BODY ====
{
  "ecid": "0x32040bec26", 
  "wifiMac": "68:db:ca:97:76:00", 
  "serialNumber": "F2PQLYPWGRX5", 
  "deviceInfo": {
    "udid": "61dd7b522bb9d7cf78008dd4ae502b634b93e970", 
    "aps-token": "90bbd89e27d207c418cba08f67befb77a8948e3f7e2c6203a45dc585f2c7be67", 
    "deviceColor": "#e4e7e8", 
    "deviceClass": "iPhone", 
    "enclosureColor": "#e4c1b9"
  }, 
  "meid": "35329007643341", 
  "btMac": "68:db:ca:97:76:01", 
  "imei": "353290076433416", 
  "deviceContext": {
    "deviceTS": "2017-04-06T22:00:38.551Z"
  }, 
  "dsid": "10973066090"
}

HTTP/1.1 500 Internal Server Error
Server: AppleHttpServer/1dad28f
Date: Thu, 06 Apr 2017 22:00:39 GMT
Content-Type: application/json;charset=UTF-8
X-Responding-Instance: fmipservice:35400302:mr90p54ic-zteg03173101:8002:17B115:3150bfb
X-Responding-Server: mr90p54ic-zteg03173101_002
X-Responding-Partition: p54
X-Apple-Retry-After: 0
Strict-Transport-Security: max-age=31536000; includeSubDomains
via: icloudedge:ho11p00ic-ztde011318:7401:17B51:Houston
X-Apple-Request-UUID: 07911e6c-4541-46e7-bf1b-1a3972fef917
access-control-expose-headers: X-Apple-Request-UUID
access-control-expose-headers: Via
Content-Length: 0


Example from my iPhone 6s Plus:
	<key>UniqueChipID</key>
	<integer>3404706751931322</integer>
	
0xc1890108363ba = 3404706751931322


POST https://p15-fmip.icloud.com/fmipservice/findme/280584859/87cda23a7230769ef6aa1ded8a99a5d3e65b9d42/identityV3
X-Mme-Sign2: AwTROoclOcMFgmjEDjDTLqgPQWYKMKiZelSx5oZho64/qyqOPc5rkwLBc1L9eszlzMGx+2KMipL0npqDYVOwx/IAidyy
Cookie: NSC_q15-gnjqtfswjdf=ffffffff12ac5ed045525d5f4f58455e445a4a422d6b
X-Apple-PrsId: 280584859
X-Mme-Sign1: vcPfSIR8rbojEQjfdy7omw==
X-Apple-Realm-Support: 1.0
X-Apple-I-Client-Time: 2017-02-03T18:55:17Z
X-Apple-Find-API-Ver: 6.0
Authorization: Basic MjgwNTg0ODU5OkFRQUFBQUJZbE5HODB6Y2dtcnJpNUR1c2NtUW95c1drTTZXT0dsRX4=
Accept-Language: en-us
X-Apple-I-MD-RINFO: 17106176
Accept: */*
Content-Type: application/json
X-Apple-AL-ID: 2A4BFD38-994F-4DA5-B3A3-A67E69ECE9F5
X-Apple-I-MD-M: 7uFG2/ZgB6SmF5r93yaqedoq+rugYFfglwmtO8rZlzO2ICtyDYMjk28WsJ7Ao7BMiPcwfupM8nF8zW87
X-Apple-I-MD: AAAABQAAABDD4s6at1JUOiIYqphz47gWAAAAAw==
User-Agent: FMDClient/6.0 iPhone8,2/14C92
Content-length: 594
Host: p15-fmip.icloud.com
Accept-Encoding: gzip, deflate
{
   "serialNumber":"F2LS47Z9HFM2",
   "chipId":"0x8003",
   "dsid":"280584859",
   "imei":"355735074445968",
   "wifiMac":"90:b0:ed:7a:0e:03",
   "deviceContext":{
      "deviceTS":"2017-02-03T18:55:10.015Z"
   },
   "btMac":"90:b0:ed:7a:0e:04",
   "ecid":"0xc1890108363ba",
   "meid":"35573507444596",
   "deviceInfo":{
      "aps-token":"E13FE0FBAA3E3E0DF21D772DD34846A662A9F0E4E63D5306671D31D4F6C838BD",
      "collectionStatus":"Complete-MA",
      "alCapability":3,
      "udid":"87cda23a7230769ef6aa1ded8a99a5d3e65b9d42"
   },
   "ifcReceipt":"A4NBPICAP8xBx5WkQDULRHpEi7pXMq16DvnriLqZtO8hGe1cQCndZEusy554KxpcSkYjbwHyggYssopnQUsCeien0GhDkglBWDrl92Plpp7Po+MGO2CmxQZvhxc9erP5"
}
