# Analysis of setup.icloud.com packets:

## Login reason types for registerDevice:

on post to https://setup.icloud.com/setup/account/registerDevice, the format of the body is as follows:
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
                <key>cause</key>
                <string>LOGIN_REASON</string>
                <key>deviceInfo</key>
                <dict>
	....
	</dict>
	</plist>

LOGIN\_REASON can be any of the following:
- login
- pushTokenChange

### NOTE: https://setup.icloud.com/setup/account/registerDevice is what actually adds a device to an iCloud account. A device can actually still have FMIP turned on without being registered on an account.


## Analysis of Authorization header field usage for setup.icloud.com:

The response body for https://setup.icloud.com/setup/get_account_settings contains all account tokens.

The Authorization header field looks like the following:
	Authorization: Basic MjgwNTg0ODU5OkFRQUFBQUJZeFZXZTVUTzBEN0lML1ByUFVSdndCaGJiU01BbXl6ND0=^M
Base64 decoding the above gives: 280584859:AQAAAABYxVWe5TO0D7IL/PrPURvwBhbbSMAmyz4=
The above is just PrsID:mmeAuthToken


## Analysis of changes in X-Mme-Nas-Qualify header field (always base64 encoded):

### NOTE: the following is from syslog when posting to setup.icloud.com with X-Mme-Nas-Qualify in headers:

	Mar 13 13:51:20 scottgls-iPhone Preferences(AppleAccount)[788] <Notice>: "Returning cached config bag" 
	Mar 13 13:51:20 scottgls-iPhone Preferences(AppleAccount)[788] <Notice>: "Fetching absinthe cert" 
	Mar 13 13:51:21 scottgls-iPhone Preferences(AppleAccount)[788] <Notice>: @"Got Absinthe cert: 2385 bytes" 
	Mar 13 13:51:21 scottgls-iPhone Preferences(AppleAccount)[788] <Notice>: @"Initializing absinthe session" 
	Mar 13 13:51:22 scottgls-iPhone Preferences(AppleAccount)[788] <Notice>: @"Initialized absinthe session, establishing key" 
	Mar 13 13:51:22 scottgls-iPhone Preferences(AppleAccount)[788] <Notice>: "Returning cached config bag" 
	Mar 13 13:51:22 scottgls-iPhone Preferences(AppleAccount)[788] <Notice>: "Request URL: <private>" 
	Mar 13 13:51:22 scottgls-iPhone Preferences(AppleAccount)[788] <Notice>: "Client Info Header: <private>" 
	Mar 13 13:51:22 scottgls-iPhone Preferences(AppleAccount)[788] <Notice>: "<private>" 
	Mar 13 13:51:22 scottgls-iPhone Preferences(AppleAccount)[788] <Notice>: "Using token auth" 
	Mar 13 13:51:22 scottgls-iPhone Preferences(AppleAccount)[788] <Notice>: @"Absinthe signing data" 
	Mar 13 13:51:22 scottgls-iPhone Preferences(AppleAccount)[788] <Notice>: "X-Mme-Nas-Qualify: <private>" 
	Mar 13 13:51:22 scottgls-iPhone Preferences(AppleAccount)[788] <Notice>: "<private>" 


- The shorter X-Mme-Nas-Qualify header field occurs in the following URLs:
https://setup.icloud.com/setup/get\_account\_settings
https://setup.icloud.com/setup/login\_or\_create\_account

- The longer X-Mme-Nas-Qualify header field occurs in the following URL only:
https://setup.icloud.com/setup/account/registerDevice


## In the first case, the beginning of the data is binary, and looks like the following (binary data before plist):

	02 DF 41 72 EC 3D 86 28 8A 54 27 6F 0A AC F9 8D F4 AC A8 7B A2 17 36 A6 49 07 9D F6 88 AC 8C 24 96 00 00 02 B0 06 00 00 00 00 00 00 00 80 B9 41 61 B8 74 E0 3E 6E 31 D6 CE A0 85 AA 22 19 A5 D2 85 E6 DE 07 1A 97 A8 2D C0 00 DF 03 C1 00 03 46 8A 90 FC 19 3D D8 B2 D9 16 22 42 62 9B 4F 7D B1 AB DD 73 AA 5E 7A 2D DD 64 76 38 AD 2D 6B 69 A3 AE 03 5E 5D 79 6C 36 F8 0F 34 8D DB AD DF B4 65 0D 59 71 1E 60 E3 24 2F 01 17 C1 0B 28 E7 E1 01 5D 2F DD 01 A6 BA AB 0D D2 1C 84 41 F7 09 77 34 13 C7 4B 72 B4 DA FA 17 C1 55 D2 D3 89 86 00 00 01 CB

## The first byte is always constant, and the 32 bytes that follow are always different between requests (could be SHA256). The next 13 bytes seem to be constant always. The next 128 bytes seem to be constantly different between requests, possibly indicating a hash or a cert.

	DF4172EC3D86288A54276F0AACF98DF4ACA87BA21736A649079DF688AC8C2496 

## Binary data following the plist:

	00 00 00 4F 01 DA B7 DC 6B B6 82 09 B9 F9 22 52 F9 73 FF B7 05 BF 43 FD DB 00 00 00 36 08 05 4A 77 15 86 88 1B C3 25 8C 06 22 0B 1C EA 52 95 58 A0 F5 A4 A3 63 1D A0 A0 6F B2 71 E3 BA 36 04 AA 21 7D 51 A6 F2 22 81 B5 0C C0 2F 7B 0B F9 4E B1 2E FF 76 00 00 00 00 00

##in this "footer" binary data, the first three bytes are constant, and the next 20 bytes are constantly different between requests (could be an SHA1 hash). Then the following 4 bytes are constant, and the following 

	DAB7DC6BB68209B9F92252F973FFB705BF43FDDB


## deRegister device (NOTE: backupDeviceUUID also used when communicating with pXX-quota.icloud.com where it is passed in as header field X-Client-Backup-UUID. Also occurs in body as deviceUdid="D:d9614827b8f0bfd998267f638bccff0acb597f8f"):

	POST https://setup.icloud.com/setup/account/deregisterDevice
	X-Apple-I-MD-RINFO: 17106176^M
	X-Mme-Nas-Qualify: Atol8yrv8AwY0oUG0IQ9INcjqyhhXmO4zYC2MLkSy/6bAAADsAYAAAAAAAAAgGmVRKIq5/JjzpWLRy9GwCT0xFwe7VbURJbDlBpOabG0TVPM61gA9/yYYY50+/jIsH4nUJXhhLL4NTWJRErpogGV/PF/wNFzlXSqPAlSYJrxKmKgCyRZb0SeSZDhHItswsyAAULGdInZGI6MBbkfh3aXRK8tL0HuPigxibpDG+dHAAACwjw/eG1sIHZlcnNpb249IjEuMCIgZW5jb2Rpbmc9IlVURi04Ij8+CjwhRE9DVFlQRSBwbGlzdCBQVUJMSUMgIi0vL0FwcGxlLy9EVEQgUExJU1QgMS4wLy9FTiIgImh0dHA6Ly93d3cuYXBwbGUuY29tL0RURHMvUHJvcGVydHlMaXN0LTEuMC5kdGQiPgo8cGxpc3QgdmVyc2lvbj0iMS4wIj4KPGRpY3Q+Cgk8a2V5PmRldmljZUluZm88L2tleT4KCTxkaWN0PgoJCTxrZXk+YXBwbGVJZDwva2V5PgoJCTxzdHJpbmc+c2NvdHRnbEBnbWFpbC5jb208L3N0cmluZz4KCQk8a2V5PmJhY2t1cERldmljZVVVSUQ8L2tleT4KCQk8c3RyaW5nPkQ6ZDk2MTQ4MjdiOGYwYmZkOTk4MjY3ZjYzOGJjY2ZmMGFjYjU5N2Y4Zjwvc3RyaW5nPgoJCTxrZXk+ZHNpZDwva2V5PgoJCTxzdHJpbmc+MjgwNTg0ODU5PC9zdHJpbmc+CgkJPGtleT5wdXNoVG9rZW48L2tleT4KCQk8c3RyaW5nPjVENjJERDEyOTZFMzZGQTUyRUQyNkNCMzZBNzQ2QkJCRTIwNUU5QjAwQzJGQ0EzQkZDNDAwRjUyN0FEQjVCRTg8L3N0cmluZz4KCQk8a2V5PnNlcmlhbE51bWJlcjwva2V5PgoJCTxzdHJpbmc+RjJMUzQ3WjlIRk0yPC9zdHJpbmc+CgkJPGtleT51ZGlkPC9rZXk+CgkJPHN0cmluZz44N2NkYTIzYTcyMzA3NjllZjZhYTFkZWQ4YTk5YTVkM2U2NWI5ZDQyPC9zdHJpbmc+Cgk8L2RpY3Q+Cgk8a2V5PmlzUHJpbWFyeUFjY291bnQ8L2tleT4KCTx0cnVlLz4KPC9kaWN0Pgo8L3BsaXN0PgoAAABPASetR1YnpdTEZG6gwFEIzCPOchIFAAAANgADu+iGT58/2r5K6jHiYSAuSFijVREaMg3HQXPtSSrxyw20bKmfw3i95kec2Bl15FAC1x/OnwAAAAAAAAAAAAAAAAAA^M
	Accept: */*^M
	Authorization: Basic MjgwNTg0ODU5OkFRQUFBQUJZbzFQMXlLZUJ6UnFyN3dobnBYZytpaHFobldBWFJlST0=^M
	X-MMe-Country: US^M
	X-MMe-Client-Info: <iPhone8,2> <iPhone OS;10.2.1;14D27> <com.apple.AppleAccount/1.0 (com.apple.ind/113)>^M
	X-MMe-Language: en-US^M
	Accept-Language: en-us^M
	Content-Length: 706^M
	User-Agent: Settings/1.0 CFNetwork/672.1.10 Darwin/14.0.0^M
	X-Apple-I-MD-M: 7uFG2/ZgB6SmF5r93yaqedoq+ruy3Y45vpgp4qHYpB3kNCkwFwm3Bsl/laowBDtoqwyN8rEUiE80nVbL^M
	X-Apple-ADSID: 000919-05-b45534a8-fa23-4dfa-9ff7-0fcfa37c3d34^M
	X-Apple-I-Client-Time: 2017-02-14T19:05:53Z^M
	X-Apple-I-MD: AAAABQAAABAGdzN00TYBtVwMrNL5Fal9AAAAAw==^M
	Content-Type: application/xml^M
	Host: setup.icloud.com^M
	Accept-Encoding: gzip, deflate^M
	X-Mme-Nas-Qualify-Decoded:
	<?xml version="1.0" encoding="UTF-8"?>
	<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
	<plist version="1.0">
	<dict>
			<key>deviceInfo</key>
			<dict>
					<key>appleId</key>
					<string>scottgl@gmail.com</string>
					<key>backupDeviceUUID</key>
					<string>D:d9614827b8f0bfd998267f638bccff0acb597f8f</string>
					<key>dsid</key>
					<string>280584859</string>
					<key>pushToken</key>
					<string>5D62DD1296E36FA52ED26CB36A746BBBE205E9B00C2FCA3BFC400F527ADB5BE8</string>
					<key>serialNumber</key>
					<string>F2LS47Z9HFM2</string>
					<key>udid</key>
					<string>87cda23a7230769ef6aa1ded8a99a5d3e65b9d42</string>
			</dict>
			<key>isPrimaryAccount</key>
			<true/>
	</dict>
	</plist>


## Here is a sequence of POSTS I've never seen, so adding them all (from spoofing iPhone 6s Plus using iPhone 5c):
### Most notable URLs from below:
### https://setup.icloud.com/setup/iosbuddy/ui/upgradeIOSTermsUI
### https://setup.icloud.com/setup/iosbuddy/updateAppleID
### https://setup.icloud.com/setup/iosbuddy/createDelegateAccounts

	POST https://setup.icloud.com/setup/iosbuddy/ui/upgradeIOSTermsUI
	Accept-Language: en-us
	X-Apple-I-MD: AAAABQAAABA8ubRPJ4pwJZg7x4wP0JrvAAAAAw==
	X-Apple-I-MD-M: q89pkBhz0ArKwC5hqosqZlVI3OtHK8ZkB0lXvnixV5ksspqjyq4fw2IPQitzBP+9KUNJ7YGMnPeItnqG
	X-Apple-I-Client-Time: 2017-04-06T21:51:50Z
	Accept: */*
	Content-Type: application/xml
	X-Apple-I-MD-RINFO: 17106176
	Authorization: Basic am9lLmtpbmcuMUBpY2xvdWQuY29tOkdRc2NrU1paSERXY0FXM0h2c0U0M3d3T3FuNExhQWtzbFFGNW9Lbmc5WXZkWWNlVWNRL2tZL3liSU5laktXMjY3SW5RUW1JVVorOHlKb0xBNTBTN0tQcS9ISE9Qem1YaDJuWCtWRHlHTnpISVcrRVdoN2lxNzNMVmkvWnM3bGdFakUrVmllOTFGMmdKMmJRVnlueWNheXVvbDYvMVpjbWhIdzcxcUd5d3FOTHp6ek56ZDdaWDFGbk5LbGJTWDdwbEJnMjFyWWc9UEVU
	Content-Length: 0
	X-MMe-Country: US
	User-Agent: Setup/1.0 CFNetwork/758.3.15 Darwin/15.4.0
	X-MMe-Client-Info: <iPhone8,2> <iPhone OS;9.3.1;13E238> <com.apple.AppleAccount/1.0 (com.apple.purplebuddy/1.0)>
	Host: setup.icloud.com
	Accept-Encoding: gzip, deflate

	HTTP/1.1 200 OK
	date: Thu, 06 Apr 2017 21:51:50 GMT
	X-Apple-Request-UUID: e3e43102-7c37-315a-9de4-d5bc66007c55
	X-Apple-Jingle-Correlation-Key: 4PSDCAT4G4YVVHPE2W6GMAD4KU
	apple-seq: 0
	apple-tk: false
	Apple-Originating-System: UnknownOriginatingSystem
	X-Responding-Instance: setupservice:35600402:mr90p56ic-zteg05160701:8002:17B247:4001a34
	Cache-Control: no-cache, no-store, private
	Content-Type: application/xml; charset=UTF-8
	content-encoding: gzip
	Strict-Transport-Security: max-age=31536000; includeSubDomains
	Content-Length: 423
	<xmlui action="dismiss">
		<clientInfo continue="true"/>
		<serverInfo restricted="false" tos-versions="0:528801:0:0:0:0:0:0:0:0:0:0:0" session="YXBwbGUtaWQ9am9lLmtpbmcuMSU0MGljbG91ZC5jb20mcGFzc3dvcmQ9R1FzY2tTWlpIRFdjQVczSHZzRTQzd3dPcW40TGFBa3NsUUY1b0tuZzlZdmRZY2VVY1ElMkZrWSUyRnliSU5laktXMjY3SW5RUW1JVVolMkI4eUpvTEE1MFM3S1BxJTJGSEhPUHptWGgyblglMkJWRHlHTnpISVclMkJFV2g3aXE3M0xWaSUyRlpzN2xnRWpFJTJCVmllOTFGMmdKMmJRVnlueWNheXVvbDYlMkYxWmNtaEh3NzFxR3l3cU5Menp6TnpkN1pYMUZuTktsYlNYN3BsQmcyMXJZZyUzRFBFVA=="/>
	</xmlui>

	GET https://setup.icloud.com/setup/qualify/session
	Accept-Language: en-us
	X-Apple-I-MD: AAAABQAAABA8ubRPJ4pwJZg7x4wP0JrvAAAAAw==
	X-Apple-I-MD-M: q89pkBhz0ArKwC5hqosqZlVI3OtHK8ZkB0lXvnixV5ksspqjyq4fw2IPQitzBP+9KUNJ7YGMnPeItnqG
	X-Apple-I-Client-Time: 2017-04-06T21:51:51Z
	Accept: */*
	X-Apple-I-MD-RINFO: 17106176
	X-MMe-Nas-Session: AQhLLJFIHZt9oGVw1iuQTUGwnM3EifahqQVIccT9L/o+YXIgRY2VSWjtgO2Rt+FNLTIFaIVHS+uRpTjaZWTbCCE+Djjhhpmk8zcIAxlmoexAPnwy6qT8SMrzV+C8PkTGwmDJnMS82rD5btLtFP0cLnkHufr8rXHkh4jPPsuLIFO1bVS76cV21mHcByndGha6bSZiSf6bD04g9s4EwtdAlRwzQqA748bCaCUxclKu51dNm/wzr5fMsWF8DqBEqK5ZSp7Oqx6vY9Cj0Tfm/6KdGwKhhTlWFJW6Oqc5NeVg/4S6B3QXjTj76ewFU5n/cObYNuCt2syLzO5dcfRoXi+KPJ79dtPZtQfGWlvwqGSqmc1luu8vJ2eoJbVcAAAAIKUvzEZIWefqzsCUw/gUKCOSUzqUy2tt2UPyTPC8i4qxL1qmLZv2isd5HQkLvjEWXG6RqSA=
	X-MMe-Country: US
	User-Agent: Setup/1.0 CFNetwork/758.3.15 Darwin/15.4.0
	X-MMe-Client-Info: <iPhone8,2> <iPhone OS;9.3.1;13E238> <com.apple.AppleAccount/1.0 (com.apple.purplebuddy/1.0)>
	Host: setup.icloud.com
	Accept-Encoding: gzip, deflate

	HTTP/1.1 200 OK
	date: Thu, 06 Apr 2017 21:51:51 GMT
	X-Apple-Request-UUID: 6392f018-1261-0fab-76c4-082dbec2ef10
	X-Apple-Jingle-Correlation-Key: MOJPAGASMEH2W5WEBAW35QXPCA
	apple-seq: 0
	apple-tk: false
	Apple-Originating-System: UnknownOriginatingSystem
	X-Responding-Instance: setupservice:35600201:mr90p56ic-zteg05151001:8001:17B247:4001a34
	Cache-Control: no-cache, no-store, private
	content-type: application/json; charset=UTF-8
	content-encoding: gzip
	Strict-Transport-Security: max-age=31536000; includeSubDomains
	Content-Length: 246
	{
	  "session-info": "AvrmwUSeOX1wg343To8/hhcAAABA8FCrPaFFjB+rEXQjkzNRP3vJjl33LP3HspjLImWu7GDuo7UIOVH1Ppwy4/o3G6MKl9IZygNKDsMIU0ra04ko1AHfYdKccZsHjL0i0WJQ41i2TH8MlwAAADYHAvnLQpo8JFPT+uIVSFThP99Y5rh3rZ54XFzVgsYAAdE3vsBmJgYRQ8Gr7aJcXSKtr1fKB3FXAEwA", 
	  "success": true
	}
	POST https://setup.icloud.com/setup/iosbuddy/updateAppleID
	X-Apple-I-MD: AAAABQAAABA8ubRPJ4pwJZg7x4wP0JrvAAAAAw==
	Accept-Language: en-us
	X-Apple-I-MD-M: q89pkBhz0ArKwC5hqosqZlVI3OtHK8ZkB0lXvnixV5ksspqjyq4fw2IPQitzBP+9KUNJ7YGMnPeItnqG
	X-Apple-I-Client-Time: 2017-04-06T21:51:51Z
	Accept: */*
	Content-Type: application/x-www-form-urlencoded
	X-Apple-I-MD-RINFO: 17106176
	Authorization: Basic MTA5NzMwNjYwOTA6QVFBQUFBQlk1ak4zZnNjdlNMejZEK3ZUN2tBcFhCclZVZWN0Q2xrPQ==
	X-MMe-Country: US
	X-Mme-Nas-Qualify: AkIpxn3O1hRTat1lzzI7uQi7ikRfZmxxShZytmxvI/25AAAF4AYAAABeAAAAgKrlDNq4NQpkqTnzQrdwLy2kaEDJEJSH36u6ykT8AKCnVk6Yooall6rgfDBept9uWJUjbPw3qgnL01vc8c/0unKQfkP0ZiJIUT4aBBXhoCVPeaLuA08ZlUu8Cj698NiyTYjPOWlnnKUwFEWXscISC+BdKDptPpTeSRTiyL/IJjVpAAAE+Dw/eG1sIHZlcnNpb249IjEuMCIgZW5jb2Rpbmc9IlVURi04Ij8+CjwhRE9DVFlQRSBwbGlzdCBQVUJMSUMgIi0vL0FwcGxlLy9EVEQgUExJU1QgMS4wLy9FTiIgImh0dHA6Ly93d3cuYXBwbGUuY29tL0RURHMvUHJvcGVydHlMaXN0LTEuMC5kdGQiPgo8cGxpc3QgdmVyc2lvbj0iMS4wIj4KPGRpY3Q+Cgk8a2V5PmFwcGxlLWlkPC9rZXk+Cgk8c3RyaW5nPmpvZS5raW5nLjFAaWNsb3VkLmNvbTwvc3RyaW5nPgoJPGtleT5jbGllbnQtaWQ8L2tleT4KCTxzdHJpbmc+Njg0NzY1MDMtQkRCMy00MzYyLUExMDYtRDIxNUVGMEZGRDI2PC9zdHJpbmc+Cgk8a2V5PmNvdW50cnk8L2tleT4KCTxzdHJpbmc+VVM8L3N0cmluZz4KCTxrZXk+bGFuZ3VhZ2U8L2tleT4KCTxzdHJpbmc+ZW4tdXM8L3N0cmluZz4KCTxrZXk+cGFzc3dvcmQ8L2tleT4KCTxzdHJpbmc+R1FzY2tTWlpIRFdjQVczSHZzRTQzd3dPcW40TGFBa3NsUUY1b0tuZzlZdmRZY2VVY1Eva1kveWJJTmVqS1cyNjdJblFRbUlVWis4eUpvTEE1MFM3S1BxL0hIT1B6bVhoMm5YK1ZEeUdOekhJVytFV2g3aXE3M0xWaS9aczdsZ0VqRStWaWU5MUYyZ0oyYlFWeW55Y2F5dW9sNi8xWmNtaEh3NzFxR3l3cU5Menp6TnpkN1pYMUZuTktsYlNYN3BsQmcyMXJZZz1QRVQ8L3N0cmluZz4KCTxrZXk+c2VydmVySW5mbzwva2V5PgoJPGRpY3Q+CgkJPGtleT5yZXN0cmljdGVkPC9rZXk+CgkJPHN0cmluZz5mYWxzZTwvc3RyaW5nPgoJCTxrZXk+c2Vzc2lvbjwva2V5PgoJCTxzdHJpbmc+WVhCd2JHVXRhV1E5YW05bExtdHBibWN1TVNVME1HbGpiRzkxWkM1amIyMG1jR0Z6YzNkdmNtUTlSMUZ6WTJ0VFdscElSRmRqUVZjelNIWnpSVFF6ZDNkUGNXNDBUR0ZCYTNOc1VVWTFiMHR1WnpsWmRtUlpZMlZWWTFFbE1rWnJXU1V5Um5saVNVNWxha3RYTWpZM1NXNVJVVzFKVlZvbE1rSTRlVXB2VEVFMU1GTTNTMUJ4SlRKR1NFaFBVSHB0V0dneWJsZ2xNa0pXUkhsSFRucElTVmNsTWtKRlYyZzNhWEUzTTB4V2FTVXlSbHB6TjJ4blJXcEZKVEpDVm1sbE9URkdNbWRLTW1KUlZubHVlV05oZVhWdmJEWWxNa1l4V21OdGFFaDNOekZ4UjNsM2NVNU1lbnA2VG5wa04xcFlNVVp1VGt0c1lsTllOM0JzUW1jeU1YSlpaeVV6UkZCRlZBPT08L3N0cmluZz4KCQk8a2V5PnRvcy12ZXJzaW9uczwva2V5PgoJCTxzdHJpbmc+MDo1Mjg4MDE6MDowOjA6MDowOjA6MDowOjA6MDowPC9zdHJpbmc+Cgk8L2RpY3Q+Cgk8a2V5PnRpbWV6b25lPC9rZXk+Cgk8c3RyaW5nPkFtZXJpY2EvQ2hpY2Fnbzwvc3RyaW5nPgo8L2RpY3Q+CjwvcGxpc3Q+CgAAAE8B32HSnHGbB4y9ItFiUONYtkx/DJcAAAA2BwL5y0KaPCRT0/riFUhU4T/fWOa4d62eeFxc1YLGAAHRN77AZiYGEUPBq+2iXF0ira9XygdxAAAAAAAAAAA=
	User-Agent: Setup/1.0 CFNetwork/758.3.15 Darwin/15.4.0
	X-MMe-Client-Info: <iPhone8,2> <iPhone OS;9.3.1;13E238> <com.apple.AppleAccount/1.0 (com.apple.purplebuddy/1.0)>
	Device-UDID: 61dd7b522bb9d7cf78008dd4ae502b634b93e970
	Content-length: 1272
	Host: setup.icloud.com
	Accept-Encoding: gzip, deflate
	<?xml version="1.0" encoding="UTF-8"?>
	<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
	<plist version="1.0">
	<dict>
		<key>apple-id</key>
		<string>joe.king.1@icloud.com</string>
		<key>client-id</key>
		<string>68476503-BDB3-4362-A106-D215EF0FFD26</string>
		<key>country</key>
		<string>US</string>
		<key>language</key>
		<string>en-us</string>
		<key>password</key>
		<string>GQsckSZZHDWcAW3HvsE43wwOqn4LaAkslQF5oKng9YvdYceUcQ/kY/ybINejKW267InQQmIUZ+8yJoLA50S7KPq/HHOPzmXh2nX+VDyGNzHIW+EWh7iq73LVi/Zs7lgEjE+Vie91F2gJ2bQVynycayuol6/1ZcmhHw71qGywqNLzzzNzd7ZX1FnNKlbSX7plBg21rYg=PET</string>
		<key>serverInfo</key>
		<dict>
			<key>restricted</key>
			<string>false</string>
			<key>session</key>
			<string>YXBwbGUtaWQ9am9lLmtpbmcuMSU0MGljbG91ZC5jb20mcGFzc3dvcmQ9R1FzY2tTWlpIRFdjQVczSHZzRTQzd3dPcW40TGFBa3NsUUY1b0tuZzlZdmRZY2VVY1ElMkZrWSUyRnliSU5laktXMjY3SW5RUW1JVVolMkI4eUpvTEE1MFM3S1BxJTJGSEhPUHptWGgyblglMkJWRHlHTnpISVclMkJFV2g3aXE3M0xWaSUyRlpzN2xnRWpFJTJCVmllOTFGMmdKMmJRVnlueWNheXVvbDYlMkYxWmNtaEh3NzFxR3l3cU5Menp6TnpkN1pYMUZuTktsYlNYN3BsQmcyMXJZZyUzRFBFVA==</string>
			<key>tos-versions</key>
			<string>0:528801:0:0:0:0:0:0:0:0:0:0:0</string>
		</dict>
		<key>timezone</key>
		<string>America/Chicago</string>
	</dict>
	</plist>

	HTTP/1.1 200 OK
	date: Thu, 06 Apr 2017 21:51:51 GMT
	X-Apple-Request-UUID: aae5af68-80ea-4f24-75a0-b0405a97f469
	X-Apple-Jingle-Correlation-Key: VLS262EA5JHSI5NAWBAFVF7UNE
	apple-seq: 0
	apple-tk: false
	Apple-Originating-System: UnknownOriginatingSystem
	X-Responding-Instance: setupservice:35600202:mr90p56ic-zteg05151001:8002:17B247:4001a34
	Cache-Control: no-cache, no-store, private
	Set-Cookie: tos-versions=0:528801:0:0:0:0:0:0:0:0:0:0:0;Path=/setup/iosbuddy/;HttpOnly
	Set-Cookie: x-setup-session="YXBwbGUtaWQ9am9lLmtpbmcuMSU0MGljbG91ZC5jb20mcGFzc3dvcmQ9R1FzY2tTWlpIRFdjQVczSHZzRTQzd3dPcW40TGFBa3NsUUY1b0tuZzlZdmRZY2VVY1ElMkZrWSUyRnliSU5laktXMjY3SW5RUW1JVVolMkI4eUpvTEE1MFM3S1BxJTJGSEhPUHptWGgyblglMkJWRHlHTnpISVclMkJFV2g3aXE3M0xWaSUyRlpzN2xnRWpFJTJCVmllOTFGMmdKMmJRVnlueWNheXVvbDYlMkYxWmNtaEh3NzFxR3l3cU5Menp6TnpkN1pYMUZuTktsYlNYN3BsQmcyMXJZZyUzRFBFVA==";Path=/setup/iosbuddy/;HttpOnly
	Content-Type: application/xml; charset=UTF-8
	content-encoding: gzip
	Strict-Transport-Security: max-age=31536000; includeSubDomains
	Content-Length: 262
	<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
	<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
	<plist version="1.0">
		<dict>
			<key>apple-id</key>
			<string>joe.king.1@icloud.com</string>

			<key>dsid</key>
			<string>10973066090</string>

			<key>status</key>
			<integer>0</integer>

		</dict>
	</plist>
	POST https://setup.icloud.com/setup/iosbuddy/createDelegateAccounts
	X-Apple-ADSID: 000771-08-4e81ab0e-c629-44f1-ba35-b5e53220b7a5
	X-Apple-I-MD: AAAABQAAABA8ubRPJ4pwJZg7x4wP0JrvAAAAAw==
	Accept-Language: en-us
	X-Apple-I-MD-M: q89pkBhz0ArKwC5hqosqZlVI3OtHK8ZkB0lXvnixV5ksspqjyq4fw2IPQitzBP+9KUNJ7YGMnPeItnqG
	X-Apple-I-Client-Time: 2017-04-06T21:51:51Z
	Accept: */*
	Content-Type: application/x-www-form-urlencoded
	X-Apple-I-MD-RINFO: 17106176
	Cookie: tos-versions=0:528801:0:0:0:0:0:0:0:0:0:0:0; x-setup-session="YXBwbGUtaWQ9am9lLmtpbmcuMSU0MGljbG91ZC5jb20mcGFzc3dvcmQ9R1FzY2tTWlpIRFdjQVczSHZzRTQzd3dPcW40TGFBa3NsUUY1b0tuZzlZdmRZY2VVY1ElMkZrWSUyRnliSU5laktXMjY3SW5RUW1JVVolMkI4eUpvTEE1MFM3S1BxJTJGSEhPUHptWGgyblglMkJWRHlHTnpISVclMkJFV2g3aXE3M0xWaSUyRlpzN2xnRWpFJTJCVmllOTFGMmdKMmJRVnlueWNheXVvbDYlMkYxWmNtaEh3NzFxR3l3cU5Menp6TnpkN1pYMUZuTktsYlNYN3BsQmcyMXJZZyUzRFBFVA=="
	X-MMe-Country: US
	X-Mme-Nas-Qualify: AteDoLBRJyk35LfbtA4ACQbAgQN1TxsoKAvsOMBqwrleAAAHQAYAAABeAAAAgH/8xlFXBHcz1XDqEKm8fh4TnotWHHyJwVN3xb6twyOrCVZdxpNl7yoGoPIQOyvX2vyBkqd12I8GwcRtrUMqFNtxNSEleDOPxoJCqO76kbJdNXDuv4eUdeGvDHA9eelJrUsBn5EAiykoHLrWMXUc7HObw4WPns9FqKurEJ7nCK3dAAAGXjw/eG1sIHZlcnNpb249IjEuMCIgZW5jb2Rpbmc9IlVURi04Ij8+CjwhRE9DVFlQRSBwbGlzdCBQVUJMSUMgIi0vL0FwcGxlLy9EVEQgUExJU1QgMS4wLy9FTiIgImh0dHA6Ly93d3cuYXBwbGUuY29tL0RURHMvUHJvcGVydHlMaXN0LTEuMC5kdGQiPgo8cGxpc3QgdmVyc2lvbj0iMS4wIj4KPGRpY3Q+Cgk8a2V5PmFwcGxlLWlkPC9rZXk+Cgk8c3RyaW5nPmpvZS5raW5nLjFAaWNsb3VkLmNvbTwvc3RyaW5nPgoJPGtleT5jbGllbnQtaWQ8L2tleT4KCTxzdHJpbmc+Njg0NzY1MDMtQkRCMy00MzYyLUExMDYtRDIxNUVGMEZGRDI2PC9zdHJpbmc+Cgk8a2V5PmRlbGVnYXRlczwva2V5PgoJPGRpY3Q+CgkJPGtleT5jb20uYXBwbGUuZmFjZXRpbWU8L2tleT4KCQk8ZGljdD4KCQkJPGtleT5wcm90b2NvbC12ZXJzaW9uPC9rZXk+CgkJCTxzdHJpbmc+NDwvc3RyaW5nPgoJCTwvZGljdD4KCQk8a2V5PmNvbS5hcHBsZS5nYW1lY2VudGVyPC9rZXk+CgkJPGRpY3Q+CgkJCTxrZXk+ZGV2aWNlLWlkPC9rZXk+CgkJCTxzdHJpbmc+NjFkZDdiNTIyYmI5ZDdjZjc4MDA4ZGQ0YWU1MDJiNjM0YjkzZTk3MDwvc3RyaW5nPgoJCQk8a2V5PnBsYXllci1pZDwva2V5PgoJCQk8c3RyaW5nPkc6MTA5NzMwNjYwOTA8L3N0cmluZz4KCQk8L2RpY3Q+CgkJPGtleT5jb20uYXBwbGUuaXR1bmVzPC9rZXk+CgkJPGRpY3Q+CgkJCTxrZXk+ZGV2aWNlLW5hbWU8L2tleT4KCQkJPHN0cmluZz5pUGhvbmU8L3N0cmluZz4KCQkJPGtleT5kcm0tY2xpZW50PC9rZXk+CgkJCTxzdHJpbmc+aVR1bmVzPC9zdHJpbmc+CgkJCTxrZXk+ZHJtLXR5cGU8L2tleT4KCQkJPHN0cmluZz5uNDhhcDwvc3RyaW5nPgoJCQk8a2V5PmRybS12ZXJzaW9uPC9rZXk+CgkJCTxzdHJpbmc+OS4zLjE8L3N0cmluZz4KCQkJPGtleT5ndWlkPC9rZXk+CgkJCTxzdHJpbmc+NjFkZDdiNTIyYmI5ZDdjZjc4MDA4ZGQ0YWU1MDJiNjM0YjkzZTk3MDwvc3RyaW5nPgoJCQk8a2V5PnVzZXItYWdlbnQ8L2tleT4KCQkJPHN0cmluZz5jb20uYXBwbGUucHVycGxlYnVkZHkvMS4wLjAgaU9TLzkuMy4xIG1vZGVsL2lQaG9uZTgsMiBod3AvczVsODk1MHggYnVpbGQvMTNFMjM4ICg2OyBkdDo5Nyk8L3N0cmluZz4KCQk8L2RpY3Q+CgkJPGtleT5jb20uYXBwbGUubWFkcmlkPC9rZXk+CgkJPGRpY3Q+CgkJCTxrZXk+cHJvdG9jb2wtdmVyc2lvbjwva2V5PgoJCQk8c3RyaW5nPjQ8L3N0cmluZz4KCQk8L2RpY3Q+CgkJPGtleT5jb20uYXBwbGUubW9iaWxlbWU8L2tleT4KCQk8ZGljdC8+CgkJPGtleT5jb20uYXBwbGUucHJpdmF0ZS5pZHM8L2tleT4KCQk8ZGljdD4KCQkJPGtleT5wcm90b2NvbC12ZXJzaW9uPC9rZXk+CgkJCTxzdHJpbmc+NDwvc3RyaW5nPgoJCTwvZGljdD4KCTwvZGljdD4KCTxrZXk+cGFzc3dvcmQ8L2tleT4KCTxzdHJpbmc+R1FzY2tTWlpIRFdjQVczSHZzRTQzd3dPcW40TGFBa3NsUUY1b0tuZzlZdmRZY2VVY1Eva1kveWJJTmVqS1cyNjdJblFRbUlVWis4eUpvTEE1MFM3S1BxL0hIT1B6bVhoMm5YK1ZEeUdOekhJVytFV2g3aXE3M0xWaS9aczdsZ0VqRStWaWU5MUYyZ0oyYlFWeW55Y2F5dW9sNi8xWmNtaEh3NzFxR3l3cU5Menp6TnpkN1pYMUZuTktsYlNYN3BsQmcyMXJZZz1QRVQ8L3N0cmluZz4KPC9kaWN0Pgo8L3BsaXN0PgoAAABPAd9h0pxxmweMvSLRYlDjWLZMfwyXAAAANgcC+ctCmjwkU9P64hVIVOE/31jmuHetnnhcXNWCxgAB0Te+wGYmBhFDwavtolxdIq2vV8oHcQAA
	User-Agent: Setup/1.0 CFNetwork/758.3.15 Darwin/15.4.0
	X-MMe-Client-Info: <iPhone8,2> <iPhone OS;9.3.1;13E238> <com.apple.AppleAccount/1.0 (com.apple.purplebuddy/1.0)>
	Content-length: 1628
	Host: setup.icloud.com
	Accept-Encoding: gzip, deflate
	<?xml version="1.0" encoding="UTF-8"?>
	<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
	<plist version="1.0">
	<dict>
		<key>apple-id</key>
		<string>joe.king.1@icloud.com</string>
		<key>client-id</key>
		<string>68476503-BDB3-4362-A106-D215EF0FFD26</string>
		<key>delegates</key>
		<dict>
			<key>com.apple.facetime</key>
			<dict>
				<key>protocol-version</key>
				<string>4</string>
			</dict>
			<key>com.apple.gamecenter</key>
			<dict>
				<key>device-id</key>
				<string>61dd7b522bb9d7cf78008dd4ae502b634b93e970</string>
				<key>player-id</key>
				<string>G:10973066090</string>
			</dict>
			<key>com.apple.itunes</key>
			<dict>
				<key>device-name</key>
				<string>iPhone</string>
				<key>drm-client</key>
				<string>iTunes</string>
				<key>drm-type</key>
				<string>n66map</string>
				<key>drm-version</key>
				<string>9.3.1</string>
				<key>guid</key>
				<string>61dd7b522bb9d7cf78008dd4ae502b634b93e970</string>
				<key>user-agent</key>
				<string>com.apple.purplebuddy/1.0.0 iOS/9.3.1 model/iPhone8,2 hwp/s8003 build/13E238 (6; dt:97)</string>
			</dict>
			<key>com.apple.madrid</key>
			<dict>
				<key>protocol-version</key>
				<string>4</string>
			</dict>
			<key>com.apple.mobileme</key>
			<dict/>
			<key>com.apple.private.ids</key>
			<dict>
				<key>protocol-version</key>
				<string>4</string>
			</dict>
		</dict>
		<key>password</key>
		<string>GQsckSZZHDWcAW3HvsE43wwOqn4LaAkslQF5oKng9YvdYceUcQ/kY/ybINejKW267InQQmIUZ+8yJoLA50S7KPq/HHOPzmXh2nX+VDyGNzHIW+EWh7iq73LVi/Zs7lgEjE+Vie91F2gJ2bQVynycayuol6/1ZcmhHw71qGywqNLzzzNzd7ZX1FnNKlbSX7plBg21rYg=PET</string>
	</dict>
	</plist>

	HTTP/1.1 200 OK
	date: Thu, 06 Apr 2017 21:51:51 GMT
	X-Apple-Request-UUID: 926be57c-d560-66d7-76d9-be3a48d8b9bc
	X-Apple-Jingle-Correlation-Key: SJV6K7GVMBTNO5WZXY5ERWFZXQ
	apple-seq: 0
	apple-tk: false
	Apple-Originating-System: UnknownOriginatingSystem
	X-Responding-Instance: setupservice:35600102:mr90p56ic-zteg05151101:8002:17B247:4001a34
	Cache-Control: no-cache, no-store, private
	Content-Type: application/xml; charset=UTF-8
	content-encoding: gzip
	Strict-Transport-Security: max-age=31536000; includeSubDomains
	Content-Length: 4229
	<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
	<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
	<plist version="1.0">
		<dict>
			<key>delegates</key>
			<dict>
				<key>com.apple.madrid</key>
				<dict>
					<key>status</key>
					<integer>0</integer>

					<key>service-data</key>
					<dict>
						<key>email-address</key>
						<string>joe.king.1@icloud.com</string>

						<key>auth-token</key>
						<string>V1MHKW000771dd6cd4e78c371608effdc4c6e8e0b578VKZZDad309faa121cb0190ad412cd3c156e3f563045850094332df38df575e973ce864114c95497eba11c7d492b5889594e9326eea0fcaab96caf6a700d007b6c448c1f5da2cd5a31b86658b8ccdc36b1595b0c57b7209d3a5d2a5f642579ab4cce249e3b8fe1fbc1cae988c875f19c1baf0ea35cf699dd13328c0343fe6b50ee99998814160efe81492ca7637231291964b5ea30d2b6b6b96feb07fd197db422705b2138ab4528ca126ced6c8f41a985bdb1a2d35e603277c49777310b08f4ff4145e924491c7f790fd7838c07b4641e3dc85d316ab7a631189de95fe28e22a213dfcf03c0b24ed67bd792c13f2ab7321da24dd31392651eb831668dca561ee8fb62ca7736f55a28f3a2664e21bb6f5fcd0c770892116fc366f2a8d7404a8cb54a68cd0f2d5caef41dfde2f555c81cb5a8f8cea0b49068dedc292d8ea9ab4be60e34a005b1012baa88230432fa13bbbfc4e09ba8db3d1848be9433f35b7b8524e12f5fae44ae8b5e3d03c6242c5fd2a3290abc762f7a526557a6b99e733a519d2d03f938b50f58cc4eeb8dbb08fa0360f3b5ab2578f05cf25b05309ae3393df205c9c2facd3827198793fdb7e180bed17042223f8749358edfa451f8d3c86b553299b11e4bcc73104c8ffee8df7e5c2f0da8495052f21a344ece2d0d462400a63795871611eee16c6d0122c6ff0ffdbb12ee0a5096ed571bc5be443909d4d470b5922b36441cbc1205a1aab1a69ff6cbb09a0454b590a28c02ba660ef10b9641862d0639d1d95086dfdf290b748451ba6a21da86dde09b2fd33569c9bdbd206dbebd3a53bfddf6585eb4e92a43a74e74feae32dae3aa0df398cc724b208e14ba080a0c8a336ad7a450f3a3ff2190c38c06ef2a8ea01026945991d2f6dfa3387ba0bd61f0685efecc12efbe98c6245454ee1721dec213b8f2a63518676d302055862888003e3bd7d842fec55f6dea7062b4d6924c323a44023b7bc5151682b2f16fe5da30512d92753430b3d1b361a6ff8be466850d074a03ee83d918e13f915cbeca57478abd4c1ace3b62f239e65ca7e27525f857b9ff26a5822def79c7115a785535ec392ee2136d6fe735145626e773b6d730631a0eccbc15ec104025d1b5d633624bb1986fc16233dcab49d9f22a170d2c5702f3198015d1302d415c124bccce611ec38ca902b48b7fe14ed460aba9a73372eef91238a9ea55256edc51d34f0ae031c2e1b24ae523d5ff2dc097611eee1974fe74823cb623fbe962d0394de5824b3d2bb5e0e4f96e2fc8e95f0dcf710aKMHZ</string>

						<key>invitation-context</key>
						<dict>
							<key>extra</key>
							<dict>
							</dict>

							<key>base-phone-number</key>
							<string>+10000000000</string>

							<key>region-id</key>
							<string>R:US</string>

						</dict>

						<key>self-handle</key>
						<dict>
							<key>uri</key>
							<string>urn:ds:10973066090</string>

						</dict>

						<key>handles</key>
						<array>
							<dict>
								<key>status</key>
								<integer>5051</integer>

								<key>uri</key>
								<string>mailto:joe.king.1@icloud.com</string>

							</dict>
						</array>

						<key>profile-id</key>
						<string>D:10973066090</string>

						<key>apple-id</key>
						<string>joe.king.1@icloud.com</string>

						<key>realm-user-id</key>
						<string>D:10973066090</string>

					</dict>

					<key>account-exists</key>
					<true/>

				</dict>

				<key>com.apple.facetime</key>
				<dict>
					<key>status</key>
					<integer>0</integer>

					<key>service-data</key>
					<dict>
						<key>email-address</key>
						<string>joe.king.1@icloud.com</string>

						<key>auth-token</key>
						<string>V1MHKW000771dd6cd4e78c371608effdc4c6e8e0b578VKZZDc274cb32a4555ed349eed1a6d5b4eab8f24c53466d793115a4e0c17a2ee384a06548d02e33f5a232a66dab03f185ca1261afa9686bce780fe3f817cabd9d61d985ed800705c32485baf1a7194fcd7a2b3849cf74d9352e7635944f470583e3c7885dc0484b7054014ed030a82945a359f1d3560418162fd5060f69be935a91a6762187c9cb53f1d35c1749a9b96d29fcd0b0160b9e86accb6874794234d1244d9aea7a231f5018338e3a9fc57a6d3ee08f679abe3c923aff47511b7e3460e4c501a8e97d19ae9db49b7601cb651e748593168b1f19066aa0dd8856fb0ce948ead525445453f859aa86a7650329731fd6882d6d4a481de898890293fd83f894e1c9898f31687c7cda3c5478b044a3dd122159c76b27aceaaee019a0204821446b8686dec4de8afda2013e383bff5903bc153f9eb7b05c3731bb21a689e18bc1f3fda3a5bfd59138917aab8dc3560aa936a09eeb9d44a79ff66d7dfffde0e2ed6581b092ee2cfba8f5e3863c32d3b67c8e2130295dbe4dedcca018298a77fe6a0d7a1310d018adfc33b2d163ab0c3ce5a822b88b02772a22cfc80c4be2d2490e19986c6310f3884340f0c6ea1062d3d1e74a10bca67df5ae9e9209118470bf233d468cef01a144f57ebaeeeb29c56e760e1c1a32ba253b583dd13ac70928fdeb9f3f66e299d33bdd625128cb6315e7527ee97b9ff82c3426813e2fb7dce6cb7dedb8c14d9688399f386f4ec640370481846a5c04178064653cb6707c20eb65eb2012200864845dded487ce523114135b97d50019e75d206fbd5cba0bdfb83062673d8ea06b3e21254aca1403e787c0383ee83e3854d915f10c298d9b2a30b062247e4715fcda4d02e5fca00a851a8a4e661e5079dc6be09fb0af2aafa4c879cc3d2a464283f023950b49d3fbbad15dfc446cb9ed579ac69f156125778127c54add8ac99633efe7469824f92d1c6395a8c0cca1a9c09121f802c703516e7a8cf09ae19583e26a1904059a02cecfda0a7ea70852b5d64ef8a3e95b6a393d98a00a3186127e0a034f050fd4b75f91311249f38a16b840b170fcd2d480a74ca2a814b7164012246ada84464baac7a06e21f52a92419184a7b7b5e594a41cbbb972f66fd706fa8114e0c599280841576e45a55a7002d7f2e6e34b0f3105d7a93e2f7b23efdc837f72eb096d80e1a03aefd7d4cf38da0f58c5ac828b414fe8ac043200a33a5b6af84575339bf639b2ff4137f1f60b63ecebab6e790514e12a2551b05772e083d73e3a4328809cb721d9c53f69d8KMHZ</string>

						<key>invitation-context</key>
						<dict>
							<key>extra</key>
							<dict>
							</dict>

							<key>base-phone-number</key>
							<string>+10000000000</string>

							<key>region-id</key>
							<string>R:US</string>

						</dict>

						<key>self-handle</key>
						<dict>
							<key>uri</key>
							<string>urn:ds:10973066090</string>

						</dict>

						<key>handles</key>
						<array>
							<dict>
								<key>status</key>
								<integer>5051</integer>

								<key>uri</key>
								<string>mailto:joe.king.1@icloud.com</string>

							</dict>
						</array>

						<key>profile-id</key>
						<string>D:10973066090</string>

						<key>apple-id</key>
						<string>joe.king.1@icloud.com</string>

						<key>realm-user-id</key>
						<string>D:10973066090</string>

					</dict>

					<key>account-exists</key>
					<true/>

				</dict>

				<key>com.apple.mobileme</key>
				<dict>
					<key>status</key>
					<integer>1</integer>

					<key>status-message</key>
					<string>invalid device while updating mme delegate account</string>

				</dict>

				<key>com.apple.gamecenter</key>
				<dict>
					<key>service-data</key>
					<dict>
						<key>alias</key>
						<string>psafrhpd39zm8</string>

						<key>lastName</key>
						<string>King</string>

						<key>auth-token</key>
						<string>2:28:AQAAAABY5rh3+1qdUuG1yUFRpR0q4ZMfE4jKVIU=:28:AQAAAABY5rh3CDVoML5QDF9ZgpkCBK/aFYcX340=</string>

						<key>player-id</key>
						<string>G:10973066090</string>

						<key>firstName</key>
						<string>Joe</string>

						<key>env</key>
						<string>PROD</string>

						<key>apple-id</key>
						<string>joe.king.1@icloud.com</string>

					</dict>

					<key>status</key>
					<integer>0</integer>

					<key>account-exists</key>
					<true/>

				</dict>

				<key>com.apple.itunes</key>
				<dict>
					<key>service-data</key>
					<dict>
					</dict>
					<key>status</key>
					<string>2003</string>
					<key>status-message</key>
					<string>serial-number is an empty string</string>
				</dict>

				<key>com.apple.private.ids</key>
				<dict>
					<key>status</key>
					<integer>0</integer>

					<key>service-data</key>
					<dict>
						<key>email-address</key>
						<string>joe.king.1@icloud.com</string>
						<key>auth-token</key>
						<string>V1MHKW000771dd6cd4e78c371608effdc4c6e8e0b578VKZZDc53276b1b8a8b9002fb12b8b0b2a0528bf972282e810604d0244bd06226250b5588f2e405e102d74d66412fb698a09e640d892daa8b106ccb547ea8737ad36d96e03cad60baf55e532146a4ce21a1b46191e9f6d8ad4657bb7b6e0054c0a00c7a76d0f886ec4fe47cc2611df0c3abc028dc20c8db8223e1bc95a9dfeb24b80e3a63876754c8ac32d142d88907ffb0ca0aa762cada372e45059c71b6a74802665e7c51647839f2e54ef3b5286102b381833f6778603d2e41a99d0033068eacfef9f981fc985f65cbbcabe25837cf1e7eea5b98156fe207925a1b43b7cb979d33bc026afb9306bc6a72d799ba8d69d6f37b199b687568fd6c9b1f9c618899e060b59d0cec42064315cc705af53dfe657799b53b6bb676806ddf9041faeec4804e5880f90554ce282037f1b6835abd4f2d5bd325e7718b89a8f2c1ddd5114ce17f35f044dc97a00ab15cada63f6fc09e2944c7d9dcc3141e39ea920232ad0657db010be839e8e9c7f156851e9420a1747c57748ecf48b8fa3d465f4ee98b757ae17fbcf8a32e73870607bf289753ea8fdc7f976b30ec5fafc968138adafca9a71264d44b5119aa7afa976491de94be45320c415c64774dd9e88a0ca32d53cd331223f2e7e0cded7f549943e71ac70016b3fac685db26fe33c5d60a6a6adf303bb840cde68957aa3bcaf3ff0eca8690bd1e767139e0e73b0b293a68342ef689215892945cd2207d46c9cfd67bbed40c0ccada84d574da6db49b6b1eca22f5ddaeab6b7b9ef02f3af83651c583aaf6abdbf4d4950669fe578f10c967eea93b472127c6c75a44ddf0cbb79f7b0a40c73aed2768a0af46411c7822a84d7272fb0517e364c4c7afc3515ee26fdcbe5a1a22ffb2bd0dff1af046a0860d782144c99bc7be9c2db987a91d7eef0d7e1c3cefafcb38012060f6065dd98d1a6257a54f7374705aa2fbf1e1cd7363e1c85bcfcaf2e98f4f67a5b3a68b67c105c5c1502a8aa9963be44386832811aafa5649ea23b053d1343c7c13607e25d16c3b732d87a206da702e4ca6cd5948d05f92724fbd02371f2da39d7c072318a2d6fd5eafe1933c4d2e78631a3f4f6e97b3f84ec34be418850011382fcc7bdb8e08054e72b66244f08dbb5d854b24fbc809aaa1da5fa61bb55980c2f75734822c0c8e44b8d60df775434ef7e42031d40ed5febaafe31a9c278014dfaa06073a78a2ce84c68006941ab6d07c069c043474963718d49baba08498d72ab0166883362ef64d45e70db7307238cd351c1fd5d1d7fa773d10a78631dKMHZ</string>
						<key>invitation-context</key>
						<dict>
							<key>extra</key>
							<dict>
							</dict>
							<key>base-phone-number</key>
							<string>+10000000000</string>
							<key>region-id</key>
							<string>R:US</string>
						</dict>
						<key>self-handle</key>
						<dict>
							<key>uri</key>
							<string>urn:ds:10973066090</string>
						</dict>
						<key>handles</key>
						<array>
							<dict>
								<key>status</key>
								<integer>5051</integer>

								<key>uri</key>
								<string>mailto:joe.king.1@icloud.com</string>
							</dict>
						</array>
						<key>profile-id</key>
						<string>D:10973066090</string>
						<key>apple-id</key>
						<string>joe.king.1@icloud.com</string>
						<key>realm-user-id</key>
						<string>D:10973066090</string>
					</dict>
					<key>account-exists</key>
					<true/>
				</dict>
			</dict>
			<key>status</key>
			<integer>0</integer>
		</dict>
	</plist>
