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


## Analysis of changes in X-Mme-Nas-Qualify header field (always base64 encoded):

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

