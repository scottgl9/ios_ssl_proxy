# Research on gsa.apple.com:

## For the initial post to https://gsa.apple.com/grandslam/GsService2 with a plist xml formatted body:

### This initial body seems to be what sets up many of the header fields used later, such as X-Apple-I-MD, X-Apple-I-MD-M, etc. Below is the initial packet:

	POST https://gsa.apple.com/grandslam/GsService2
	Content-Type: text/x-xml-plist^M
	Accept: */*^M
	Accept-Language: en-us^M
	User-Agent: akd/1.0 CFNetwork/808.2.16 Darwin/16.3.0^M
	X-MMe-Client-Info: <iPhone8,2> <iPhone OS;10.2;14C92> <com.apple.akd/1.0 (com.apple.akd/1.0)>^M
	Content-length: 2168^M
	Host: gsa.apple.com^M
	Accept-Encoding: gzip, deflate^M
	<?xml version="1.0" encoding="UTF-8"?>
	<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
	<plist version="1.0">
	<dict>
			<key>Header</key>
			<dict>
					<key>Version</key>
					<string>1.0.1</string>
			</dict>
			<key>Request</key>
			<dict>
					<key>app</key>
					<array>
							<string>com.apple.gs.appleid.auth</string>
					</array>
					<key>c</key>
					<data>
					NTBmNjljMmItZWJlMS00MDAyLTgwYmMtMWU2YWQzMjQ1MDRiQUh2Mk1RdnNi
					LzdJNUdBT0dJbXF6b0tUN0huVWJuMjZPek9RWlJDczFnM2RTNUJZSzEvM0Fz
					UWFROGRoaTVRcXRjd1N4OUhyRGlDdHk3T2NXRHVQOUw0anZlNEdlaU5ZQUE4
					d3FYUDJpZDdPVGlVeXYwVm9QME1DZWJFejlwaldXRnBI
					</data>
					<key>checksum</key>
					<data>
					dIfTy0pydCA/s1ijzF7256VGrismz98/N4gsPdf2uJ8=
					</data>
					<key>cpd</key>
					<dict>
							<key>AppleIDClientIdentifier</key>
							<string>36ADD28C-3BE0-4E36-96A3-B5CF27677963</string>
							<key>X-Apple-I-Client-Time</key>
							<string>2017-02-01T22:59:19Z</string>
							<key>X-Apple-I-MD</key>
							<string>AAAABQAAABAP8dw5sHseHxVwLdi116YZAAAAAw==</string>
							<key>X-Apple-I-MD-M</key>
							<string>7uFG2/ZgB6SmF5r93yaqedoq+rugYFfglwmtO8rZlzO2ICtyDYMjk28WsJ7Ao7BMiPcwfupM8nF8zW87</string>
							<key>X-Apple-I-MD-RINFO</key>
							<string>17106176</string>
							<key>X-Apple-I-SRL-NO</key>
							<string>F2LS47Z9HFM2</string>
							<key>X-Mme-Device-Id</key>
							<string>87cda23a7230769ef6aa1ded8a99a5d3e65b9d42</string>
							<key>capp</key>
							<string>accountsd</string>
							<key>dc</key>
							<string>#b9b7ba</string>
							<key>dec</key>
							<string>#272728</string>
							<key>loc</key>
							<string>en_US</string>
							<key>papp</key>
							<string>Preferences</string>
							<key>pbe</key>
							<false/>
							<key>prtn</key>
							<string>MN3E2</string>
							<key>svct</key>
							<string>iCloud</string>
					</dict>
					<key>o</key>
					<string>apptokens</string>
					<key>t</key>
					<string>AAAABLwIAAAAAFiSMJ4RDGdzLmlkbXMuYXV0aL0ATq91nbHk0WNNFpN1hvqHyF6Jbx/q+sIVamHTN50CGOX4gBAaljQMu7iP4O93xsavh+D0+OL8NX/7XN7j3iJFxIxkO+9KvRxBFhVjYQeK+OpRwI3BU14+ddrUpmPiIo4NEk1hLInsfTaVT3NxLiIYjNhTYcqhfNPsNKY684CUYnItNJiQ+rM9jRovG49nZiITauJnWB0ftvNWWXUgMLXv9yw9oCU=</string>
					<key>u</key>
					<string>000919-05-b45534a8-fa23-4dfa-9ff7-0fcfa37c3d34</string>
			</dict>
	</dict>
	</plist>

### In the above body, the plist key 'c' base64 decoded has the following value:
	50f69c2b-ebe1-4002-80bc-1e6ad324504bAHv2MQvsb/7I5GAOGImqzoKT7HnUbn26OzOQZRCs1g3dS5BYK1/3AsQaQ8dhi5QqtcwSx9HrDiCty7OcWDuP9L4jve4GeiNYAA8wqXP2id7OTiUyv0VoP0MCebEz9pjWWFpH

### the base64 decoded hex value of the field checksum in the above body is: 7487D3CB4A7274203FB358A3CC5EF6E7A546AE2B26CFDF3F37882C3DD7F6B89F (32 bytes long, SHA256, unsure what this is the checksum of) 

### For the following field X-Apple-HB-Token:

X-Apple-HB-Token: MDAwOTE5LTA1LWI0NTUzNGE4LWZhMjMtNGRmYS05ZmY3LTBmY2ZhMzdjM2QzNDpBQUFBQkx3SUFBQUFBRmliZWNzUkNtZHpMbWxrYlhNdWFHSzlBSWFoRlJvSlh5QVl0aTMxNTdiUGhEVGdCVDJaWUI4T0oyNmNvVVlpRHZkdkF2dTBTK2JyclE5dkFkekxMdVM0ZTFCMjB6TWF4bVVjMU9YREFaZ1M1R1hwQ3YyQmd4eEpTa2gxQlBDOGQ5UUlsMDhUNi9aVkl0dTY3Tk0vT0tqb3d4NG9JUjBmWWdGV0JBL1p4U2Q3TGhmYWg5VUE2c0hhL09lUzVaZFR4Y0d6Q2p6THhZRzJjYUwzRHgyYkVSQ2M1WmNUVmR0N1ZUZFF0anVGaU5wMTFVWnQ5aTVk

The string "MDAwOTE5LTA1LWI0NTUzNGE4LWZhMjMtNGRmYS05ZmY3LTBmY2ZhMzdjM2QzNDpBQUFBQkx3SUFBQUFBRmli" occurs as the beginning of the field gsAuthAgentToken when communicating with identity.apple.com:
	<?xml version="1.0"?><methodCall><methodName>com.apple.ist.idm.web.collaboration.PersonService.getMyInfo</methodName><params><param><value><struct><member><name>ClientAIDVRecordIdentifier</name><value><string></string></value></member><member><name>ClientTime</name><value><dateTime.iso8601>20170208T21:27:36Z</dateTime.iso8601></value></member><member><name>AppleIDAuthProtocolVersion</name><value><i4>101</i4></value></member><member><name>gsAuthAgentToken</name><value><string>MDAwOTE5LTA1LWI0NTUzNGE4LWZhMjMtNGRmYS05ZmY3LTBmY2ZhMzdjM2QzNDpBQUFBQkx3SUFBQUFBRmlialVnUkVXZHpMbUYxZEdoaFoyVnVkQzVoZFhSb3ZRQjB6OEpBdE1BRkFlbm1UWmRIaTJoMWtvSWN6Y0Jvd3k0NkhuQkR4U3cvd0hDcUdkc245OW5nYlkvNGUwU3BlMllBWUcwOWQ2N1kydExROG9odXF4YUI0blg3U1k0Mkp2bUtDVEEyRUlsMkl5ZXVpS2M4RitWUDFHanJrUmE4Nnc2WDZlTDVZMFltQjZGemp5a1VyTUlDNGIzYXpBbURqWmxIeVd1RXMxUkNlOHVNMnRTeEtOVHBOWC9OR01tdU9rc1ZUbm1jbHhZcjVkWHB6WDRIeVRlREZzSk1vdz09</string></value></member><member><name>SystemVersion</name><value><string>14C92</string></value></member><member><name>ProductName</name><value><string>iPhone OS</string></value></member><member><name>CertificateSerialNumber</name><value><string>231b449298f881ca</string></value></member><member><name>OSServicesVersion</name><value><string>775.2</string></value></member></struct></value></param></params></methodCall>

When X-Apple-HB-Token is base64 decoded, the value is:

	000919-05-b45534a8-fa23-4dfa-9ff7-0fcfa37c3d34:AAAABLwIAAAAAFibecsRCmdzLmlkbXMuaGK9AIahFRoJXyAYti3157bPhDTgBT2ZYB8OJ26coUYiDvdvAvu0S+brrQ9vAdzLLuS4e1B20zMaxmUc1OXDAZgS5GXpCv2BgxxJSkh1BPC8d9QIl08T6/ZVItu67NM/OKjowx4oIR0fYgFWBA/ZxSd7Lhfah9UA6sHa/OeS5ZdTxcGzCjzLxYG2caL3Dx2bERCc5ZcTVdt7VTdQtjuFiNp11UZt9i5d

The above is ASDID:UNKNOWN\_BASE64ENCODED\_BINARY
