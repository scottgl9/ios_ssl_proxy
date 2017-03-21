## When performing post to https://albert.apple.com/deviceservices/deviceActivation From the actual device, when performing the activation step, the request body will have a plist containing ActivationInfoXML, FairPlayCertChain, FairPlaySignature, and these fields which I haven't seen before:

        <key>RKCertification</key>
        <data>
        MIICDTCCAbICAQEwGKIWBBQ4OTYwLTViNjhiMTZmNmQ4LWQtMDCB2QIBATAKBggqhkjO
        PQQDAgNHADBEAiBmgG3BA0qgY9VeGnlLrDooCgcqBwvDVy6V7x2BzXfAagIgSVcq/SPK
        tAAgFsDycifOvO7l4M8gwB57SSj9UaHQNm4wWzAVBgcqhkjOPQIBoAoGCCqGSM49AwEH
        A0IABGgWJjc6GUbKWYLu+ARstvtCqJPzduZZWOkc8V0s2ulXJUe23M7OWcajoRorTpdx
        eej61EjmdT0QQk7rqLcH0UugCgQIIHNrc0gAAACiFgQUmQtDhlCeVVZeDLPdhkUjwoLW
        zCQwgbYCAQEwCgYIKoZIzj0EAwIDSAAwRQIgCn7emlYvh2b/IIzUN4OV3N4eoZGQqLuA
        Y0bpY4OzMdgCIQCEtwbLHZtb5TKz9jQAeR4chJKky/KHfOJ7xzx6LFQb2DBbMBUGByqG
        SM49AgGgCgYIKoZIzj0DAQcDQgAEgTYJ8o10XWfbcWKEfkJqSo8UXVecA71Te8W1z/oO
        bGhZxn+isIZdKWcZdz5RN2Skuuvf4RiJ+0OEO5nhivbFKDAKBggqhkjOPQQDAgNJADBG
        AiEA5XESVTorRaRDiuEEXJXJOdprPVUgqooLOO7bRwTpNUUCIQD0X91qmU45c4GQlPhR
        Y8/HmwxN7sZwKP//gz+k8S47sQ==
        </data>
        <key>RKSignature</key>
        <data>
        MEUCIDao9luc7C1qwE7dKKrWnDrmCoZm/RArQ1nfGz5co3kOAiEAzI50iDtIedoJV7nq
        pUueKTHKepb81JyUBltvv+ijgY4=
        </data>
        <key>serverKP</key>
        <data>
        A2B7l6rqE/aSQIAroCW7aHsO/N3+7hVXSspEyYp/zOUMnNd2UJsCVragRHY21T7xpij5
        5CeVB3lOYEdQaGHdQfXdu9js
        </data>
        <key>signActRequest</key>
        <data>
        LDVntEqDZU1NBd/mzQzcnQ==
        </data>

## Also saw this request packet which seems to occur every time before posting to deviceActivation:

	POST https://albert.apple.com/deviceservices/drmHandshake
	Content-Type: application/xml
	X-iOS-Activation-Medium: WiFi
	Accept: application/xml
	Accept-Language: en-us
	User-Agent: iOS Device Activator (MobileActivation-182.30.16 built on Dec 15 2016 at 22:54:03)
	Content-length: 526
	Host: albert.apple.com
	Accept-Encoding: gzip, deflate
	<?xml version="1.0" encoding="UTF-8"?>
	<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
	<plist version="1.0">
	<dict>
		<key>FDRBlob</key>
		<data>
		uNAFArLlnmDdTqW1pgGHIlAxq5EdQrCI/w2kvzRzPjAHQLSX3b+DwlHXSpB3P5C0LHCl
		R3de2u8J7VKQF7iOxzecXmZa5HNFDjQ4Vmn4f3h1l9rg4Y6qHZQBfh4JvpgW
		</data>
		<key>HandshakeRequestMessage</key>
		<data>
		AmbIBUIa2Zw8jMmtkryQ1BrYbC7y
		</data>
		<key>UniqueDeviceID</key>
		<string>a64badc34879619f66b56d5c90170ef1ae73b1da</string>
	</dict>
	</plist>
	
	HTTP/1.1 200 OK
	Server: Apache-Coyote/1.1
	Cache-Control: private, no-cache, no-store, must-revalidate, max-age=0
	Content-Type: application/xml
	Content-Length: 866
	Date: Fri, 10 Feb 2017 17:50:07 GMT
	<plist version="1.0"><dict><key>HandshakeResponseMessage</key><data>AqVGksjBfLV1XbdqNIu8k+CmYgtut/9qsfV4/H1e5Y+DKWYUAMdzO/92Sxk8lTMT3tKfVcDCoK0Awjb2qNvBBqgBoDZ/cNfRCocUwMRXe01mBVj1yXkE+vo9dXYhzJ1UykxAoSrgccH2VGxaG41g8CWoymt5sz0hpWpgLj+07V+5ku+dTKEZ1caRzfXD44H0EEY5GEVC9Mt654/8WjE6jAnzsNnlAGBszD4EbWMOkf/y3HsN9asDFBRkJIJRB5dE0J/k86cEWor7QrUg2xOCt3brQ3IQ79ByI9VaRxYq8HF8U3gBrewYI9jtBj7yfi9LM86ZtwgfNFcksh8FZT+iurmkJE3cWSRZKTuXUy3kFl5ui38sATMHuhk1yzv7mMnDa7pCNXsjn4P3y3v2Y0KiI7Kr0i4SxbVW0Ecsk9U04Tb7DulAGmeTRKE1UMornfOTL23jqUf2PqXbnOsV7UBL8ser3TEazzo/0kWJ7e1c+/pgemp4EbphT+C7/yn4wbG1M0swCjgnpqRaeeCu3diPNoKYDoRiIFoOjcn3X7Ca4u1ry7lDlt1ZChb2WFTLOjhkd76NZePZAaeH/DM+Gzd1aJEkv2vdzRhT8bkScOo+LdMYQaZsDGwVZosnFaDVew0vc0LnAAoAAYI=</data><key>serverKP</key><data>A2B7l6rqE/aSQIAroCW7aHsO/N3+7hVXSspEyYp/zOUMnNd2UJsCVragRHY21T7xpij55CeVB3lOYEdQaGHdQfXdu9js</data></dict></plist>


## This is something I've never seen before after deactivating the iphone 5c, it seems that this is possibly the initial full FDRBlob:

	https://albert.apple.com/deviceservices/deviceActivation
	Content-Type: application/xml
	Accept: application/xml
	Accept-Language: en-us
	X-iOS-Activation-Medium: WiFi
	User-Agent: iOS Device Activator (MobileActivation-96.40.36 built on Mar 24 2016 at 08:29:25)
	Content-length: 5230
	Host: albert.apple.com
	Accept-Encoding: gzip, deflate
	<?xml version="1.0" encoding="UTF-8"?>
	<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
	<plist version="1.0">
	<dict>
		<key>FDRBlob</key>
		<data>
		MIINvTCCDWMCAQEwggq2oIIKsjCCCq4wCwYJKoZIhvcNAQEFMYICuoEIKe0dfCwAAACC
		BFCJAACDBAoAAACEBAEAAACFBAEAAACGE2lCb290LTI4MTcuNDAuMTA2fjKHFFFeuQLu
		OwSxr9FyTQmVl/8obs3jiBTQ6U71TbZzQD6mWQrVZYqUfDiLW4kUaKjhdhpnMHzQFN07
		2IgQlPl/iwyKFJ0BcPUZrzkmTddYtxuHjjNuSlZ3jRRC3urEg+NRmVJ+ibPOto59Ap4+
		oY4U80hV8SuINJZYl7n0MlMY+me1wiiPFHk9PebF/b0MZo5/Es2f0AwpXluEkBQCTlXe
		4LKZN7jz9X7L3sle2Z5yGJIUzaSFwfG5GXMncAbyJvZW/aBZVD+UE2lCb290LTI4MTcu
		NDAuMTA2fjKWE2lCb290LTI4MTcuNDAuMTA2fjKXFNDpTvVNtnNAPqZZCtVlipR8OItb
		mBRoqOF2GmcwfNAU3TvYiBCU+X+LDJkUnQFw9RmvOSZN11i3G4eOM25KVneaFKI0/SbW
		7o1+1ev8uuYodmBf5CU4nBThO5s5sLTG5NO5HCQ7jQZUNmO2pJ8wBAEAAACfMQQBAAAA
		nzIEAQAAAJ8zBAEAAACfNgQBAAAAnzcEAQAAAJ84BAEAAACfOQQBAAAAnzsEAQAAAJ88
		BAEAAACfPQQBAAAAnz4EAQAAAJ9LFNhcGJvC8XLxhcxpaUlglwuzqBXIn04UeKCkhzmO
		YqMnjYIcg6UVf369tLufTxQ6UwqhSK5Zmu9kzemXhkbhnJzIHZ9QFEHjogp52WByVqPp
		Y+OT40Zd7ABWn1QEAQAAAJ9VBAEAAACfVgQBAAAAn4FkFIyaApBT5n8Br+/WSjYFgIaC
		dwNqn4FlFGixdpbjyZ2v6rW3T+2yr26XDWa5n4FmFNsUejRHs0S63ckHDGL7oWgNOROq
		n4FnBAEAAACfgWgEAQAAAJ+BaQQBAAAABIGACohlj9ooVFtibOMkiqbTerh7RtvifZwk
		Wejn3gjarLAM8x7RJBUDCZT67RwIdaSaVu3lvNUnCddbcAmfkLAGMkXcLI+ihU2QOK2b
		4DdVps8pTwGTw2AUFEpRN8NFu8gGlkxV0ipOuxtaQdH3Bj1SwXU+4GzDXMVMpaJGyiVy
		1z+hggdcMIID+DCCAuCgAwIBAgIBEDANBgkqhkiG9w0BAQUFADBiMQswCQYDVQQGEwJV
		UzETMBEGA1UEChMKQXBwbGUgSW5jLjEmMCQGA1UECxMdQXBwbGUgQ2VydGlmaWNhdGlv
		biBBdXRob3JpdHkxFjAUBgNVBAMTDUFwcGxlIFJvb3QgQ0EwHhcNMDcwMTA1MTkyMTU5
		WhcNMjIwMTA1MTkyMTU5WjB+MQswCQYDVQQGEwJVUzETMBEGA1UEChMKQXBwbGUgSW5j
		LjEmMCQGA1UECxMdQXBwbGUgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxMjAwBgNVBAMT
		KUFwcGxlIFNlY3VyZSBCb290IENlcnRpZmljYXRpb24gQXV0aG9yaXR5MIIBIjANBgkq
		hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA/vLd2mU5sHLjA4SB9FbJ0aFKu8gEAfNGDZXh
		N5UKaUfGxIx5PkdVBrIGFOt+pPUj/kI1mO80Bc6a062U0KIPwtK0BEhMI1pbxwudYtPz
		42sQ/pcIV8YSdncZssbDLJjttymH5NwYtuXzuhP7sra3Z9nL32+lkz3tepNntP00FuQA
		qwu3Th9a1gNoPnK2FDA6DGSXoEYieRt3LFsukOAR3Baj4cj3hLJP3Es6CtUSftwRP/oR
		c2UaSXCgfnWCtDwrL1XfMIixdU1F3AcoLUo6hf2flT4iupxG97doe7OU1UI+BbM4+Gd5
		SIxsH4u+7u1UBdWjC1h9eA8kqaHcCnTq9wIDAQABo4GcMIGZMA4GA1UdDwEB/wQEAwIB
		hjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRJPTZTydcV4YZhTqyrqxhWY13DxjAf
		BgNVHSMEGDAWgBQr0GlHlHYJ/vRrjS5ApvdHTX8IXjA2BgNVHR8ELzAtMCugKaAnhiVo
		dHRwOi8vd3d3LmFwcGxlLmNvbS9hcHBsZWNhL3Jvb3QuY3JsMA0GCSqGSIb3DQEBBQUA
		A4IBAQA0xQzFDlkRL6bCnzJ452QyadutwiXKt0eDt5I8cVOgsq0wlYBQvW1fTNzOeA1M
		SRBQOBA1v0WBrGZYLCEj+JZegOnTxkz9ha45YfYoqkTtFZs/R8BXrGccjM3Uk41P22pU
		p3tCWw+Zxtc4q1KnoYMdhTB06g0d2miEj+KEfsu5QW7Vn6hCtf8ztnF/6qO53UkDYIV2
		ED6OqOE24xLdhWztZlOwW0ibL3/2yhzwXZgtdK3wSEfF4ZpnsiIPsA4CoOG6amK5tLVx
		9CXhs+Wg7cgaQLX4MRUFpFw4I0yQnUcDgIDUMpBFjw+vm/wC7u3L5jH2nxXmfStXQw7i
		D6GgrYnaMIIDXDCCAkSgAwIBAgICAS8wDQYJKoZIhvcNAQEFBQAwfjELMAkGA1UEBhMC
		VVMxEzARBgNVBAoTCkFwcGxlIEluYy4xJjAkBgNVBAsTHUFwcGxlIENlcnRpZmljYXRp
		b24gQXV0aG9yaXR5MTIwMAYDVQQDEylBcHBsZSBTZWN1cmUgQm9vdCBDZXJ0aWZpY2F0
		aW9uIEF1dGhvcml0eTAeFw0xMTA1MjAyMzIzNDlaFw0yMTA1MjAyMzIzNDlaMGIxCzAJ
		BgNVBAYTAlVTMRMwEQYDVQQKEwpBcHBsZSBJbmMuMQwwCgYDVQQLEwNFVFMxMDAuBgNV
		BAMTJ0g1UC1EYXJ3aW4tUHJvZC1DRVBPMS1UaWNrZXQtRGF0YUNlbnRlcjCBnzANBgkq
		hkiG9w0BAQEFAAOBjQAwgYkCgYEAlOdC21DvP0jHMxQRyVSD0ALBvtwIrpLMmMXeHlfD
		oVIaZTRgXibp4HCbac/gEkguBl5vpzLoknHz0yp5bMiKEDKY13Vw1anF9Sx7m+SZM0Jx
		cZ9onkrYmbHpNRne5+BgnlXySKRk8n4RLpsRqgKgzyY7VOIFaLSsGcAKLIeBiccCAwEA
		AaOBgzCBgDALBgNVHQ8EBAMCB4AwHQYDVR0OBBYEFDGZSSgS8zd86BOi5PqODHprWXJe
		MB8GA1UdIwQYMBaAFEk9NlPJ1xXhhmFOrKurGFZjXcPGMDEGCiqGSIb3Y2QGAQsBAf8E
		IDAeoRwxGoIEUIkAAIQEAQAAAIUEAQAAAJ+BawQBAAAAMA0GCSqGSIb3DQEBBQUAA4IB
		AQDnE+ereWLHcht71rOw7m1HSMmYhjEwlCU0WusJreIIB8sjI8MHu/uaeDiircyjA1Nt
		CA2Ak/ylYTuh0rD3i8G6bwlLXOp7IJ7MAMgOrsj/q/0LrB3DhL2u7cgTvBR/X4dJJ263
		s3XH3WsW4wW9i8iYOnkYQBUPIZoNI04fjoov93bE0mT9lHxnkoJZP9a+4hqwEYCdX7kO
		W1JsD1F3AQ4FkMMPwsXAov5nybkvdUVGRef8NyXM1gXo9begX6uXbtEtxHg51SX35bH2
		q+4DlAcIQa8zcPhiunHpSrINQhSzck4nDj6XRlHXny9c+b1n79TuHrEs0sndq7Nd72Rs
		I+fdMIHbAgEBMAoGCCqGSM49BAMCA0kAMEYCIQCBdmFWMJNPnI7hDKvmUnKC5wMoRJod
		0ugjRXdYA2SmBwIhALX4/Qjt2fJKVlvGvdo9MShVgCsS5V3wQOFTa+5VHSxRMFswFQYH
		KoZIzj0CAaAKBggqhkjOPQMBBwNCAARrS3a3U4hwvs9HWPZIMB1ROxkT4F5J26nmfbSt
		c9u6smnW/tNdQ7EvuHGO1fogPPmLTCCqizxxAGSZG0Xa1pmKoAoECGFjc3NIAAAAohYE
		FFjrvHlLoxjbl57+zNRNU6oHAgh+MIHgAgEBMAoGCCqGSM49BAMCA0kAMEYCIQDqJPf7
		gIp3R477wGVJJTytIIA8fnI17H8A1ry0A5Tm6gIhALN0S5yAsDc1TUQ5U56zfLaYdiYk
		Ur/3tXBY4rK+sUisMFswFQYHKoZIzj0CAaAKBggqhkjOPQMBBwNCAASN9b1Qji9VUJXx
		peOj2EBxpJoB8vvY+t8zVW7e30gPyNcp78ZLlvmds+uBP0E28bnGchXqrq+vaHzxkJhc
		9CRZoAoECGFjc3MWAAAAoxsEGTAwMDA4OTUwLTAwMDAwMDJDN0MxREVEMjmggeIwgd8C
		AQEwCgYIKoZIzj0EAwIDSAAwRQIgZ8rGA8BCkF3t/pujRW2I/ApHmhJz0J3sNUvKDQNN
		M4ECIQC746Z0k2a3tdqxZUVlU9qx7/W29a8l8WMCENgzrMllzzBbMBUGByqGSM49AgGg
		CgYIKoZIzj0DAQcDQgAEjfW9UI4vVVCV8aXjo9hAcaSaAfL72PrfM1Vu3t9ID8jXKe/G
		S5b5nbPrgT9BNvG5xnIV6q6vr2h88ZCYXPQkWaAKBAhhY3NzFgAAAKMbBBkwMDAwODk1
		MC0wMDAwMDAyQzdDMURFRDI5MAoGCCqGSM49BAMCA0gAMEUCIQC+ktDg5vbQ69RimbMn
		DbCIMRBXXtEjbAXcR3OH+jZtdAIgFsxfdNB+/GXgK1Vn7Anvpz2HgSWTWZ47XeL1lcc3
		ZFw=
		</data>
		<key>HandshakeRequestMessage</key>
		<data>
		AljNXePePP0z1h50Gsi4KkZgmBdU
		</data>
		<key>UniqueDeviceID</key>
		<string>c1ffc3c03997b19d9dcf68fb81f117226539ef6b</string>
	</dict>
	</plist>

	HTTP/1.1 200 OK
	Server: Apache-Coyote/1.1
	Cache-Control: private, no-cache, no-store, must-revalidate, max-age=0
	Content-Type: application/x-buddyml
	Content-Length: 243
	Date: Tue, 21 Mar 2017 04:51:16 GMT
	<xmlui><page><navigationBar title="Verification Failed" hidesBackButton="false"/><tableView><section footer="Please retry activation."/><section><buttonRow align="center" label="Try Again" name="tryAgain"/></section></tableView></page></xmlui>

