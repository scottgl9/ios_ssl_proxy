# Research on init.ess.apple.com:

## The typical http request/response to init.ess.apple.com looks like the following:

	GET http://init.ess.apple.com/WebObjects/VCInit.woa/wa/getBag?ix=4
	Accept-Language: en-us
	Accept: */*
	User-Agent: server-bag [iPhone OS,9.3.1,13E238,iPhone5,3]
	Host: init.ess.apple.com
	Accept-Encoding: gzip, deflate

	HTTP/1.1 200 OK
	X-Apple-Request-UUID: d689c78b-649e-4f91-4834-e1e0a2b7199f
	X-Apple-Jingle-Correlation-Key: 22E4PC3ETZHZCSBU4HQKFNYZT4
	apple-seq: 0
	apple-tk: false
	Apple-Originating-System: UnknownOriginatingSystem
	X-Responding-Instance: Init:300101:mr11p00vn-ztbu04134501:9001:17E119:e8c47a7
	X-Apple-Splunk-Hint: earliest=1490286364 latest=1490286484 d689c78b-649e-4f91-4834-e1e0a2b7199f
	Cache-Control: max-age=3492
	Content-Type: text/xml
	Content-Encoding: gzip
	Content-Length: 6503
	Date: Thu, 23 Mar 2017 16:57:07 GMT
	Vary: Accept-Encoding
	<?xml version="1.0" encoding="UTF-8" standalone="no"?>
	<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
	<plist version="1.0">
	<dict>
	  <key>signature</key><data>C8xNhJC/843wtynEiUl5V4SLxqBNyTsJ+52ebazEtNnjTIayQEKevUfGyUKX8kdI/aOwAaDzldp0p9pflS/2gWWVZU1H+rQNEXgEHblTpSH1WoYgMkjahaIb/tDBaBtxZoNEU80m46rmxrCnugf2lRrWmDeP+jbCCsaNR0lC6jkI4NRE0j/MThvybYza8Q2G0FWHrGIMXkgg2NO2sFHqddD9qEQkUntPlFWo7buSpskQsXyJ4mAoqKAaRXxM9g62HBscwnUPSC0DzYUDj0ORdsegZS3+GHcXEJoSfPM5JftqbBL5aHUKgFctS2C/sQXV9bXLvptoAqs7+tRMjMrdcQ==</data>
	  <key>certs</key>
	  <array>
		<data>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</data>
		<data>MIIFODCCBCCgAwIBAgIQUT+5dDhwtzRAQY0wkwaZ/zANBgkqhkiG9w0BAQsFADCByjELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDlZlcmlTaWduLCBJbmMuMR8wHQYDVQQLExZWZXJpU2lnbiBUcnVzdCBOZXR3b3JrMTowOAYDVQQLEzEoYykgMjAwNiBWZXJpU2lnbiwgSW5jLiAtIEZvciBhdXRob3JpemVkIHVzZSBvbmx5MUUwQwYDVQQDEzxWZXJpU2lnbiBDbGFzcyAzIFB1YmxpYyBQcmltYXJ5IENlcnRpZmljYXRpb24gQXV0aG9yaXR5IC0gRzUwHhcNMTMxMDMxMDAwMDAwWhcNMjMxMDMwMjM1OTU5WjB+MQswCQYDVQQGEwJVUzEdMBsGA1UEChMUU3ltYW50ZWMgQ29ycG9yYXRpb24xHzAdBgNVBAsTFlN5bWFudGVjIFRydXN0IE5ldHdvcmsxLzAtBgNVBAMTJlN5bWFudGVjIENsYXNzIDMgU2VjdXJlIFNlcnZlciBDQSAtIEc0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAstgFyhx0LbUXVjnFSlIJluhL2AzxaJ+aQihiw6UwU35VEYJbA3oNL+F5BMm0lncZgQGUWfm893qZJ4Itt4PdWid/sgN6nFMl6UgfRk/InSn4vnlW9vf92Tpo2otLgjNBEsPIPMzWlnqEIRoiBAMnF4scaGGTDw5RgDMdtLXO637QYqzus3sBdO9pNevK1T2p7peYyo2qRA4lmUoVlqTObQJUHypqJuIGOmNIrLRM0XWTUP8TL9ba4cYY9Z/JJV3zADreJk20KQnNDz0jbxZKgRb78oMQw7jW2FUyPfG9D72MUpVKFpd6UiFjdS8W+cRmvvW1Cdj/JwDNRHxvSz+w9wIDAQABo4IBYzCCAV8wEgYDVR0TAQH/BAgwBgEB/wIBADAwBgNVHR8EKTAnMCWgI6Ahhh9odHRwOi8vczEuc3ltY2IuY29tL3BjYTMtZzUuY3JsMA4GA1UdDwEB/wQEAwIBBjAvBggrBgEFBQcBAQQjMCEwHwYIKwYBBQUHMAGGE2h0dHA6Ly9zMi5zeW1jYi5jb20wawYDVR0gBGQwYjBgBgpghkgBhvhFAQc2MFIwJgYIKwYBBQUHAgEWGmh0dHA6Ly93d3cuc3ltYXV0aC5jb20vY3BzMCgGCCsGAQUFBwICMBwaGmh0dHA6Ly93d3cuc3ltYXV0aC5jb20vcnBhMCkGA1UdEQQiMCCkHjAcMRowGAYDVQQDExFTeW1hbnRlY1BLSS0xLTUzNDAdBgNVHQ4EFgQUX2DPYZBV34RDFIpgKrL1evRDGO8wHwYDVR0jBBgwFoAUf9Nlp8Ld7LvwMAnzQzn6Aq8zMTMwDQYJKoZIhvcNAQELBQADggEBAF6UVkndji1l9cE2UbYD49qecxnyH1mrWH5sJgUs+oHXXCMXIiw3k/eG7IXmsKP9H+IyqEVv4dn7ua/ScKAyQmW/hP4WKo8/xabWo5N9Q+l0IZE1KPRj6S7t9/Vcf0uatSDpCr3gRRAMFJSaXaXjS5HoJJtGQGX0InLNmfiIEfXzf+YzguaoxX7+0AjiJVgIcWjmzaLmFN5OUiQt/eV5E1PnXi8tTRttQBVSK/eHiXgSgW7ZTaoteNTCLD0IX4eRnh8OsN4wUmSGiaqdZpwOdgyA8nTYKvi4Os7X1g8RvmurFPW9QaAiY4nxug9vKWNmLT+sjHLF+8fk1A/yO0+MKcc=</data>
	  </array>
	  <key>bag</key><data>PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiIHN0YW5kYWxvbmU9Im5vIj8+CjwhRE9DVFlQRSBwbGlzdCBQVUJMSUMgIi0vL0FwcGxlIENvbXB1dGVyLy9EVEQgUExJU1QgMS4wLy9FTiIgImh0dHA6Ly93d3cuYXBwbGUuY29tL0RURHMvUHJvcGVydHlMaXN0LTEuMC5kdGQiPgo8cGxpc3QgdmVyc2lvbj0iMS4wIj4KPGRpY3Q+CiAgPGtleT52Yy1idWlsZC12ZXJzaW9uPC9rZXk+PHN0cmluZz4xN0UxMTk8L3N0cmluZz4KICA8a2V5PnZjLWJ1aWxkLXJldmlzaW9uPC9rZXk+PHN0cmluZz51bmRlZmluZWQ8L3N0cmluZz4KICA8a2V5PnZjLWRpc2FzdGVyLW1vZGU8L2tleT48ZmFsc2UvPgogIDxrZXk+dmMtZGlzYXN0ZXItc2VuZGVyLW1heC1yZXRyaWVzPC9rZXk+PGludGVnZXI+MTwvaW50ZWdlcj4KICA8a2V5PnZjLWRpc2FzdGVyLXJlY2VpdmVyLXJldHJ5LWludGVydmFsPC9rZXk+PGludGVnZXI+NjAwPC9pbnRlZ2VyPgogIDxrZXk+dmMtZGlzYXN0ZXItc2VuZGVyLXNlbGYtdG9rZW5zPC9rZXk+PGZhbHNlLz4KICA8a2V5PnZjLWVuYWJsZS1oZXZjPC9rZXk+PGZhbHNlLz4KICA8a2V5PnZjLWVuYWJsZS1oZXZjLXYyPC9rZXk+PHRydWUvPgogIDxrZXk+dmMtZW5hYmxlLWV2cy1hdWRpby1jb2RlYzwva2V5Pjx0cnVlLz4KICA8a2V5PnZjLWVuYWJsZS1yZWQtYXVkaW88L2tleT48dHJ1ZS8+CiAgPGtleT5hcG5zLWlkcy1xdWVyeS1wZXJjZW50YWdlPC9rZXk+PGludGVnZXI+MTAwPC9pbnRlZ2VyPgogIDxrZXk+YXBucy1pZHMtcXVlcnktbWluLXZlcnNpb248L2tleT48aW50ZWdlcj4yPC9pbnRlZ2VyPgogIDxrZXk+aWQtdmFsaWRhdGlvbi1jZXJ0PC9rZXk+PHN0cmluZz5odHRwOi8vc3RhdGljLmVzcy5hcHBsZS5jb20vaWRlbnRpdHkvdmFsaWRhdGlvbi9jZXJ0LTEuMC5wbGlzdDwvc3RyaW5nPgogIDxrZXk+aWQtcmVjb3Zlci1zaWduYXR1cmU8L2tleT48c3RyaW5nPmh0dHBzOi8vaWRlbnRpdHkuZXNzLmFwcGxlLmNvbS9XZWJPYmplY3RzL1RESWRlbnRpdHlTZXJ2aWNlLndvYS93YS9yZWNvdmVyU2lnbmF0dXJlPC9zdHJpbmc+CiAgPGtleT5pZC1pbml0aWFsaXplLXZhbGlkYXRpb248L2tleT48c3RyaW5nPmh0dHBzOi8vaWRlbnRpdHkuZXNzLmFwcGxlLmNvbS9XZWJPYmplY3RzL1RESWRlbnRpdHlTZXJ2aWNlLndvYS93YS9pbml0aWFsaXplVmFsaWRhdGlvbjwvc3RyaW5nPgogIDxrZXk+aWQtcHJvdmlzaW9uLXBob25lLW51bWJlcjwva2V5PjxzdHJpbmc+aHR0cHM6Ly9pZGVudGl0eS5lc3MuYXBwbGUuY29tL1dlYk9iamVjdHMvVERJZGVudGl0eVNlcnZpY2Uud29hL3dhL2F1dGhlbnRpY2F0ZVBob25lTnVtYmVyPC9zdHJpbmc+CiAgPGtleT5pZC1wcmVmbGlnaHQ8L2tleT48c3RyaW5nPmh0dHBzOi8vaWRlbnRpdHkuZXNzLmFwcGxlLmNvbS9XZWJPYmplY3RzL1RESWRlbnRpdHlTZXJ2aWNlLndvYS93YS9wcmVmbGlnaHQ8L3N0cmluZz4KICA8a2V5PmlkLXByb3Zpc2lvbi1kcy1pZDwva2V5PjxzdHJpbmc+aHR0cHM6Ly9wcm9maWxlLmVzcy5hcHBsZS5jb20vV2ViT2JqZWN0cy9WQ1Byb2ZpbGVTZXJ2aWNlLndvYS93YS9hdXRoZW50aWNhdGVEUzwvc3RyaW5nPgogIDxrZXk+aWQtcmVnaXN0ZXI8L2tleT48c3RyaW5nPmh0dHBzOi8vaWRlbnRpdHkuZXNzLmFwcGxlLmNvbS9XZWJPYmplY3RzL1RESWRlbnRpdHlTZXJ2aWNlLndvYS93YS9yZWdpc3Rlcjwvc3RyaW5nPgogIDxrZXk+aWQtZGVyZWdpc3Rlcjwva2V5PjxzdHJpbmc+aHR0cHM6Ly9pZGVudGl0eS5lc3MuYXBwbGUuY29tL1dlYk9iamVjdHMvVERJZGVudGl0eVNlcnZpY2Uud29hL3dhL2RlcmVnaXN0ZXI8L3N0cmluZz4KICA8a2V5PmlkLWNhbm9uaWNhbGl6ZTwva2V5PjxzdHJpbmc+aHR0cHM6Ly9xdWVyeS5lc3MuYXBwbGUuY29tL1dlYk9iamVjdHMvVERJZGVudGl0eVNlcnZpY2Uud29hL3dhL2Nhbm9uaWNhbGl6ZTwvc3RyaW5nPgogIDxrZXk+aWQtcXVlcnk8L2tleT48c3RyaW5nPmh0dHBzOi8vcXVlcnkuZXNzLmFwcGxlLmNvbS9XZWJPYmplY3RzL1F1ZXJ5U2VydmljZS53b2Evd2EvcXVlcnk8L3N0cmluZz4KICA8a2V5PmlkLWNoZWNrLXVua25vd248L2tleT48c3RyaW5nPmh0dHBzOi8vcXVlcnkuZXNzLmFwcGxlLmNvbS9XZWJPYmplY3RzL1F1ZXJ5U2VydmljZS53b2Evd2EvY2hlY2tVbmtub3duPC9zdHJpbmc+CiAgPGtleT5pZC1yZXBvcnQtc3BhbTwva2V5PjxzdHJpbmc+aHR0cHM6Ly9pZGVudGl0eS5lc3MuYXBwbGUuY29tL1dlYk9iamVjdHMvVERJZGVudGl0eVNlcnZpY2Uud29hL3dhL3JlcG9ydFNwYW08L3N0cmluZz4KICA8a2V5PmlkLXJlcG9ydC11bmtub3duPC9rZXk+PHN0cmluZz5odHRwczovL2lkZW50aXR5LmVzcy5hcHBsZS5jb20vV2ViT2JqZWN0cy9URElkZW50aXR5U2VydmljZS53b2Evd2EvcmVwb3J0VW5rbm93bjwvc3RyaW5nPgogIDxrZXk+aWQtdmFsaWRhdGUtY3JlZGVudGlhbHM8L2tleT48c3RyaW5nPmh0dHBzOi8vaWRlbnRpdHkuZXNzLmFwcGxlLmNvbS9XZWJPYmplY3RzL1RESWRlbnRpdHlTZXJ2aWNlLndvYS93YS92YWxpZGF0ZUNyZWRlbnRpYWxzPC9zdHJpbmc+CiAgPGtleT5pZC1xdWVyeS1ieS1zZXJ2aWNlPC9rZXk+PHN0cmluZz5odHRwczovL3F1ZXJ5LmVzcy5hcHBsZS5jb20vV2ViT2JqZWN0cy9RdWVyeVNlcnZpY2Uud29hL3dhL3F1ZXJ5QnlTZXJ2aWNlPC9zdHJpbmc+CiAgPGtleT5pZC1nZXQtcGFpcmluZy10b2tlbjwva2V5PjxzdHJpbmc+aHR0cHM6Ly9xdWVyeS5lc3MuYXBwbGUuY29tL1dlYk9iamVjdHMvUXVlcnlTZXJ2aWNlLndvYS93YS9nZXRQYWlyaW5nVG9rZW48L3N0cmluZz4KICA8a2V5PmlkLWdldC1zZXJ2aWNlLXVzZXItaWQ8L2tleT48c3RyaW5nPmh0dHBzOi8vcXVlcnkuZXNzLmFwcGxlLmNvbS9XZWJPYmplY3RzL1F1ZXJ5U2VydmljZS53b2Evd2EvZ2V0U2VydmljZVVzZXJJZDwvc3RyaW5nPgogIDxrZXk+aWQtZ2V0LWFkbWluLXRva2VuPC9rZXk+PHN0cmluZz5odHRwczovL3F1ZXJ5LmVzcy5hcHBsZS5jb20vV2ViT2JqZWN0cy9RdWVyeVNlcnZpY2Uud29hL3dhL2dldEFkbWluVG9rZW48L3N0cmluZz4KICA8a2V5PmlkLWdldC1jb25zZW50LXRva2VuPC9rZXk+PHN0cmluZz5odHRwczovL3F1ZXJ5LmVzcy5hcHBsZS5jb20vV2ViT2JqZWN0cy9RdWVyeVNlcnZpY2Uud29hL3dhL2dldENvbnNlbnRUb2tlbjwvc3RyaW5nPgogIDxrZXk+aWQtZ2V0LXVzZXItdG9rZW48L2tleT48c3RyaW5nPmh0dHBzOi8vcXVlcnkuZXNzLmFwcGxlLmNvbS9XZWJPYmplY3RzL1F1ZXJ5U2VydmljZS53b2Evd2EvZ2V0VXNlclRva2VuPC9zdHJpbmc+CiAgPGtleT5pZC1nZXQtZGVwZW5kZW50LXJlZ2lzdHJhdGlvbnM8L2tleT48c3RyaW5nPmh0dHBzOi8vaWRlbnRpdHkuZXNzLmFwcGxlLmNvbS9XZWJPYmplY3RzL1RESWRlbnRpdHlTZXJ2aWNlLndvYS93YS9nZXREZXBlbmRlbnRSZWdpc3RyYXRpb25zPC9zdHJpbmc+CiAgPGtleT5pZC1hdXRoZW50aWNhdGUtcGhvbmUtbnVtYmVyPC9rZXk+PHN0cmluZz5odHRwczovL2lkZW50aXR5LmVzcy5hcHBsZS5jb20vV2ViT2JqZWN0cy9URElkZW50aXR5U2VydmljZS53b2Evd2EvYXV0aGVudGljYXRlUGhvbmVOdW1iZXI8L3N0cmluZz4KICA8a2V5PmlkLWF1dGhlbnRpY2F0ZS1kcy1pZDwva2V5PjxzdHJpbmc+aHR0cHM6Ly9wcm9maWxlLmVzcy5hcHBsZS5jb20vV2ViT2JqZWN0cy9WQ1Byb2ZpbGVTZXJ2aWNlLndvYS93YS9hdXRoZW50aWNhdGVEUzwvc3RyaW5nPgogIDxrZXk+aWQtYXV0aGVudGljYXRlLWljbG91ZDwva2V5PjxzdHJpbmc+aHR0cHM6Ly9wcm9maWxlLmVzcy5hcHBsZS5jb20vV2ViT2JqZWN0cy9WQ1Byb2ZpbGVTZXJ2aWNlLndvYS93YS9hdXRoZW50aWNhdGVJQ2xvdWQ8L3N0cmluZz4KICA8a2V5PmlkLWdldC1oYW5kbGVzPC9rZXk+PHN0cmluZz5odHRwczovL3Byb2ZpbGUuZXNzLmFwcGxlLmNvbS9XZWJPYmplY3RzL1ZDUHJvZmlsZVNlcnZpY2Uud29hL3dhL2lkc0dldEhhbmRsZXM8L3N0cmluZz4KICA8a2V5Pm1heC1zcGFtLW1lc3NhZ2Utc2l6ZTwva2V5PjxpbnRlZ2VyPjEwMjQ8L2ludGVnZXI+CiAgPGtleT5tYXgtc3BhbS1tZXNzYWdlcy1wZXItcmVwb3J0PC9rZXk+PGludGVnZXI+MjwvaW50ZWdlcj4KICA8a2V5PnZjLXJlZ2lzdGVyPC9rZXk+PHN0cmluZz5odHRwczovL3JlZ2lzdHJhdGlvbi5lc3MuYXBwbGUuY29tL1dlYk9iamVjdHMvVkNSZWdpc3RyYXRpb25TZXJ2aWNlLndvYS93YS9yZWdpc3Rlcjwvc3RyaW5nPgogIDxrZXk+dmMtZGVyZWdpc3Rlcjwva2V5PjxzdHJpbmc+aHR0cHM6Ly9yZWdpc3RyYXRpb24uZXNzLmFwcGxlLmNvbS9XZWJPYmplY3RzL1ZDUmVnaXN0cmF0aW9uU2VydmljZS53b2Evd2EvZGVyZWdpc3Rlcjwvc3RyaW5nPgogIDxrZXk+dmMtcmVnaXN0cmF0aW9uLWhiaTwva2V5PjxpbnRlZ2VyPjIzMTcyNDY8L2ludGVnZXI+CiAgPGtleT5nay1pbnZpdGF0aW9uLWluaXRpYXRlPC9rZXk+PHN0cmluZz5odHRwczovL3Byb2ZpbGUuZXNzLmFwcGxlLmNvbS9XZWJPYmplY3RzL1ZDSW52aXRhdGlvblNlcnZpY2Uud29hL3dhL2luaXRpYXRlPC9zdHJpbmc+CiAgPGtleT5nay1pbnZpdGF0aW9uLXJlaW5pdGlhdGU8L2tleT48c3RyaW5nPmh0dHBzOi8vcHJvZmlsZS5lc3MuYXBwbGUuY29tL1dlYk9iamVjdHMvVkNJbnZpdGF0aW9uU2VydmljZS53b2Evd2EvcmVpbml0aWF0ZTwvc3RyaW5nPgogIDxrZXk+Z2staW52aXRhdGlvbi1hY2NlcHQ8L2tleT48c3RyaW5nPmh0dHBzOi8vcHJvZmlsZS5lc3MuYXBwbGUuY29tL1dlYk9iamVjdHMvVkNJbnZpdGF0aW9uU2VydmljZS53b2Evd2EvYWNjZXB0PC9zdHJpbmc+CiAgPGtleT5nay1pbnZpdGF0aW9uLXJlamVjdDwva2V5PjxzdHJpbmc+aHR0cHM6Ly9wcm9maWxlLmVzcy5hcHBsZS5jb20vV2ViT2JqZWN0cy9WQ0ludml0YXRpb25TZXJ2aWNlLndvYS93YS9yZWplY3Q8L3N0cmluZz4KICA8a2V5PmdrLWludml0YXRpb24tY2FuY2VsPC9rZXk+PHN0cmluZz5odHRwczovL3Byb2ZpbGUuZXNzLmFwcGxlLmNvbS9XZWJPYmplY3RzL1ZDSW52aXRhdGlvblNlcnZpY2Uud29hL3dhL2NhbmNlbDwvc3RyaW5nPgogIDxrZXk+Z2staW52aXRhdGlvbi1yZWxheS1pbml0aWF0ZTwva2V5PjxzdHJpbmc+aHR0cHM6Ly9wcm9maWxlLmVzcy5hcHBsZS5jb20vV2ViT2JqZWN0cy9WQ0ludml0YXRpb25TZXJ2aWNlLndvYS93YS9yZWxheUluaXRpYXRlPC9zdHJpbmc+CiAgPGtleT5nay1pbnZpdGF0aW9uLXJlbGF5LXVwZGF0ZTwva2V5PjxzdHJpbmc+aHR0cHM6Ly9wcm9maWxlLmVzcy5hcHBsZS5jb20vV2ViT2JqZWN0cy9WQ0ludml0YXRpb25TZXJ2aWNlLndvYS93YS9yZWxheVVwZGF0ZTwvc3RyaW5nPgogIDxrZXk+Z2staW52aXRhdGlvbi1yZWxheS1jYW5jZWw8L2tleT48c3RyaW5nPmh0dHBzOi8vcHJvZmlsZS5lc3MuYXBwbGUuY29tL1dlYk9iamVjdHMvVkNJbnZpdGF0aW9uU2VydmljZS53b2Evd2EvcmVsYXlDYW5jZWw8L3N0cmluZz4KICA8a2V5PmdrLWludml0YXRpb24tc2VuZDwva2V5PjxzdHJpbmc+aHR0cHM6Ly9wcm9maWxlLmVzcy5hcHBsZS5jb20vV2ViT2JqZWN0cy9WQ0ludml0YXRpb25TZXJ2aWNlLndvYS93YS9zZW5kPC9zdHJpbmc+CiAgPGtleT5nay1pbnZpdGF0aW9uLWJyZWFrLWJlZm9yZS1tYWtlLXRpbWVvdXQ8L2tleT48cmVhbD41LjA8L3JlYWw+CiAgPGtleT52Yy1wcm9maWxlLWF1dGhlbnRpY2F0ZTwva2V5PjxzdHJpbmc+aHR0cHM6Ly9wcm9maWxlLmVzcy5hcHBsZS5jb20vV2ViT2JqZWN0cy9WQ1Byb2ZpbGVTZXJ2aWNlLndvYS93YS9hdXRoZW50aWNhdGVVc2VyPC9zdHJpbmc+CiAgPGtleT52Yy1wcm9maWxlLWdldC1oYW5kbGVzPC9rZXk+PHN0cmluZz5odHRwczovL3Byb2ZpbGUuZXNzLmFwcGxlLmNvbS9XZWJPYmplY3RzL1ZDUHJvZmlsZVNlcnZpY2Uud29hL3dhL2dldEhhbmRsZXM8L3N0cmluZz4KICA8a2V5PnZjLXByb2ZpbGUtZ2V0LWVtYWlsczwva2V5PjxzdHJpbmc+aHR0cHM6Ly9wcm9maWxlLmVzcy5hcHBsZS5jb20vV2ViT2JqZWN0cy9WQ1Byb2ZpbGVTZXJ2aWNlLndvYS93YS9nZXRFbWFpbHM8L3N0cmluZz4KICA8a2V5PnZjLXByb2ZpbGUtdmFsaWRhdGUtZW1haWw8L2tleT48c3RyaW5nPmh0dHBzOi8vcHJvZmlsZS5lc3MuYXBwbGUuY29tL1dlYk9iamVjdHMvVkNQcm9maWxlU2VydmljZS53b2Evd2EvdmFsaWRhdGVIYW5kbGU8L3N0cmluZz4KICA8a2V5PnZjLXByb2ZpbGUtdmFsaWRhdGUtaGFuZGxlPC9rZXk+PHN0cmluZz5odHRwczovL3Byb2ZpbGUuZXNzLmFwcGxlLmNvbS9XZWJPYmplY3RzL1ZDUHJvZmlsZVNlcnZpY2Uud29hL3dhL3ZhbGlkYXRlSGFuZGxlPC9zdHJpbmc+CiAgPGtleT52Yy1wcm9maWxlLWxpbmstaGFuZGxlPC9rZXk+PHN0cmluZz5odHRwczovL3Byb2ZpbGUuZXNzLmFwcGxlLmNvbS9XZWJPYmplY3RzL1ZDUHJvZmlsZVNlcnZpY2Uud29hL3dhL2xpbmtIYW5kbGU8L3N0cmluZz4KICA8a2V5PnZjLXByb2ZpbGUtdW5saW5rLWhhbmRsZTwva2V5PjxzdHJpbmc+aHR0cHM6Ly9wcm9maWxlLmVzcy5hcHBsZS5jb20vV2ViT2JqZWN0cy9WQ1Byb2ZpbGVTZXJ2aWNlLndvYS93YS91bmxpbmtIYW5kbGU8L3N0cmluZz4KICA8a2V5PnZjLXByb2ZpbGUtY29uZmlybS1lbWFpbDwva2V5PjxzdHJpbmc+aHR0cHM6Ly9wcm9maWxlLmVzcy5hcHBsZS5jb20vV2ViT2JqZWN0cy9WQ1Byb2ZpbGVTZXJ2aWNlLndvYS93YS9saW5rSGFuZGxlPC9zdHJpbmc+CiAgPGtleT52Yy1wcm9maWxlLXByb3Zpc2lvbjwva2V5PjxzdHJpbmc+aHR0cHM6Ly9wcm9maWxlLmVzcy5hcHBsZS5jb20vV2ViT2JqZWN0cy9WQ1Byb2ZpbGVTZXJ2aWNlLndvYS93YS9wcm92aXNpb25FbWFpbHM8L3N0cmluZz4KICA8a2V5PnZjLXByb2ZpbGUtc2V0dXAtcGFnZTwva2V5PjxzdHJpbmc+aHR0cHM6Ly9wcm9maWxlLmVzcy5hcHBsZS5jb20vV2ViT2JqZWN0cy9WQ1Byb2ZpbGVTZXJ2aWNlLndvYS93cC9hY2NvdW50U2V0dXA8L3N0cmluZz4KICA8a2V5PnZjLXByb2ZpbGUtZWRpdC1wYWdlPC9rZXk+PHN0cmluZz5odHRwczovL3Byb2ZpbGUuZXNzLmFwcGxlLmNvbS9XZWJPYmplY3RzL1ZDUHJvZmlsZVNlcnZpY2Uud29hL3dwL2FjY291bnRFZGl0PC9zdHJpbmc+CiAgPGtleT52Yy1wcm9maWxlLWF1dGhvcml6ZTwva2V5PjxzdHJpbmc+aHR0cHM6Ly9wcm9maWxlLmVzcy5hcHBsZS5jb20vV2ViT2JqZWN0cy9WQ1Byb2ZpbGVTZXJ2aWNlLndvYS93cC9hY2NvdW50RWRpdDwvc3RyaW5nPgogIDxrZXk+dmMtcHJvZmlsZS1wYXNzd29yZC1jaGFuZ2U8L2tleT48c3RyaW5nPmh0dHBzOi8vcHJvZmlsZS5lc3MuYXBwbGUuY29tL1dlYk9iamVjdHMvVkNQcm9maWxlU2VydmljZS53b2Evd3AvcGFzc3dvcmRDaGFuZ2U8L3N0cmluZz4KICA8a2V5PnZjLXByb2ZpbGUtZ2V0LXJlZ2lvbi1tZXRhZGF0YTwva2V5PjxzdHJpbmc+aHR0cHM6Ly9wcm9maWxlLmVzcy5hcHBsZS5jb20vV2ViT2JqZWN0cy9WQ1Byb2ZpbGVTZXJ2aWNlLndvYS93YS9yZWdpb25NZXRhZGF0YTwvc3RyaW5nPgogIDxrZXk+dmMtcHJvZmlsZS1nZXQtZGVmYXVsdC1pbnZpdGF0aW9uLWNvbnRleHQ8L2tleT48c3RyaW5nPmh0dHBzOi8vcHJvZmlsZS5lc3MuYXBwbGUuY29tL1dlYk9iamVjdHMvVkNQcm9maWxlU2VydmljZS53b2Evd2EvZ2V0RGVmYXVsdEludml0YXRpb25Db250ZXh0PC9zdHJpbmc+CiAgPGtleT52Yy1wcm9maWxlLXZhbGlkYXRlLWludml0YXRpb24tY29udGV4dDwva2V5PjxzdHJpbmc+aHR0cHM6Ly9wcm9maWxlLmVzcy5hcHBsZS5jb20vV2ViT2JqZWN0cy9WQ1Byb2ZpbGVTZXJ2aWNlLndvYS93YS92YWxpZGF0ZUludml0YXRpb25Db250ZXh0PC9zdHJpbmc+CiAgPGtleT5tZC1wcm9maWxlLXNldHVwLXBhZ2U8L2tleT48c3RyaW5nPmh0dHBzOi8vcHJvZmlsZS5lc3MuYXBwbGUuY29tL1dlYk9iamVjdHMvVkNQcm9maWxlU2VydmljZS53b2Evd3AvYWNjb3VudFNldHVwPC9zdHJpbmc+CiAgPGtleT5tZC1wcm9maWxlLWVkaXQtcGFnZTwva2V5PjxzdHJpbmc+aHR0cHM6Ly9wcm9maWxlLmVzcy5hcHBsZS5jb20vV2ViT2JqZWN0cy9WQ1Byb2ZpbGVTZXJ2aWNlLndvYS93cC9hY2NvdW50RWRpdDwvc3RyaW5nPgogIDxrZXk+bWQtcHJvZmlsZS1hdXRob3JpemU8L2tleT48c3RyaW5nPmh0dHBzOi8vcHJvZmlsZS5lc3MuYXBwbGUuY29tL1dlYk9iamVjdHMvVkNQcm9maWxlU2VydmljZS53b2Evd3AvYWNjb3VudEVkaXQ8L3N0cmluZz4KICA8a2V5Pm1kLXByb2ZpbGUtcGFzc3dvcmQtY2hhbmdlPC9rZXk+PHN0cmluZz5odHRwczovL3Byb2ZpbGUuZXNzLmFwcGxlLmNvbS9XZWJPYmplY3RzL1ZDUHJvZmlsZVNlcnZpY2Uud29hL3dwL3Bhc3N3b3JkQ2hhbmdlPC9zdHJpbmc+CiAgPGtleT5xci1pbnZpdGF0aW9ucy1lbmFibGVkPC9rZXk+PGludGVnZXI+MTwvaW50ZWdlcj4KICA8a2V5PmRzLWlmb3Jnb3QtdXJsPC9rZXk+PHN0cmluZz5odHRwczovL2lmb3Jnb3QuYXBwbGUuY29tLzwvc3RyaW5nPgogIDxrZXk+ZHMtdmV0dGluZy1lbWFpbC1mcm9tPC9rZXk+CiAgPGFycmF5PgogICAgPHN0cmluZz5hcHBsZWlkQGlkLmFwcGxlLmNvbTwvc3RyaW5nPgogICAgPHN0cmluZz5hcHBsZWlkQGFwcGxlLmNvbTwvc3RyaW5nPgogIDwvYXJyYXk+CiAgPGtleT5nay1jZHg8L2tleT48c3RyaW5nPjE3LjE1NS41LjIzMjo0Mzk4PC9zdHJpbmc+CiAgPGtleT5nay1jb21tbmF0LW1haW4wPC9rZXk+PHN0cmluZz4xNy4xNzguMTA0Ljk5OjE2Mzg0PC9zdHJpbmc+CiAgPGtleT5nay1jb21tbmF0LW1haW4xPC9rZXk+PHN0cmluZz4xNy4xNzguMTA0Ljk5OjE2Mzg1PC9zdHJpbmc+CiAgPGtleT5nay1jb21tbmF0LWNvaG9ydDwva2V5PjxzdHJpbmc+MTcuMTc4LjEwNC4xMDA6MTYzODY8L3N0cmluZz4KICA8a2V5PmdrLWNkeC1uYW1lPC9rZXk+PHN0cmluZz5jZHguZXNzLmFwcGxlLmNvbTo0Mzk4PC9zdHJpbmc+CiAgPGtleT5nay1jb21tbmF0LW1haW4wLW5hbWU8L2tleT48c3RyaW5nPmNvbW1uYXQtbWFpbi5lc3MuYXBwbGUuY29tOjE2Mzg0PC9zdHJpbmc+CiAgPGtleT5nay1jb21tbmF0LW1haW4xLW5hbWU8L2tleT48c3RyaW5nPmNvbW1uYXQtbWFpbi5lc3MuYXBwbGUuY29tOjE2Mzg1PC9zdHJpbmc+CiAgPGtleT5nay1jb21tbmF0LWNvaG9ydC1uYW1lPC9rZXk+PHN0cmluZz5jb21tbmF0LWNvaG9ydC5lc3MuYXBwbGUuY29tOjE2Mzg2PC9zdHJpbmc+CiAgPGtleT5nay1wMnAtdGNwLWNoZWNrLXVybDwva2V5PjxzdHJpbmc+aHR0cDovL3N0YXRpYy5lc3MuYXBwbGUuY29tOjgwL2Nvbm5lY3Rpdml0eS50eHQ8L3N0cmluZz4KICA8a2V5PmdrLXAycC1zc2wtY2hlY2stdXJsPC9rZXk+PHN0cmluZz5odHRwczovL3Byb2ZpbGUuZXNzLmFwcGxlLmNvbTo0NDMvV2ViT2JqZWN0cy9WQ0ludml0YXRpb25TZXJ2aWNlLndvYS93YS9oZWFsdGhDaGVjazwvc3RyaW5nPgogIDxrZXk+Z2stcDJwLWJsb2Itc2l6ZS1tYXg8L2tleT48aW50ZWdlcj4xMzA8L2ludGVnZXI+CiAgPGtleT5nay1wMnAtbmF0LXR5cGUtdGltZW91dDwva2V5PjxyZWFsPjUuMDwvcmVhbD4KICA8a2V5PmdrLXAycC1pY2UtdGltZW91dDwva2V5PjxyZWFsPjM1LjA8L3JlYWw+CiAgPGtleT5nay1wMnAtcHJlLXJlbGF5LXRpbWVvdXQ8L2tleT48cmVhbD42LjA8L3JlYWw+CiAgPGtleT5nay1wMnAtcmVsYXktYml0cmF0ZS1tYXg8L2tleT48aW50ZWdlcj4yMDAwPC9pbnRlZ2VyPgogIDxrZXk+Z2stcDJwLXRjcC1yZWxheS1iaXRyYXRlLW1heDwva2V5PjxpbnRlZ2VyPjIwMDA8L2ludGVnZXI+CiAgPGtleT5nay1wMnAtcmVtb3RlLXBhY2tldHMtdGltZW91dDwva2V5PjxyZWFsPjMwLjA8L3JlYWw+CiAgPGtleT5nay1wMnAtbmV0d29yay1jb25kaXRpb25zLXRpbWVvdXQ8L2tleT48cmVhbD42MC4wPC9yZWFsPgogIDxrZXk+Z2stcDJwLXBvc3QtY29ubmVjdGl2aXR5LWNoZWNrPC9rZXk+PHRydWUvPgogIDxrZXk+Z2stcDJwLXN0YXJ0dXAtdGltZW91dDwva2V5PjxyZWFsPjMwLjA8L3JlYWw+CiAgPGtleT5nay1wMnAtdmlkZW8tdGhyb3R0bGluZy10aW1lb3V0PC9rZXk+PHJlYWw+MzAuMDwvcmVhbD4KICA8a2V5PmdrLXAycC1lbmFibGVkLTNnPC9rZXk+PHRydWUvPgogIDxrZXk+Z2stcDJwLWJpdHJhdGUtbWF4LTJnPC9rZXk+PGludGVnZXI+MTAwPC9pbnRlZ2VyPgogIDxrZXk+Z2stcDJwLWJpdHJhdGUtbWF4LTNnPC9rZXk+PGludGVnZXI+MjI4PC9pbnRlZ2VyPgogIDxrZXk+Z2stcDJwLWJpdHJhdGUtbWF4LWx0ZTwva2V5PjxpbnRlZ2VyPjIyODwvaW50ZWdlcj4KICA8a2V5PnJ0Yy1hYy1iaXRyYXRlLW1heC0yZzwva2V5PjxpbnRlZ2VyPjQwPC9pbnRlZ2VyPgogIDxrZXk+cnRjLWFjLWJpdHJhdGUtbWF4LTNnPC9rZXk+PGludGVnZXI+NDA8L2ludGVnZXI+CiAgPGtleT5ydGMtYWMtYml0cmF0ZS1tYXgtbHRlPC9rZXk+PGludGVnZXI+NDA8L2ludGVnZXI+CiAgPGtleT5ydGMtYWMtcmVsYXktYml0cmF0ZS1tYXg8L2tleT48aW50ZWdlcj40MDwvaW50ZWdlcj4KICA8a2V5PnJ0Yy1hYy10Y3AtcmVsYXktYml0cmF0ZS1tYXg8L2tleT48aW50ZWdlcj40MDwvaW50ZWdlcj4KICA8a2V5PnJ0Yy1zcy1iaXRyYXRlLW1heC0yZzwva2V5PjxpbnRlZ2VyPjUxMDwvaW50ZWdlcj4KICA8a2V5PnJ0Yy1zcy1iaXRyYXRlLW1heC0zZzwva2V5PjxpbnRlZ2VyPjUxMDwvaW50ZWdlcj4KICA8a2V5PnJ0Yy1zcy1iaXRyYXRlLW1heC1sdGU8L2tleT48aW50ZWdlcj41MTA8L2ludGVnZXI+CiAgPGtleT5waG9uZS1yZWdpc3RyYXRpb24tcmV0cnktaW50ZXJ2YWwtc2Vjb25kczwva2V5PjxpbnRlZ2VyPjg2NDAwPC9pbnRlZ2VyPgogIDxrZXk+bWF4LXVyaS1tdWx0aS1xdWVyeTwva2V5PjxpbnRlZ2VyPjM1PC9pbnRlZ2VyPgogIDxrZXk+ZG8taHR0cC1waXBlbGluaW5nPC9rZXk+PHRydWUvPgogIDxrZXk+ZG8taHR0cC1rZWVwLWFsaXZlPC9rZXk+PHRydWUvPgogIDxrZXk+aHR0cC1rZWVwLWFsaXZlLWlkbGUtdGltZW91dC13aWZpLW1pbGxpczwva2V5PjxpbnRlZ2VyPjMwMDAwPC9pbnRlZ2VyPgogIDxrZXk+aHR0cC1rZWVwLWFsaXZlLWlkbGUtdGltZW91dC1jZWxsLW1pbGxpczwva2V5PjxpbnRlZ2VyPjMwMDAwPC9pbnRlZ2VyPgogIDxrZXk+bWF4LWNvbmN1cnJlbnQtY29ubmVjdGlvbnM8L2tleT48aW50ZWdlcj40PC9pbnRlZ2VyPgogIDxrZXk+aWRzLWRhdGFjaGFubmVscy1tYXhiaXRyYXRlLW92ZXItcXVpY2stcmVsYXk8L2tleT48aW50ZWdlcj4xMDAwMDA8L2ludGVnZXI+CiAgPGtleT5nZHItbWF4LWF1dGgtcmV0cmllczwva2V5PjxpbnRlZ2VyPjEwPC9pbnRlZ2VyPgogIDxrZXk+Z2RyLWF1dGgtcmV0cnktaW50ZXJ2YWwtc2Vjb25kczwva2V5PjxyZWFsPjE1LjA8L3JlYWw+CiAgPGtleT5zbXMtbWF4LXJldHJpZXM8L2tleT48aW50ZWdlcj41PC9pbnRlZ2VyPgogIDxrZXk+c21zLW1heC1kZWxpdmVyeS1yZXRyaWVzPC9rZXk+PGludGVnZXI+NTwvaW50ZWdlcj4KICA8a2V5PmJhZy1leHBpcnktdGltZXN0YW1wPC9rZXk+PGludGVnZXI+MTQ5MDg5MTIyNDU1MjwvaW50ZWdlcj4KICA8a2V5PnZjLWVuYWJsZS1pcmF0LXJlY29tbWVuZGF0aW9uPC9rZXk+PHRydWUvPgogIDxrZXk+bWFkcmlkLWhlYWx0aGNoZWNrPC9rZXk+PHRydWUvPgogIDxrZXk+bWF4LWVudHJ5LW11bHRpLXNlcnZpY2UtcXVlcnk8L2tleT48aW50ZWdlcj41MDwvaW50ZWdlcj4KICA8a2V5PnByZWZsaWdodC1lbmFibGVkPC9rZXk+PHRydWUvPgo8L2RpY3Q+CjwvcGxpc3Q+Cg==</data>
	</dict>
	</plist>

## If we base64 decode the bag, here is the data:

	<?xml version="1.0" encoding="UTF-8" standalone="no"?>
	<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
	<plist version="1.0">
	<dict>
	  <key>vc-build-version</key><string>17E119</string>
	  <key>vc-build-revision</key><string>undefined</string>
	  <key>vc-disaster-mode</key><false/>
	  <key>vc-disaster-sender-max-retries</key><integer>1</integer>
	  <key>vc-disaster-receiver-retry-interval</key><integer>600</integer>
	  <key>vc-disaster-sender-self-tokens</key><false/>
	  <key>vc-enable-hevc</key><false/>
	  <key>vc-enable-hevc-v2</key><true/>
	  <key>vc-enable-evs-audio-codec</key><true/>
	  <key>vc-enable-red-audio</key><true/>
	  <key>apns-ids-query-percentage</key><integer>100</integer>
	  <key>apns-ids-query-min-version</key><integer>2</integer>
	  <key>id-validation-cert</key><string>http://static.ess.apple.com/identity/validation/cert-1.0.plist</string>
	  <key>id-recover-signature</key><string>https://identity.ess.apple.com/WebObjects/TDIdentityService.woa/wa/recoverSignature</string>
	  <key>id-initialize-validation</key><string>https://identity.ess.apple.com/WebObjects/TDIdentityService.woa/wa/initializeValidation</string>
	  <key>id-provision-phone-number</key><string>https://identity.ess.apple.com/WebObjects/TDIdentityService.woa/wa/authenticatePhoneNumber</string>
	  <key>id-preflight</key><string>https://identity.ess.apple.com/WebObjects/TDIdentityService.woa/wa/preflight</string>
	  <key>id-provision-ds-id</key><string>https://profile.ess.apple.com/WebObjects/VCProfileService.woa/wa/authenticateDS</string>
	  <key>id-register</key><string>https://identity.ess.apple.com/WebObjects/TDIdentityService.woa/wa/register</string>
	  <key>id-deregister</key><string>https://identity.ess.apple.com/WebObjects/TDIdentityService.woa/wa/deregister</string>
	  <key>id-canonicalize</key><string>https://query.ess.apple.com/WebObjects/TDIdentityService.woa/wa/canonicalize</string>
	  <key>id-query</key><string>https://query.ess.apple.com/WebObjects/QueryService.woa/wa/query</string>
	  <key>id-check-unknown</key><string>https://query.ess.apple.com/WebObjects/QueryService.woa/wa/checkUnknown</string>
	  <key>id-report-spam</key><string>https://identity.ess.apple.com/WebObjects/TDIdentityService.woa/wa/reportSpam</string>
	  <key>id-report-unknown</key><string>https://identity.ess.apple.com/WebObjects/TDIdentityService.woa/wa/reportUnknown</string>
	  <key>id-validate-credentials</key><string>https://identity.ess.apple.com/WebObjects/TDIdentityService.woa/wa/validateCredentials</string>
	  <key>id-query-by-service</key><string>https://query.ess.apple.com/WebObjects/QueryService.woa/wa/queryByService</string>
	  <key>id-get-pairing-token</key><string>https://query.ess.apple.com/WebObjects/QueryService.woa/wa/getPairingToken</string>
	  <key>id-get-service-user-id</key><string>https://query.ess.apple.com/WebObjects/QueryService.woa/wa/getServiceUserId</string>
	  <key>id-get-admin-token</key><string>https://query.ess.apple.com/WebObjects/QueryService.woa/wa/getAdminToken</string>
	  <key>id-get-consent-token</key><string>https://query.ess.apple.com/WebObjects/QueryService.woa/wa/getConsentToken</string>
	  <key>id-get-user-token</key><string>https://query.ess.apple.com/WebObjects/QueryService.woa/wa/getUserToken</string>
	  <key>id-get-dependent-registrations</key><string>https://identity.ess.apple.com/WebObjects/TDIdentityService.woa/wa/getDependentRegistrations</string>
	  <key>id-authenticate-phone-number</key><string>https://identity.ess.apple.com/WebObjects/TDIdentityService.woa/wa/authenticatePhoneNumber</string>
	  <key>id-authenticate-ds-id</key><string>https://profile.ess.apple.com/WebObjects/VCProfileService.woa/wa/authenticateDS</string>
	  <key>id-authenticate-icloud</key><string>https://profile.ess.apple.com/WebObjects/VCProfileService.woa/wa/authenticateICloud</string>
	  <key>id-get-handles</key><string>https://profile.ess.apple.com/WebObjects/VCProfileService.woa/wa/idsGetHandles</string>
	  <key>max-spam-message-size</key><integer>1024</integer>
	  <key>max-spam-messages-per-report</key><integer>2</integer>
	  <key>vc-register</key><string>https://registration.ess.apple.com/WebObjects/VCRegistrationService.woa/wa/register</string>
	  <key>vc-deregister</key><string>https://registration.ess.apple.com/WebObjects/VCRegistrationService.woa/wa/deregister</string>
	  <key>vc-registration-hbi</key><integer>2317246</integer>
	  <key>gk-invitation-initiate</key><string>https://profile.ess.apple.com/WebObjects/VCInvitationService.woa/wa/initiate</string>
	  <key>gk-invitation-reinitiate</key><string>https://profile.ess.apple.com/WebObjects/VCInvitationService.woa/wa/reinitiate</string>
	  <key>gk-invitation-accept</key><string>https://profile.ess.apple.com/WebObjects/VCInvitationService.woa/wa/accept</string>
	  <key>gk-invitation-reject</key><string>https://profile.ess.apple.com/WebObjects/VCInvitationService.woa/wa/reject</string>
	  <key>gk-invitation-cancel</key><string>https://profile.ess.apple.com/WebObjects/VCInvitationService.woa/wa/cancel</string>
	  <key>gk-invitation-relay-initiate</key><string>https://profile.ess.apple.com/WebObjects/VCInvitationService.woa/wa/relayInitiate</string>
	  <key>gk-invitation-relay-update</key><string>https://profile.ess.apple.com/WebObjects/VCInvitationService.woa/wa/relayUpdate</string>
	  <key>gk-invitation-relay-cancel</key><string>https://profile.ess.apple.com/WebObjects/VCInvitationService.woa/wa/relayCancel</string>
	  <key>gk-invitation-send</key><string>https://profile.ess.apple.com/WebObjects/VCInvitationService.woa/wa/send</string>
	  <key>gk-invitation-break-before-make-timeout</key><real>5.0</real>
	  <key>vc-profile-authenticate</key><string>https://profile.ess.apple.com/WebObjects/VCProfileService.woa/wa/authenticateUser</string>
	  <key>vc-profile-get-handles</key><string>https://profile.ess.apple.com/WebObjects/VCProfileService.woa/wa/getHandles</string>
	  <key>vc-profile-get-emails</key><string>https://profile.ess.apple.com/WebObjects/VCProfileService.woa/wa/getEmails</string>
	  <key>vc-profile-validate-email</key><string>https://profile.ess.apple.com/WebObjects/VCProfileService.woa/wa/validateHandle</string>
	  <key>vc-profile-validate-handle</key><string>https://profile.ess.apple.com/WebObjects/VCProfileService.woa/wa/validateHandle</string>
	  <key>vc-profile-link-handle</key><string>https://profile.ess.apple.com/WebObjects/VCProfileService.woa/wa/linkHandle</string>
	  <key>vc-profile-unlink-handle</key><string>https://profile.ess.apple.com/WebObjects/VCProfileService.woa/wa/unlinkHandle</string>
	  <key>vc-profile-confirm-email</key><string>https://profile.ess.apple.com/WebObjects/VCProfileService.woa/wa/linkHandle</string>
	  <key>vc-profile-provision</key><string>https://profile.ess.apple.com/WebObjects/VCProfileService.woa/wa/provisionEmails</string>
	  <key>vc-profile-setup-page</key><string>https://profile.ess.apple.com/WebObjects/VCProfileService.woa/wp/accountSetup</string>
	  <key>vc-profile-edit-page</key><string>https://profile.ess.apple.com/WebObjects/VCProfileService.woa/wp/accountEdit</string>
	  <key>vc-profile-authorize</key><string>https://profile.ess.apple.com/WebObjects/VCProfileService.woa/wp/accountEdit</string>
	  <key>vc-profile-password-change</key><string>https://profile.ess.apple.com/WebObjects/VCProfileService.woa/wp/passwordChange</string>
	  <key>vc-profile-get-region-metadata</key><string>https://profile.ess.apple.com/WebObjects/VCProfileService.woa/wa/regionMetadata</string>
	  <key>vc-profile-get-default-invitation-context</key><string>https://profile.ess.apple.com/WebObjects/VCProfileService.woa/wa/getDefaultInvitationContext</string>
	  <key>vc-profile-validate-invitation-context</key><string>https://profile.ess.apple.com/WebObjects/VCProfileService.woa/wa/validateInvitationContext</string>
	  <key>md-profile-setup-page</key><string>https://profile.ess.apple.com/WebObjects/VCProfileService.woa/wp/accountSetup</string>
	  <key>md-profile-edit-page</key><string>https://profile.ess.apple.com/WebObjects/VCProfileService.woa/wp/accountEdit</string>
	  <key>md-profile-authorize</key><string>https://profile.ess.apple.com/WebObjects/VCProfileService.woa/wp/accountEdit</string>
	  <key>md-profile-password-change</key><string>https://profile.ess.apple.com/WebObjects/VCProfileService.woa/wp/passwordChange</string>
	  <key>qr-invitations-enabled</key><integer>1</integer>
	  <key>ds-iforgot-url</key><string>https://iforgot.apple.com/</string>
	  <key>ds-vetting-email-from</key>
	  <array>
		<string>appleid@id.apple.com</string>
		<string>appleid@apple.com</string>
	  </array>
	  <key>gk-cdx</key><string>17.155.5.232:4398</string>
	  <key>gk-commnat-main0</key><string>17.178.104.99:16384</string>
	  <key>gk-commnat-main1</key><string>17.178.104.99:16385</string>
	  <key>gk-commnat-cohort</key><string>17.178.104.100:16386</string>
	  <key>gk-cdx-name</key><string>cdx.ess.apple.com:4398</string>
	  <key>gk-commnat-main0-name</key><string>commnat-main.ess.apple.com:16384</string>
	  <key>gk-commnat-main1-name</key><string>commnat-main.ess.apple.com:16385</string>
	  <key>gk-commnat-cohort-name</key><string>commnat-cohort.ess.apple.com:16386</string>
	  <key>gk-p2p-tcp-check-url</key><string>http://static.ess.apple.com:80/connectivity.txt</string>
	  <key>gk-p2p-ssl-check-url</key><string>https://profile.ess.apple.com:443/WebObjects/VCInvitationService.woa/wa/healthCheck</string>
	  <key>gk-p2p-blob-size-max</key><integer>130</integer>
	  <key>gk-p2p-nat-type-timeout</key><real>5.0</real>
	  <key>gk-p2p-ice-timeout</key><real>35.0</real>
	  <key>gk-p2p-pre-relay-timeout</key><real>6.0</real>
	  <key>gk-p2p-relay-bitrate-max</key><integer>2000</integer>
	  <key>gk-p2p-tcp-relay-bitrate-max</key><integer>2000</integer>
	  <key>gk-p2p-remote-packets-timeout</key><real>30.0</real>
	  <key>gk-p2p-network-conditions-timeout</key><real>60.0</real>
	  <key>gk-p2p-post-connectivity-check</key><true/>
	  <key>gk-p2p-startup-timeout</key><real>30.0</real>
	  <key>gk-p2p-video-throttling-timeout</key><real>30.0</real>
	  <key>gk-p2p-enabled-3g</key><true/>
	  <key>gk-p2p-bitrate-max-2g</key><integer>100</integer>
	  <key>gk-p2p-bitrate-max-3g</key><integer>228</integer>
	  <key>gk-p2p-bitrate-max-lte</key><integer>228</integer>
	  <key>rtc-ac-bitrate-max-2g</key><integer>40</integer>
	  <key>rtc-ac-bitrate-max-3g</key><integer>40</integer>
	  <key>rtc-ac-bitrate-max-lte</key><integer>40</integer>
	  <key>rtc-ac-relay-bitrate-max</key><integer>40</integer>
	  <key>rtc-ac-tcp-relay-bitrate-max</key><integer>40</integer>
	  <key>rtc-ss-bitrate-max-2g</key><integer>510</integer>
	  <key>rtc-ss-bitrate-max-3g</key><integer>510</integer>
	  <key>rtc-ss-bitrate-max-lte</key><integer>510</integer>
	  <key>phone-registration-retry-interval-seconds</key><integer>86400</integer>
	  <key>max-uri-multi-query</key><integer>35</integer>
	  <key>do-http-pipelining</key><true/>
	  <key>do-http-keep-alive</key><true/>
	  <key>http-keep-alive-idle-timeout-wifi-millis</key><integer>30000</integer>
	  <key>http-keep-alive-idle-timeout-cell-millis</key><integer>30000</integer>
	  <key>max-concurrent-connections</key><integer>4</integer>
	  <key>ids-datachannels-maxbitrate-over-quick-relay</key><integer>100000</integer>
	  <key>gdr-max-auth-retries</key><integer>10</integer>
	  <key>gdr-auth-retry-interval-seconds</key><real>15.0</real>
	  <key>sms-max-retries</key><integer>5</integer>
	  <key>sms-max-delivery-retries</key><integer>5</integer>
	  <key>bag-expiry-timestamp</key><integer>1490891224552</integer>
	  <key>vc-enable-irat-recommendation</key><true/>
	  <key>madrid-healthcheck</key><true/>
	  <key>max-entry-multi-service-query</key><integer>50</integer>
	  <key>preflight-enabled</key><true/>
	</dict>
	</plist>

### Notice the unusual port numbers for the following entries from the plist above:

	  <key>gk-cdx</key><string>17.155.5.232:4398</string>
	  <key>gk-commnat-main0</key><string>17.178.104.99:16384</string>
	  <key>gk-commnat-main1</key><string>17.178.104.99:16385</string>
	  <key>gk-commnat-cohort</key><string>17.178.104.100:16386</string>
	  <key>gk-cdx-name</key><string>cdx.ess.apple.com:4398</string>
