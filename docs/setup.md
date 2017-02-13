# Analysis of setup.icloud.com packets:

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
