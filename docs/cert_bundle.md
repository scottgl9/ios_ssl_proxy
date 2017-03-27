### Documentation on the iOS 9 certificate bundle stored at /System/Library/Security/Certificates.bundle

Files in the directory /System/Library/Security/Certificates.bundle:

Allowed.plist
AppleESCertificates.plist
AssetVersion.plist
Blocked.plist
certsIndex.data
certsTable.data
EVRoots.plist
GrayListedKeys.plist
Info.plist
manifest.data
TrustedCTLogs.plist
TrustStore.html

### manifest.data
binary plist containing hashes of all other files in this directory

### certsTable.data
Contains actual CA certificates in DER format

### certIndex.data
Seems to be a list of SHA1 hashes of the CA certs in certsTable.data separated by \x00\x00.

### Allowed.plist
Binary plist containing list of allowed certificates. The two main groups of which each is a subgroup are:
1) 65F231AD2AF7F7DD52960AC702C10EEFA6D53B11
2) 7C724B39C7C0DB62A54F9BAA183492A2CA838259

The format of this file is the following:

        <key>65F231AD2AF7F7DD52960AC702C10EEFA6D53B11</key>
        <array>
                <data>
                AFv5ju1hK1Ds2nv/VqLf9GeordfuwKswV1TXZr67X+g=	(005BF98EED612B50ECDA7BFF56A2DFF467A8ADD7EEC0AB305754D766BEBB5FE8)
                </data>
                <data>
                AId1uOrQ/hYmnJqasoM5VUnKZ8KjqugvGmtNOrzK3Cc=	(008775B8EAD0FE16269C9A9AB283395549CA67C2A3AAE82F1A6B4D3ABCCADC27)
                </data>
...


The length of each entry is 32 bytes long, so probably SHA256.
