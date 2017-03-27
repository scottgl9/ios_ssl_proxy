## Documentation on the APN protobuf format (from SSL capture)

There are four strings with device specific info in the payload:
1) ConnectionType (WiFi)
2) ProductVersion (9.3.1)
3) BuildVersion (13E238)
4) ProductType (iPhone5,3)

The first 8 bytes before 'WiFi' are currently unknown, but it seems to be a constant value for every payload sent:

0C 00 00 00 29 01 00 04
