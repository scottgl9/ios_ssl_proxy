#!/usr/bin/python

import binascii
import struct
import sys
import os
from OpenSSL import crypto
import hashlib
import plistlib
import datetime


key_list = ["BuildVersion", "DeviceColor", "DeviceEnclosureColor", "HardwareModel", "ModelNumber", "ProductType", "ProductVersion", "SerialNumber", "UniqueDeviceID", "WifiAddress", "DieID", "HWModelStr", "HardwarePlatform", "BluetoothAddress", "EthernetMacAddress", "UniqueChipID", "DieId", "MLBSerialNumber", "FirmwareVersion", "CPUArchitecture", "WirelessBoardSnum", "BasebandCertId", "BasebandFirmwareVersion"]

def load_device_info(sn):
    if '.xml' in sn:
        device = plistlib.readPlist(sn)
    else:
        device = plistlib.readPlist("devices/%s.xml" % sn)
    return device

if sys.argv[1:]:
        device = sys.argv[1]
else:
    print("Usage: %s device" % sys.argv[0])
    exit(0)

p = dict()
p["shouldDisableCertificateValidation"] = True
devinfo = load_device_info(device)
for key in devinfo:
    if key in key_list:
        p[key] = devinfo[key]
        print("%s = %s" % (key, devinfo[key]))

plistlib.writePlist(p, "com.nablac0d3.SSLKillSwitchSettings.plist")
