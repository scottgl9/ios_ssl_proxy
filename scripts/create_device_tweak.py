#!/usr/bin/python

import binascii
import struct
import sys
import os
from OpenSSL import crypto
import hashlib
import plistlib
import datetime

# scp com.nablac0d3.SSLKillSwitchSettings.plist root@192.168.0.144:/var/mobile/Library/Preferences/com.nablac0d3.SSLKillSwitchSettings.plist
key_list = ["BuildVersion", "DeviceColor", "DeviceEnclosureColor", "HardwareModel", "ModelNumber", "ProductType", "ProductVersion", "SerialNumber", "UniqueDeviceID", "WiFiAddress", "DieId", "EnclosureColor", "HardwareModel", "HardwarePlatform", "BluetoothAddress", "EthernetAddress", "UniqueChipID", "DieID", "MLBSerialNumber", "FirmwareVersion", "CPUArchitecture", "WirelessBoardSnum", "BasebandCertId", "BasebandChipID", "BasebandMasterKeyHash", "BasebandVersion", "BoardId", "InternationalMobileEquipmentIdentity", "MobileEquipmentIdentifier", "WirelessBoardSerialNumber"]

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
        if key == "HardwareModel":
            p['HWModelStr'] = devinfo[key]
        elif key == "BasebandVersion":
            p['BasebandFirmwareVersion'] = devinfo[key]
        elif key == "WiFiAddress":
            p['WifiAddress'] = devinfo[key]
        elif key == "EthernetAddress":
            p['EthernetMacAddress'] = devinfo[key]
        elif key == "DieID":
            p['DieId'] = devinfo[key]
        elif key == "WirelessBoardSerialNumber":
            p['WirelessBoardSnum'] = devinfo[key]
        elif key == "EnclosureColor":
            p['DeviceEnclosureColor'] = devinfo[key]
        else:
            p[key] = devinfo[key]
        print("%s = %s" % (key, devinfo[key]))

p['UniqueDeviceIDData'] = plistlib.Data(binascii.unhexlify(p['UniqueDeviceID']))
#udid = ~hex(devinfo['UniqueDeviceID'])
#print(udid)
plistlib.writePlist(p, "com.nablac0d3.SSLKillSwitchSettings.plist")
