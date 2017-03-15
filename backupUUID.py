#!/usr/bin/python2.7

# -*- coding: utf-8 -*-
import sys
import os
import socket
import hashlib
import plistlib
from operator import xor

def load_device_info(sn):
    if '.xml' in sn:
        device = plistlib.readPlist(sn)
    else:
        device = plistlib.readPlist("devices/%s.xml" % sn)
    return device

if sys.argv[1:]:
    device = sys.argv[1]
else:
    print("Usage: %s <device>" % sys.argv[0])
    exit(0)

devinfo = load_device_info(device)
backupuuid = int(hashlib.sha1(devinfo['DeviceClass']).hexdigest(), 16)
print('{:x}'.format(backupuuid))
backupuuid = xor(backupuuid, int(hashlib.sha1(devinfo['ProductType']).hexdigest(), 16))
print('{:x}'.format(backupuuid))
backupuuid = xor(backupuuid, int(hashlib.sha1(devinfo['SerialNumber']).hexdigest(), 16))
print('{:x}'.format(backupuuid))
backupuuid = xor(backupuuid, int(hashlib.sha1(devinfo['DeviceColor']).hexdigest(), 16))
print('{:x}'.format(backupuuid))
backupuuid = xor(backupuuid, int(hashlib.sha1(devinfo['HardwareModel']).hexdigest(), 16))
print('{:x}'.format(backupuuid))
backupuuid = xor(backupuuid, int(hashlib.sha1("iPhone 6s Plus").hexdigest(), 16))
print('{:x}'.format(backupuuid))
backupuuid = xor(backupuuid, int(hashlib.sha1(devinfo['EnclosureColor']).hexdigest(), 16))
print('{:x}'.format(backupuuid))

print(hashlib.sha1(("\x01%s\x01\x01%s\x02\x01%s\x03\x01%s\x04\x01%s\x05\x01%s\x06\x01%s\x07" % (devinfo['DeviceClass'], devinfo['ProductType'], devinfo['SerialNumber'], devinfo['DeviceColor'], devinfo['HardwareModel'], 'iPhone 6s Plus', devinfo['EnclosureColor']))).hexdigest())

print(hashlib.sha1(("\x01%s\x01\x01%s\x02\x01%s\x03\x01%s\x04\x01%s\x05\x01%s\x06" % (devinfo['DeviceClass'], devinfo['ProductType'], devinfo['SerialNumber'], devinfo['DeviceColor'], devinfo['HardwareModel'], 'iPhone 6s Plus'))).hexdigest())
print(hashlib.sha1(("\x01%s\x01\x01%s\x02\x01%s\x03\x01%s\x04\x01%s\x05\x01%s\x06" % (devinfo['DeviceClass'], devinfo['ProductType'], devinfo['SerialNumber'], devinfo['DeviceColor'], devinfo['HardwareModel'], devinfo['EnclosureColor']))).hexdigest())

