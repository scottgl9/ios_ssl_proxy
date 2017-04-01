#!/usr/bin/python2.7

# -*- coding: utf-8 -*-
import sys
import os
import socket
import ssl
import select
import httplib
import urlparse
import threading
import gzip
import zlib
import time
import json
import re
import plistlib

def load_device_info(sn):
    if '.xml' in sn:
        device = plistlib.readPlist(sn)
    else:
        device = plistlib.readPlist("devices/%s.xml" % sn)
    return device

if sys.argv[1:]:
        device1 = sys.argv[1]
        device2 = sys.argv[2]
else:
    print("Usage: %s <device1> <device2>" % sys.argv[0])
    exit(0)

keylist = [ 'EthernetAddress', 'BasebandMasterKeyHash', 'ModelNumber', 'UniqueDeviceID', 'WiFiAddress', 'IntegratedCircuitCardIdentity', 'CPUArchitecture', 'DeviceColor', 'InternationalMobileSubscriberIdentity', 'InternationalMobileEquipmentIdentity', 'HardwarePlatform', 'MobileEquipmentIdentifier', 'SerialNumber', 'ProductType', 'BluetoothAddress', 'MLBSerialNumber', 'HardwareModel', 'EnclosureColor' ]

dev1info = load_device_info(device1)
dev2info = load_device_info(device2)
for key in dev1info:
    if key not in dev2info: continue
    if isinstance(dev1info[key], str) and key in keylist:
        print("    else if (HttpRequestReplaceString(data, dataLength, '%s', '%s')) if (appID) SSKLog(@\"@ SSLWrite() Replaced %s -> %s\", appID);" % (dev1info[key], dev2info[key], dev1info[key], dev2info[key]));
        #print("%s: %s -> %s" % (key, dev1info[key], dev2info[key]))

