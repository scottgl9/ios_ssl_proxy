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
import base64
import SocketServer
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from SocketServer import ThreadingMixIn, BaseRequestHandler
from cStringIO import StringIO
from HTMLParser import HTMLParser
from OpenSSL import crypto, SSL
from pyasn1.type import univ, constraint, char, namedtype, tag
from pyasn1.codec.der.decoder import decode
from pyasn1.error import PyAsn1Error
import fcntl
import struct
import binascii
import netifaces
import hashlib
import requests
import uuid
import ConfigParser
import signal

TYPE_RSA = crypto.TYPE_RSA
TYPE_DSA = crypto.TYPE_DSA

class _GeneralName(univ.Choice):
    # We are only interested in dNSNames. We use a default handler to ignore
    # other types.
    # TODO: We should also handle iPAddresses.
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('dNSName', char.IA5String().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2)
        )
        ),
    )


class _GeneralNames(univ.SequenceOf):
    componentType = _GeneralName()
    sizeSpec = univ.SequenceOf.sizeSpec + \
        constraint.ValueSizeConstraint(1, 1024)

class ProxyRewrite:
    dev1info = dict()
    dev2info = dict()
    logger = None
    apnproxy = False
    apnproxyssl = False
    transparent = False
    changeClientID = False
    changePushToken = False
    changeBackupDeviceUUID = False
    rewriteDevice = True
    rewriteOSVersion = True
    jailbroken = False
    singlelogfile = False
    apnscnt = 0
    server_address = None
    interface = None

    @staticmethod
    def load_device_info(sn):
        if '.xml' in sn:
            device = plistlib.readPlist(sn)
        else:
            device = plistlib.readPlist("devices/%s.xml" % sn)
        return device

    @staticmethod
    def intercept_this_host(hostname):
        hostname = hostname.replace(':443','')
        if ProxyRewrite.is_courier_push_ip(hostname): return False
        # always intercept IP addresses
        isip=re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$",hostname)
        if isip: return True
        if 'spcsdns.net' in hostname or 'sprint.com' in hostname: return True
        if "apple.com" not in hostname and "icloud.com" not in hostname and "itunes.com" not in hostname and 'apple-cloudkit.com' not in hostname and 'apple-cdn.com' not in hostname: return False

        # this means sslkill2 isn't installed
        if ProxyRewrite.jailbroken == False:
            if 'fmip.icloud.com' in hostname: return False
            if 'itunes.apple.com' in hostname: return False
            if 'itunes.com' in hostname: return False
            if 'xp.apple.com' in hostname: return False
            if hostname == "gsa.apple.com": return False
            if hostname == "gsas.apple.com": return False

        if hostname == "ppq.apple.com": return False
        #if hostname == "albert.apple.com": return False
        #if hostname == "static.ips.apple.com": return False
        #if hostname == "captive.apple.com": return False
        return True

    @staticmethod
    def is_courier_push_ip(ipaddr):
		# from data gathered, this will match the ip address to map to the hostname courier.push.apple.com
        if re.match(r"^17.188.\b1[2-6][0-9]\b.\d{1,3}$",ipaddr): return True
        elif re.match(r"^17.249.28.\d{1,3}$",ipaddr): return True
        elif re.match(r"^17.249.60.\d{1,3}$",ipaddr): return True
        return False
    
    @staticmethod
    def replace_hostname_body(text, oldhost, newhost):
        if oldhost in text:
            text = text.replace(oldhost, newhost)
            print("Replaced %s with %s" % (oldhost, newhost))
        return text

    @staticmethod
    def generate_new_clientid():
        return str(uuid.uuid4()).upper()

    @staticmethod
    def save_plist_body_attrib(text, attrname, subname):
        p = plistlib.readPlistFromString(text)
        if subname != '' and subname in p:
            psub = p[subname]
        else:
            psub = p
        if attrname in psub:
            print("found %s in body: %s" % (attrname, psub[attrname]))
            return psub[attrname]
        return ''

    @staticmethod
    def save_json_body_attrib(text, attrname, subname):
        json_obj = json.loads(text)
        if subname != '' and subname in json_obj:
            jsub = json_obj[subname]
        else:
            jsub = json_obj
        if attrname in jsub:
            print("found %s in body: %s" % (attrname, jsub[attrname]))
            return jsub[attrname]
        return ''

    @staticmethod
    def replace_json_fields(text, fields, value):
        try:
            json_obj = json.loads(text)
            if ',' in fields:
                fieldlist = fields.split(',')
                fields = fieldlist[-1]
                for field in fieldlist[:-1]:
                    json_obj = json_obj[field]
            json_obj[fields] = value
            print ("Setting field %s to %s" % (fields, value))
            return json.dumps(json_obj)
        except ValueError:
            return text

    @staticmethod
    def rewrite_json_fields(text, fields, oldval, newval):
        try:
            json_obj = json.loads(text)
            if ',' in fields:
                fieldlist = fields.split(',')
                fields = fieldlist[-1]
            for field in fieldlist[:-1]:
                 json_obj = json_obj[field]
            if json_obj[fields] == oldval:
                json_obj[fields] = newval
                print("replacing field %s: %s -> %s" % (fields, oldval, newval))
            return json.dumps(json_obj)
        except ValueError:
            return text

    @staticmethod
    def rewrite_json_body_attribs(headers, text, attrdict, subname):
        j = json.loads(text)
        if subname != '' and subname in j:
            jsub = j[subname]
        else:
            jsub = j
        for (key, value) in attrdict.items():
            if value in ProxyRewrite.dev2info:
                print("setting body json attrib %s to value %s" % (key, ProxyRewrite.dev2info[value]))
                jsub[key] = ProxyRewrite.dev2info[value]
        if subname != '' and subname in j:
            j[subname] = jsub
        else:
            j = jsub
        text = json.dumps(j)
        return text

    @staticmethod
    def rewrite_plist_body_attribs(headers, text, attrdict, subname):
        p = plistlib.readPlistFromString(text)
        if subname != '' and subname in p:
            psub = p[subname]
        else:
            psub = p
        for (key, value) in attrdict.items():
            if value in ProxyRewrite.dev2info:
                print("setting body plist attrib %s to value %s" % (key, ProxyRewrite.dev2info[value]))
                psub[key] = ProxyRewrite.dev2info[value]
        if subname != '' and subname in p:
            p[subname] = psub
        else:
            p = psub
        text = plistlib.writePlistToString(p)
        return text

    # extract only plist (ignore extra junk such as boundary)
    @staticmethod
    def get_plist_body_activation(headers, text):
        if headers['Content-Type'] == 'application/x-plist': return
        elif headers['Content-Type'] == 'application/xml': return
        return text[text.find('<?xml'):text.find('</plist>')+8]

    @staticmethod
    def rewrite_plist_body_activation(headers, text):
        xml = get_plist_body_activation(headers, text)
        boundary = headers['Content-Type'].split('=')[1]
        print("Boundary = %s" % boundary)
        p = plistlib.readPlistFromString(xml)
        if 'ActivationInfoXML' in ProxyRewrite.dev2info:
            # copy straight from device info
            p['ActivationInfoXML'] = ProxyRewrite.dev2info['ActivationInfoXML']
            if 'FairPlayCertChain' in ProxyRewrite.dev2info:
                p['FairPlayCertChain'] = ProxyRewrite.dev2info['FairPlayCertChain']
            if 'FairPlaySignature' in ProxyRewrite.dev2info:
                p['FairPlaySignature'] = ProxyRewrite.dev2info['FairPlaySignature']
            #if 'RKCertification' in text: del p['RKCertification']
            #if 'RKSignature' in text: del p['RKSignature']
            #if 'serverKP' in text: del p['serverKP']
            #if 'signActRequest' in text: del p['signActRequest']

        attribs = 'BluetoothAddress,EthernetAddress,ModelNumber,ProductType,SerialNumber,UniqueDeviceID,UniqueChipID,WifiAddress,DeviceClass'
        if ProxyRewrite.rewriteOSVersion == True:
            attribs = ("%s,%s,%s" % (attribs, 'BuildVersion', 'ProductVersion'))
        if 'InternationalMobileEquipmentIdentity' in ProxyRewrite.dev1info:
            attribs = ("%s,%s" % (attribs, 'InternationalMobileEquipmentIdentity'))
        if 'MobileEquipmentIdentifier' in ProxyRewrite.dev1info:
            attribs = ("%s,%s" % (attribs, 'MobileEquipmentIdentifier'))
        if 'RegulatoryModelNumber' in ProxyRewrite.dev1info:
            attribs = ("%s,%s" % (attribs, 'RegulatoryModelNumber'))
        text_modified = ProxyRewrite.rewrite_body_attribs(str(p['ActivationInfoXML']), attribs, '')
        p['ActivationInfoXML'] = base64.b64encode(text_modified.replace('\\t','\t').replace('\\n', '\n'))
        text = ("--%s\nContent-Disposition: form-data; name=\"activation-info\"\n\n%s\n--%s--" % (boundary,plistlib.writePlistToString(p),boundary))
        print(text)

    @staticmethod
    def replace_header_field(headers, field, attrib):
        if field not in headers: return headers

        # skip if attribute not in dev1info or dev2info
        if attrib not in ProxyRewrite.dev1info.keys() or attrib not in ProxyRewrite.dev2info.keys(): return headers
        oldval = headers[field]
        print(ProxyRewrite.dev2info[attrib])
        if ProxyRewrite.dev1info[attrib] in headers[field]:
            headers[field] = ProxyRewrite.dev2info[attrib]
        elif str(ProxyRewrite.dev1info[attrib]).lower() in headers[field]:
            headers[field] = str(ProxyRewrite.dev2info[attrib]).lower()
        if headers[field] != oldval:
            print("%s: Replacing field %s: %s -> %s" % (headers['Host'], field, oldval, headers[field]))
        return headers

    @staticmethod
    def rewrite_header_field(headers, field, attribs):
        if field not in headers: return headers
        oldval = headers[field]
        attriblist = attribs.split(',')
        for attrib in attriblist:
            if attrib == 'ProductType2':
                headers[field] = headers[field].replace(ProxyRewrite.dev1info['ProductType'].replace(',','_'), ProxyRewrite.dev2info['ProductType'].replace(',','_'))
            elif attrib == 'ProductVersion2':
                headers[field] = headers[field].replace(ProxyRewrite.dev1info['ProductVersion'].replace('.','_'), ProxyRewrite.dev2info['ProductVersion'].replace('.','_'))
            else:
                headers[field] = headers[field].replace(ProxyRewrite.dev1info[attrib], ProxyRewrite.dev2info[attrib])

        if headers[field] != oldval:
            print("%s: Replacing field %s: %s -> %s" % (headers['Host'], field, oldval, headers[field]))
        return headers

    @staticmethod
    def b64_rewrite_text(text, attribs):
        val = bytearray(base64.b64decode(text))
        attriblist = attribs.split(',')
        for attrib in attriblist:
            oldval = val
            # skip if attribute not in dev1info or dev2info
            if attrib not in ProxyRewrite.dev1info.keys() or attrib not in ProxyRewrite.dev2info.keys(): continue
            val = val.replace(str(ProxyRewrite.dev1info[attrib]), str(ProxyRewrite.dev2info[attrib]))
            if val != oldval:
                print("%s: Replacing %s -> %s" % (attrib, str(ProxyRewrite.dev1info[attrib]), str(ProxyRewrite.dev2info[attrib])))
        text = base64.b64encode(val)
        return text

    @staticmethod
    def b64_rewrite_header_field(headers, field, attribs):
        if field not in headers: return headers
        val = bytearray(base64.b64decode(headers[field]))
        oldval = val

        attriblist = attribs.split(',')
        for attrib in attriblist:
            # skip if attribute not in dev1info or dev2info
            if attrib not in ProxyRewrite.dev1info.keys() or attrib not in ProxyRewrite.dev2info.keys(): continue
            if str(ProxyRewrite.dev1info[attrib]) not in val: continue
            val = val.replace(str(ProxyRewrite.dev1info[attrib]), str(ProxyRewrite.dev2info[attrib]))
            if headers[field] != oldval:
                print("%s: %s Replacing %s: %s -> %s" % (headers["Host"], field, attrib, str(ProxyRewrite.dev1info[attrib]), str(ProxyRewrite.dev2info[attrib])))

        headers[field] = base64.b64encode(val)
        return headers

    @staticmethod
    def rewrite_body_attribs(body, attribs, hostname):
        oldbody = body
        attriblist = attribs.split(',')
        for attrib in attriblist:
            if attrib == 'HardwarePlatform2':
                body = body.replace(str(ProxyRewrite.dev1info['HardwarePlatform'])[1:], (str(ProxyRewrite.dev2info['HardwarePlatform'])[1:]))
            # skip if attribute not in dev1info or dev2info
            if attrib not in ProxyRewrite.dev1info.keys() or attrib not in ProxyRewrite.dev2info.keys(): continue
            body = body.replace(str(ProxyRewrite.dev1info[attrib]), str(ProxyRewrite.dev2info[attrib]))
            if str(ProxyRewrite.dev1info[attrib]).lower() in body:
                body = body.replace(str(ProxyRewrite.dev1info[attrib]).lower(), str(ProxyRewrite.dev2info[attrib]).lower())

            #if body != oldbody and ProxyRewrite.dev1info[attrib] != ProxyRewrite.dev2info[attrib]:
            print("%s: Replacing body value %s -> %s" % (hostname, str(ProxyRewrite.dev1info[attrib]), str(ProxyRewrite.dev2info[attrib])))
        return body

    @staticmethod
    def rewrite_body(body, headers, path):
        if body == None: return None

        hostname = None
        if 'Host' in headers:
            hostname = headers['Host']
            hostname = hostname.replace(':443','')
        else:
            hostname = path.split(':')[0]
            hostname = hostname.replace(':443','')

        old_body = body

        if hostname == 'xp.apple.com':
            attribs = 'ProductType,HardwareModel,HardwarePlatform,DeviceClass'
            if ProxyRewrite.rewriteOSVersion == True:
                attribs = ("%s,%s,%s" % (attribs, 'BuildVersion', 'ProductVersion'))
            body = ProxyRewrite.rewrite_body_attribs(body, attribs, hostname)
            return body
        elif hostname == 'setup.icloud.com':
            attribs = 'DeviceColor,EnclosureColor,HardwareModel,HardwarePlatform,ProductType,SerialNumber,UniqueDeviceID,TotalDiskCapacity,DeviceClass'
            if ProxyRewrite.rewriteOSVersion == True:
                attribs = ("%s,%s,%s" % (attribs, 'BuildVersion', 'ProductVersion'))
            if 'InternationalMobileEquipmentIdentity' in ProxyRewrite.dev1info:
                attribs = ("%s,%s" % (attribs, 'InternationalMobileEquipmentIdentity'))
            if 'MobileEquipmentIdentifier' in ProxyRewrite.dev1info:
                attribs = ("%s,%s" % (attribs, 'MobileEquipmentIdentifier'))
            if 'aps-token' in ProxyRewrite.dev1info and 'aps-token' in ProxyRewrite.dev2info:
                attribs = ("%s,%s" % (attribs, 'aps-token'))

            # save client-id so we can replace it with our new generated UUID
            if ProxyRewrite.changeClientID == True and 'login_or_create_account' in path:
                clientid = ProxyRewrite.save_plist_body_attrib(body, 'client-id', 'userInfo')
                if clientid != ProxyRewrite.dev2info['client-id']: ProxyRewrite.dev1info['client-id'] = clientid
            elif ProxyRewrite.changeClientID == True and 'get_account_settings' in path:
                clientid = ProxyRewrite.save_plist_body_attrib(body, 'client-id', 'userInfo')
                if clientid != ProxyRewrite.dev2info['client-id']: ProxyRewrite.dev1info['client-id'] = clientid
            elif ProxyRewrite.changeClientID == True and 'loginDelegates' in path:
                clientid = ProxyRewrite.save_plist_body_attrib(body, 'client-id', '')
                if clientid != ProxyRewrite.dev2info['client-id']: ProxyRewrite.dev1info['client-id'] = clientid

            # save the push token
            if ProxyRewrite.changePushToken == True and 'registerDevice' in path:
                pushToken = ProxyRewrite.save_plist_body_attrib(body, 'pushToken', 'deviceInfo')
                if pushToken != ProxyRewrite.dev2info['aps-token']: ProxyRewrite.dev1info['aps-token'] = pushToken
            
            # save backupDeviceUUID
            if ProxyRewrite.changeBackupDeviceUUID == True and 'registerDevice' in path:
                backupDeviceUUID = ProxyRewrite.save_plist_body_attrib(body, 'backupDeviceUUID', 'deviceInfo')
                ProxyRewrite.dev1info['backupDeviceUUID'] = backupDeviceUUID
                
            if ProxyRewrite.changeClientID == True and 'client-id' in ProxyRewrite.dev1info and 'client-id' in ProxyRewrite.dev2info:
                attribs = ("%s,%s" % (attribs, 'client-id'))

            body = ProxyRewrite.rewrite_body_attribs(body, attribs, hostname)
            return body
        elif hostname.endswith('fmf.icloud.com'):
            attribs = 'DeviceColor,EnclosureColor,HardwareModel,HardwarePlatform,ProductType,SerialNumber,UniqueDeviceID,TotalDiskCapacity,DeviceClass'
            if ProxyRewrite.rewriteOSVersion == True:
                attribs = ("%s,%s,%s" % (attribs, 'BuildVersion', 'ProductVersion'))
            if 'InternationalMobileEquipmentIdentity' in ProxyRewrite.dev1info:
                attribs = ("%s,%s" % (attribs, 'InternationalMobileEquipmentIdentity'))
            if 'MobileEquipmentIdentifier' in ProxyRewrite.dev1info:
                attribs = ("%s,%s" % (attribs, 'MobileEquipmentIdentifier'))
            if 'aps-token' in ProxyRewrite.dev1info and 'aps-token' in ProxyRewrite.dev2info:
                attribs = ("%s,%s" % (attribs, 'aps-token'))
            body = ProxyRewrite.rewrite_body_attribs(body, attribs, hostname)
            return body
        elif hostname.endswith('fmfmobile.icloud.com'):
            attribs = 'DeviceColor,EnclosureColor,ProductType,SerialNumber,UniqueDeviceID,TotalDiskCapacity,DeviceClass'
            if ProxyRewrite.rewriteOSVersion == True:
                attribs = ("%s,%s,%s" % (attribs, 'BuildVersion', 'ProductVersion'))
            if 'InternationalMobileEquipmentIdentity' in ProxyRewrite.dev1info:
                attribs = ("%s,%s" % (attribs, 'InternationalMobileEquipmentIdentity'))
            if 'MobileEquipmentIdentifier' in ProxyRewrite.dev1info:
                attribs = ("%s,%s" % (attribs, 'MobileEquipmentIdentifier'))
            if 'aps-token' in ProxyRewrite.dev1info and 'aps-token' in ProxyRewrite.dev2info:
                attribs = ("%s,%s" % (attribs, 'aps-token'))
            body = ProxyRewrite.rewrite_body_attribs(body, attribs, hostname)
            # replace meDeviceId
            d1udid_encoded = base64.b64encode(ProxyRewrite.dev1info['UniqueDeviceID'])
            d2udid_encoded = base64.b64encode(ProxyRewrite.dev2info['UniqueDeviceID'])
            body = body.replace(d1udid_encoded, d2udid_encoded)
            return body
        elif hostname.endswith('fmipmobile.icloud.com'):
            attribs = 'DeviceColor,EnclosureColor,ModelNumber,ProductType,SerialNumber,UniqueDeviceID,TotalDiskCapacity,WiFiAddress,BluetoothAddress,DeviceClass'
            if ProxyRewrite.rewriteOSVersion == True:
                attribs = ("%s,%s,%s" % (attribs, 'BuildVersion', 'ProductVersion'))
            if 'InternationalMobileEquipmentIdentity' in ProxyRewrite.dev1info:
                attribs = ("%s,%s" % (attribs, 'InternationalMobileEquipmentIdentity'))
            if 'MobileEquipmentIdentifier' in ProxyRewrite.dev1info:
                attribs = ("%s,%s" % (attribs, 'MobileEquipmentIdentifier'))
            if 'aps-token' in ProxyRewrite.dev1info and 'aps-token' in ProxyRewrite.dev2info:
                attribs = ("%s,%s" % (attribs, 'aps-token'))
            body = ProxyRewrite.rewrite_body_attribs(body, attribs, hostname)

            if ProxyRewrite.dev1info['UniqueChipID'] != ProxyRewrite.dev2info['UniqueChipID']:
                d1lenfix = (len(str(hex(ProxyRewrite.dev1info['UniqueChipID']))) - 10) + 2
                d2lenfix = (len(str(hex(ProxyRewrite.dev2info['UniqueChipID']))) - 10) + 2
                d1uid = "0x%s" % str(hex(ProxyRewrite.dev1info['UniqueChipID']))[4:]
                d2uid = str(hex(ProxyRewrite.dev2info['UniqueChipID']))
                body = body.replace(d1uid, d2uid)
                print("Replaced %s with %s\n" % (d1uid, d2uid))

            if 'fmipVersion' in ProxyRewrite.dev1info and 'fmipVersion' in ProxyRewrite.dev2info and 'fmipBuildVersion' in ProxyRewrite.dev1info and 'fmipBuildVersion' in ProxyRewrite.dev2info:
                body = ProxyRewrite.rewrite_json_body_attribs(headers, body, {"buildVersion":"fmipVersion", "appVersion":"fmipBuildVersion"}, 'clientContext')
            return body
        elif 'fmip.icloud.com' in hostname:
            body = ProxyRewrite.rewrite_json_body_attribs(headers, body, {"deviceClass":"DeviceClass","deviceColor":"DeviceColor","enclosureColor":"EnclosureColor"}, 'deviceInfo')

            # save the push token
            if ProxyRewrite.changePushToken == True and 'register' in path:
                pushToken = ProxyRewrite.save_json_body_attrib(body, 'aps-token', 'deviceInfo')
                if pushToken != '' and pushToken != ProxyRewrite.dev2info['aps-token']: ProxyRewrite.dev1info['aps-token'] = pushToken

            attribs = 'DeviceColor,EnclosureColor,HardwarePlatform,HardwarePlatform2,ModelNumber,ProductType,SerialNumber,UniqueDeviceID,TotalDiskCapacity,WiFiAddress,BluetoothAddress,DeviceClass'
            if ProxyRewrite.rewriteOSVersion == True:
                attribs = ("%s,%s,%s" % (attribs, 'BuildVersion', 'ProductVersion'))
            if 'InternationalMobileEquipmentIdentity' in ProxyRewrite.dev1info:
                attribs = ("%s,%s" % (attribs, 'InternationalMobileEquipmentIdentity'))
            if 'MobileEquipmentIdentifier' in ProxyRewrite.dev1info:
                attribs = ("%s,%s" % (attribs, 'MobileEquipmentIdentifier'))
            if 'aps-token' in ProxyRewrite.dev1info and 'aps-token' in ProxyRewrite.dev2info:
                attribs = ("%s,%s" % (attribs, 'aps-token'))
            body = ProxyRewrite.rewrite_body_attribs(body, attribs, hostname)

            content_type = headers['Content-Type']
            if 'identityV3Session' in path and content_type.startswith('application/json'):
                json_obj = json.loads(body)
                text = json_obj['collectionInfo']['data']
                json_obj['collectionInfo']['data'] = ProxyRewrite.b64_rewrite_text(json_obj['collectionInfo']['data'], attribs)
                body = json.dumps(json_obj)

            if ProxyRewrite.dev1info['UniqueChipID'] != ProxyRewrite.dev2info['UniqueChipID']:
                d1lenfix = (len(str(hex(ProxyRewrite.dev1info['UniqueChipID']))) - 10) + 2
                d2lenfix = (len(str(hex(ProxyRewrite.dev2info['UniqueChipID']))) - 10) + 2
                d1uid = "0x%s" % str(hex(ProxyRewrite.dev1info['UniqueChipID']))[4:]
                d2uid = str(hex(ProxyRewrite.dev2info['UniqueChipID']))
                body = body.replace(d1uid, d2uid)
                print("Replaced %s with %s\n" % (d1uid, d2uid))

            if 'fmipVersion' in ProxyRewrite.dev1info and 'fmipVersion' in ProxyRewrite.dev2info and 'fmipVersion' in body and 'fmipBuildVersion' in ProxyRewrite.dev1info and 'fmipBuildVersion' in ProxyRewrite.dev2info and 'fmipBuildVersion' in body:
                body = ProxyRewrite.rewrite_json_body_attribs(headers, body, {"fmipVersion":"fmipVersion", "fmipBuildVersion":"fmipBuildVersion"}, 'deviceInfo')
            return body
        elif hostname.endswith('keyvalueservice.icloud.com'):
            if ProxyRewrite.changePushToken == True and 'setAPNSToken' in path:
                pushToken = ProxyRewrite.save_plist_body_attrib(body, 'apns-token', '')
                if pushToken != ProxyRewrite.dev2info['aps-token']: ProxyRewrite.dev1info['aps-token'] = pushToken

            # replace apns-token
            if 'aps-token' in ProxyRewrite.dev1info and 'aps-token' in ProxyRewrite.dev2info:
                d1apns_encoded = base64.b64encode(str(ProxyRewrite.dev1info['aps-token']).encode())
                d2apns_encoded = base64.b64encode(str(ProxyRewrite.dev2info['aps-token']).encode())
                body = body.replace(d1apns_encoded, d2apns_encoded)
                d1apns_encoded = base64.b64encode(binascii.unhexlify(ProxyRewrite.dev1info['aps-token']))
                d2apns_encoded = base64.b64encode(binascii.unhexlify(ProxyRewrite.dev2info['aps-token']))
                body = body.replace(d1apns_encoded, d2apns_encoded)
                print("%s: replacing %s -> %s" % (hostname, d1apns_encoded, d2apns_encoded))
            return body
        elif hostname.endswith('service.gc.apple.com'):
            # replace apns-token
            if 'aps-token' in ProxyRewrite.dev1info and 'aps-token' in ProxyRewrite.dev2info:
                d1apns_encoded = base64.b64encode(str(ProxyRewrite.dev1info['aps-token']).encode())
                d2apns_encoded = base64.b64encode(str(ProxyRewrite.dev2info['aps-token']).encode())
                body = body.replace(d1apns_encoded, d2apns_encoded)
                d1apns_encoded = base64.b64encode(binascii.unhexlify(ProxyRewrite.dev1info['aps-token']))
                d2apns_encoded = base64.b64encode(binascii.unhexlify(ProxyRewrite.dev2info['aps-token']))
                body = body.replace(d1apns_encoded, d2apns_encoded)
                print("%s: replacing %s -> %s" % (hostname, d1apns_encoded, d2apns_encoded))
            return body
        elif hostname.endswith('quota.icloud.com'):
            attribs = 'DeviceColor,EnclosureColor,ProductType,SerialNumber,UniqueDeviceID,TotalDiskCapacity,DeviceClass'
            if ProxyRewrite.rewriteOSVersion == True:
                attribs = ("%s,%s,%s" % (attribs, 'BuildVersion', 'ProductVersion'))
            if 'InternationalMobileEquipmentIdentity' in ProxyRewrite.dev1info:
                attribs = ("%s,%s" % (attribs, 'InternationalMobileEquipmentIdentity'))
            if 'MobileEquipmentIdentifier' in ProxyRewrite.dev1info:
                attribs = ("%s,%s" % (attribs, 'MobileEquipmentIdentifier'))
            if 'aps-token' in ProxyRewrite.dev1info and 'aps-token' in ProxyRewrite.dev2info:
                attribs = ("%s,%s" % (attribs, 'aps-token'))
            body = ProxyRewrite.rewrite_body_attribs(body, attribs, hostname)
            return body
        elif hostname.endswith('ckdevice.icloud.com'):
            if ProxyRewrite.rewriteOSVersion == True:
                body = ProxyRewrite.rewrite_body_attribs(body, 'BuildVersion,ProductType,ProductVersion', hostname)
            else:
                body = ProxyRewrite.rewrite_body_attribs(body, 'ProductType,ProductType', hostname)
            return body
        elif hostname.endswith('ckdatabase.icloud.com'):
            if ProxyRewrite.rewriteOSVersion == True:
                body = ProxyRewrite.rewrite_body_attribs(body, 'BuildVersion,ProductType,ProductVersion', hostname)
            else:
                body = ProxyRewrite.rewrite_body_attribs(body, 'ProductType,ProductType', hostname)
            return body
        elif hostname == 'gsp10-ssl.ls.apple.com':
            if ProxyRewrite.rewriteOSVersion == True:
                body = ProxyRewrite.rewrite_body_attribs(body, 'BuildVersion,ProductType,ProductVersion', hostname)
            else:
                body = ProxyRewrite.rewrite_body_attribs(body, 'ProductType,ProductType', hostname)
            return body
        elif hostname == 'sse-ws.apple.com':
            attribs = 'DeviceClass,SerialNumber,ProductType'
            if ProxyRewrite.rewriteOSVersion == True:
                attribs = ("%s,%s,%s" % (attribs, 'BuildVersion', 'ProductVersion'))
            body = ProxyRewrite.rewrite_body_attribs(body, attribs, hostname)
            return body
        elif hostname == 'gs-loc.apple.com':
            if ProxyRewrite.rewriteOSVersion == True:
                body = ProxyRewrite.rewrite_body_attribs(body, 'BuildVersion,ProductType,ProductVersion', hostname)
            else:
                body = ProxyRewrite.rewrite_body_attribs(body, 'ProductType', hostname)
            return body
        elif hostname == 'gsp-ssl.ls.apple.com':
            if ProxyRewrite.rewriteOSVersion == True:
                body = ProxyRewrite.rewrite_body_attribs(body, 'BuildVersion,ProductType,ProductVersion', hostname)
            else:
                body = ProxyRewrite.rewrite_body_attribs(body, 'ProductType', hostname)
            return body
        elif hostname == 'gsp10-ssl.ls.apple.com':
            if ProxyRewrite.rewriteOSVersion == True:
                body = ProxyRewrite.rewrite_body_attribs(body, 'BuildVersion,ProductType,ProductVersion', hostname)
            else:
                body = ProxyRewrite.rewrite_body_attribs(body, 'HardwareModel,ProductType', hostname)
            return body
        elif hostname == 'gsp64-ssl.ls.apple.com':
            if ProxyRewrite.rewriteOSVersion == True:
                body = ProxyRewrite.rewrite_body_attribs(body, 'BuildVersion,ProductType,ProductVersion', hostname)
            else:
                body = ProxyRewrite.rewrite_body_attribs(body, 'ProductType', hostname)
            return body
        elif hostname == 'lcdn-locator.apple.com':
            if ProxyRewrite.rewriteOSVersion == True:
                body = ProxyRewrite.rewrite_body_attribs(body, 'BuildVersion,ProductType,ProductVersion', hostname)
            else:
                body = ProxyRewrite.rewrite_body_attribs(body, 'ProductType', hostname)
            return body
        elif hostname == 'tbsc.apple.com':
            attribs='ProductType,SerialNumber,UniqueDeviceID'
            if ProxyRewrite.rewriteOSVersion == True:
                attribs = ("%s,%s,%s" % (attribs, 'BuildVersion', 'ProductVersion'))
            body = ProxyRewrite.rewrite_body_attribs(body, attribs, hostname)
            return body
        elif hostname == 'gsa.apple.com':
            attribs = 'DeviceColor,EnclosureColor,ModelNumber,ProductType,SerialNumber,UniqueDeviceID,TotalDiskCapacity,HardwareModel,HardwarePlatform,DeviceClass'
            if ProxyRewrite.rewriteOSVersion == True:
                attribs = ("%s,%s,%s" % (attribs, 'BuildVersion', 'ProductVersion'))
            if 'InternationalMobileEquipmentIdentity' in ProxyRewrite.dev1info:
                attribs = ("%s,%s" % (attribs, 'InternationalMobileEquipmentIdentity'))
            if 'MobileEquipmentIdentifier' in ProxyRewrite.dev1info:
                attribs = ("%s,%s" % (attribs, 'MobileEquipmentIdentifier'))
            if 'aps-token' in ProxyRewrite.dev1info and 'aps-token' in ProxyRewrite.dev2info:
                attribs = ("%s,%s" % (attribs, 'aps-token'))
            body = ProxyRewrite.rewrite_body_attribs(body, attribs, hostname)
            return body
        elif hostname == 'gsas.apple.com':
            # save the push token
            if ProxyRewrite.changePushToken == True and 'GsService2/postdata' in path:
                pushToken = ProxyRewrite.save_plist_body_attrib(body, 'ptkn', 'Request')
                if pushToken != ProxyRewrite.dev2info['aps-token']: ProxyRewrite.dev1info['aps-token'] = pushToken
            attribs = 'DeviceColor,EnclosureColor,ModelNumber,ProductType,SerialNumber,UniqueDeviceID,TotalDiskCapacity,HardwareModel,HardwarePlatform,DeviceClass'
            if ProxyRewrite.rewriteOSVersion == True:
                attribs = ("%s,%s,%s" % (attribs, 'BuildVersion', 'ProductVersion'))
            if 'InternationalMobileEquipmentIdentity' in ProxyRewrite.dev1info:
                attribs = ("%s,%s" % (attribs, 'InternationalMobileEquipmentIdentity'))
            if 'MobileEquipmentIdentifier' in ProxyRewrite.dev1info:
                attribs = ("%s,%s" % (attribs, 'MobileEquipmentIdentifier'))
            if 'aps-token' in ProxyRewrite.dev1info and 'aps-token' in ProxyRewrite.dev2info:
                attribs = ("%s,%s" % (attribs, 'aps-token'))
            body = ProxyRewrite.rewrite_body_attribs(body, attribs, hostname)
            body = ProxyRewrite.rewrite_plist_body_attribs(headers, body, {"imei":"InternationalMobileEquipmentIdentity","meid":"MobileEquipmentIdentifier","iccid":"IntegratedCircuitCardIdentity","pn":"PhoneNumber"}, 'Request')
            return body
        elif hostname.endswith('buy.itunes.apple.com'):
            attribs = 'ProductType,SerialNumber,UniqueDeviceID,HardwareModel,HardwarePlatform,InternationalMobileEquipmentIdentity,MobileEquipmentIdentifier,UniqueDeviceID,DeviceClass'
            if ProxyRewrite.rewriteOSVersion == True:
                attribs = ("%s,%s,%s" % (attribs, 'BuildVersion', 'ProductVersion'))
            if 'aps-token' in ProxyRewrite.dev1info and 'aps-token' in ProxyRewrite.dev2info:
                attribs = ("%s,%s" % (attribs, 'aps-token'))
            body = ProxyRewrite.rewrite_body_attribs(body, attribs, hostname)
            return body
        elif hostname.endswith('identity.apple.com') and ProxyRewrite.rewriteOSVersion == True:
            body = ProxyRewrite.rewrite_body_attribs(body, 'BuildVersion,ProductVersion', hostname)
            return body
        elif hostname == 'albert.apple.com':
            attribs = 'DeviceColor,EnclosureColor,ProductType,SerialNumber,UniqueDeviceID'
            if ProxyRewrite.rewriteOSVersion == True:
                attribs = ("%s,%s,%s" % (attribs, 'BuildVersion', 'ProductVersion'))
            if 'aps-token' in ProxyRewrite.dev1info and 'aps-token' in ProxyRewrite.dev2info:
                attribs = ("%s,%s" % (attribs, 'aps-token'))
            body = ProxyRewrite.rewrite_body_attribs(body, attribs, hostname)
            return body

        return body

    @staticmethod
    def rewrite_headers(headers, path):
        hostname = None
        if 'Host' in headers:
            hostname = headers['Host']
            hostname = hostname.replace(':443','')
        else:
            hostname = path.split(':')[0]
            hostname = hostname.replace(':443','')

        #if 'fmipmobile.icloud.com' in hostname:
        #        headers['Authorization'] = 'Basic %s' % base64.b64encode('%s:%s' % (ProxyRewrite.dev2info['dsPrsID'], ProxyRewrite.dev2info['mmeAuthToken']))
        #if 'fmfmobile.icloud.com' in hostname and 'Authorization' in headers and 'Basic' in headers['Authorization']:
        #        headers['Authorization'] = 'Basic %s' % base64.b64encode('%s:%s' % (ProxyRewrite.dev2info['dsPrsID'], ProxyRewrite.dev2info['mmeAuthToken']))
        #if 'keyvalueservice.icloud.com' in hostname and 'Authorization' in headers and 'X-MobileMe-AuthToken' in headers['Authorization']:
        #        headers['Authorization'] = 'X-MobileMe-AuthToken %s' % base64.b64encode('%s:%s' % (ProxyRewrite.dev2info['dsPrsID'], ProxyRewrite.dev2info['mmeAuthToken']))

        #if 'quota.icloud.com' in hostname:
        #        headers['Authorization'] = 'Basic %s' % base64.b64encode('%s:%s' % (ProxyRewrite.dev2info['dsPrsID'], ProxyRewrite.dev2info['mmeAuthToken']))

        if hostname == 'setup.icloud.com' or hostname == 'gsa.apple.com':
            #if ('getFamilyDetails' in path or 'get_account_settings' in path) and 'dsPrsID' in ProxyRewrite.dev2info and 'mmeAuthToken' in ProxyRewrite.dev2info:
            #    headers['Authorization'] = 'Basic %s' % base64.b64encode('%s:%s' % (ProxyRewrite.dev2info['dsPrsID'], ProxyRewrite.dev2info['mmeAuthToken']))
            if 'X-Mme-Nas-Qualify' in headers:
                attribs = 'DeviceColor,EnclosureColor,ProductType,SerialNumber,TotalDiskCapacity,UniqueDeviceID,DeviceClass'
                #if ProxyRewrite.rewriteOSVersion == True:
                #    attribs = ("%s,%s,%s" % (attribs, 'BuildVersion', 'ProductVersion'))

                if 'InternationalMobileEquipmentIdentity' in ProxyRewrite.dev1info:
                    attribs = ("%s,%s" % (attribs, 'InternationalMobileEquipmentIdentity'))
                if 'MobileEquipmentIdentifier' in ProxyRewrite.dev1info:
                    attribs = ("%s,%s" % (attribs, 'MobileEquipmentIdentifier'))
                if ProxyRewrite.changePushToken == True and 'aps-token' in ProxyRewrite.dev1info and 'aps-token' in ProxyRewrite.dev2info:
                    attribs = ("%s,%s" % (attribs, 'aps-token'))
                if ProxyRewrite.changeClientID == True and 'client-id' in ProxyRewrite.dev1info and 'client-id' in ProxyRewrite.dev2info:
                    attribs = ("%s,%s" % (attribs, 'client-id'))
                headers = ProxyRewrite.b64_rewrite_header_field(headers, 'X-Mme-Nas-Qualify', attribs)
            elif 'x-mme-nas-qualify' in headers:
                attribs = 'DeviceColor,EnclosureColor,ProductType,SerialNumber,TotalDiskCapacity,UniqueDeviceID,DeviceClass'
                if 'InternationalMobileEquipmentIdentity' in ProxyRewrite.dev1info:
                    attribs = ("%s,%s" % (attribs, 'InternationalMobileEquipmentIdentity'))
                if 'MobileEquipmentIdentifier' in ProxyRewrite.dev1info:
                    attribs = ("%s,%s" % (attribs, 'MobileEquipmentIdentifier'))
                if ProxyRewrite.changePushToken == True and 'aps-token' in ProxyRewrite.dev1info and 'aps-token' in ProxyRewrite.dev2info:
                    attribs = ("%s,%s" % (attribs, 'aps-token'))
                if ProxyRewrite.changeClientID == True and 'client-id' in ProxyRewrite.dev1info and 'client-id' in ProxyRewrite.dev2info:
                    attribs = ("%s,%s" % (attribs, 'client-id'))
                headers = ProxyRewrite.b64_rewrite_header_field(headers, 'x-mme-nas-qualify', attribs)
        elif hostname.endswith('quota.icloud.com'):
            if 'X-Client-UDID' in headers:
                headers = ProxyRewrite.replace_header_field(headers, 'X-Client-UDID', 'UniqueDeviceID')
            elif 'x-client-udid' in headers:
                headers = ProxyRewrite.replace_header_field(headers, 'x-client-udid', 'UniqueDeviceID')
        elif hostname.endswith('caldav.icloud.com'):
            if ProxyRewrite.changePushToken == True and'X-Apple-DAV-Pushtoken' in headers:
                ProxyRewrite.dev1info['aps-token'] = headers['X-Apple-DAV-Pushtoken']
                if 'X-Apple-DAV-Pushtoken' in headers and 'aps-token' in ProxyRewrite.dev1info and 'aps-token' in ProxyRewrite.dev2info:
                    headers = ProxyRewrite.replace_header_field(headers, 'X-Apple-DAV-Pushtoken', 'aps-token')
                elif 'x-apple-dav-pushtoken' in headers and 'aps-token' in ProxyRewrite.dev1info and 'aps-token' in ProxyRewrite.dev2info:
                    headers = ProxyRewrite.replace_header_field(headers, 'x-apple-dav-pushtoken', 'aps-token')
        elif hostname.endswith('sharedstreams.icloud.com'):
            if 'X-Apple-Mme-Sharedstreams-Client-Token' in headers:
                if 'aps-token' in ProxyRewrite.dev1info and 'aps-token' in ProxyRewrite.dev2info:
                    headers = ProxyRewrite.rewrite_header_field(headers, 'X-Apple-Mme-Sharedstreams-Client-Token', 'aps-token,UniqueDeviceID')
                else:
                    headers = ProxyRewrite.rewrite_header_field(headers, 'X-Apple-Mme-Sharedstreams-Client-Token', 'UniqueDeviceID,UniqueDeviceID')
            elif 'x-apple-mme-sharedstreams-client-token' in headers:
                if 'aps-token' in ProxyRewrite.dev1info and 'aps-token' in ProxyRewrite.dev2info:
                    headers = ProxyRewrite.rewrite_header_field(headers, 'x-apple-mme-sharedstreams-client-token', 'aps-token,UniqueDeviceID')
                else:
                    headers = ProxyRewrite.rewrite_header_field(headers, 'x-apple-mme-sharedstreams-client-token', 'UniqueDeviceID,UniqueDeviceID')
        elif hostname.endswith('ubiquity.icloud.com'):
            if ProxyRewrite.changePushToken == True and 'X-APPLE-UB-PUSHTOKEN' in headers:
                if 'aps-token' in ProxyRewrite.dev1info and 'aps-token' in ProxyRewrite.dev2info:
                    headers = ProxyRewrite.replace_header_field(headers, 'X-APPLE-UB-PUSHTOKEN', 'aps-token')
            if 'X-Apple-Ubiquity-Device-Id' in headers:
                headers = ProxyRewrite.rewrite_header_field(headers, 'X-Apple-Ubiquity-Device-Id', 'UniqueDeviceID,UniqueDeviceID')

        if 'User-Agent' in headers:
            attribs='HardwarePlatform,ProductName,ProductType,ProductType2,DeviceClass'
            if ProxyRewrite.rewriteOSVersion == True:
                attribs = ("%s,%s,%s,%s" % (attribs, 'BuildVersion', 'ProductVersion', 'ProductVersion2'))
            headers = ProxyRewrite.rewrite_header_field(headers, 'User-Agent', attribs)
        elif 'user-agent' in headers:
            attribs='HardwarePlatform,ProductName,ProductType,ProductType2,DeviceClass'
            if ProxyRewrite.rewriteOSVersion == True:
                attribs = ("%s,%s,%s,%s" % (attribs, 'BuildVersion', 'ProductVersion', 'ProductVersion2'))
            headers = ProxyRewrite.rewrite_header_field(headers, 'user-agent', attribs)

        if 'X-MMe-Client-Info' in headers:
            if ProxyRewrite.rewriteOSVersion == True:
                headers = ProxyRewrite.rewrite_header_field(headers, 'X-MMe-Client-Info', 'BuildVersion,ProductName,ProductType,ProductVersion,HardwareModel') #,DeviceClass')
            else: headers = ProxyRewrite.rewrite_header_field(headers, 'X-MMe-Client-Info', 'ProductName,ProductType,HardwareModel')
        elif 'x-mme-client-info' in headers:
            if ProxyRewrite.rewriteOSVersion == True:
                headers = ProxyRewrite.rewrite_header_field(headers, 'x-mme-client-info', 'BuildVersion,ProductName,ProductType,ProductVersion,HardwareModel') #,DeviceClass')
            else: headers = ProxyRewrite.rewrite_header_field(headers, 'x-mme-client-info', 'ProductName,ProductType,HardwareModel')
        if 'X-Mme-Device-Id' in headers:
            headers = ProxyRewrite.replace_header_field(headers, 'X-Mme-Device-Id', 'UniqueDeviceID')
        elif 'x-mme-device-id' in headers:
            headers = ProxyRewrite.replace_header_field(headers, 'x-mme-device-id', 'UniqueDeviceID')

        if 'Device-UDID' in headers:
            headers = ProxyRewrite.replace_header_field(headers, 'Device-UDID', 'UniqueDeviceID')
        elif 'device-udid' in headers:
            headers = ProxyRewrite.replace_header_field(headers, 'device-udid', 'UniqueDeviceID')

        if 'X-AppleID-Device-Udid' in headers:
            headers = ProxyRewrite.replace_header_field(headers, 'X-AppleID-Device-Udid', 'UniqueDeviceID')
        elif 'x-appleid-device-udid' in headers:
            headers = ProxyRewrite.replace_header_field(headers, 'x-appleid-device-udid', 'UniqueDeviceID')

        if 'X-Apple-I-SRL-NO' in headers:
            headers = ProxyRewrite.replace_header_field(headers, 'X-Apple-I-SRL-NO', 'SerialNumber')
        elif 'x-apple-i-srl-no' in headers:
            headers = ProxyRewrite.replace_header_field(headers, 'x-apple-i-srl-no', 'SerialNumber')

        if 'X-Apple-Client-Info' in headers:
            if ProxyRewrite.rewriteOSVersion == True:
                headers = ProxyRewrite.rewrite_header_field(headers, 'X-Apple-Client-Info', 'BuildVersion,ProductName,ProductType,ProductVersion,DeviceClass')
            else: headers = ProxyRewrite.rewrite_header_field(headers, 'X-Apple-Client-Info', 'ProductName,ProductType,DeviceClass')
        elif 'x-apple-client-info' in headers:
            if ProxyRewrite.rewriteOSVersion == True:
                headers = ProxyRewrite.rewrite_header_field(headers, 'x-apple-client-info', 'BuildVersion,ProductName,ProductType,ProductVersion,DeviceClass')
            else: headers = ProxyRewrite.rewrite_header_field(headers, 'x-apple-client-info', 'ProductName,ProductType,DeviceClass')

        if 'X-Client-Device-Enclosure-Color' in headers:
            headers = ProxyRewrite.replace_header_field(headers, 'X-Client-Device-Enclosure-Color', 'EnclosureColor')

        if 'X-Client-Device-Color' in headers:
            headers = ProxyRewrite.replace_header_field(headers, 'X-Client-Device-Color', 'DeviceColor')
            if 'X-Client-Device-Enclosure-Color' not in headers and 'EnclosureColor' in ProxyRewrite.dev2info:
                headers['X-Client-Device-Enclosure-Color'] = ProxyRewrite.dev2info['EnclosureColor']

        if 'x-apple-translated-wo-url' in headers:
            if ProxyRewrite.rewriteOSVersion == True:
                headers = ProxyRewrite.rewrite_header_field(headers, 'x-apple-translated-wo-url', 'BuildVersion,ProductType,ProductVersion,UniqueDeviceID')
            else: headers = ProxyRewrite.rewrite_header_field(headers, 'x-apple-translated-wo-url', 'ProductType,UniqueDeviceID')

        if 'x-apple-orig-url' in headers:
            if ProxyRewrite.rewriteOSVersion == True:
                headers = ProxyRewrite.rewrite_header_field(headers, 'x-apple-orig-url', 'BuildVersion,ProductType,ProductVersion,UniqueDeviceID')
            else: headers = ProxyRewrite.rewrite_header_field(headers, 'x-apple-orig-url', 'ProductType,UniqueDeviceID')

        if 'X-Apple-MBS-Lock' in headers:
            headers = ProxyRewrite.rewrite_header_field(headers, 'X-Apple-MBS-Lock', 'UniqueDeviceID,UniqueDeviceID')
        elif 'x-apple-mbs-lock' in headers:
            headers = ProxyRewrite.rewrite_header_field(headers, 'x-apple-mbs-lock', 'UniqueDeviceID,UniqueDeviceID')

        if 'X-iTunes-User-Agent' in headers:
            if ProxyRewrite.rewriteOSVersion == True:
                headers = ProxyRewrite.rewrite_header_field(headers, 'X-iTunes-User-Agent', 'BuildVersion,HardwareModel,ProductName,ProductType,ProductVersion,DeviceClass')
            else: headers = ProxyRewrite.rewrite_header_field(headers, 'X-iTunes-User-Agent', 'HardwareModel,ProductName,ProductType,DeviceClass')

        if 'X-Apple-ATS-Cache-Key' in headers:
            if ProxyRewrite.rewriteOSVersion == True:
                headers = ProxyRewrite.rewrite_header_field(headers, 'x-apple-orig-url', 'BuildVersion,HardwarePlatform,ProductType,ProductVersion')
            else: headers = ProxyRewrite.rewrite_header_field(headers, 'x-apple-orig-url', 'HardwarePlatform,ProductType')

        if 'X-Apple-TA-Device' in headers:
            if ProxyRewrite.rewriteOSVersion == True:
                headers = ProxyRewrite.rewrite_header_field(headers, 'X-Apple-TA-Device', 'BuildVersion,ProductType,ProductVersion')
            else: headers = ProxyRewrite.rewrite_header_field(headers, 'X-Apple-TA-Device', 'ProductType')

        return headers

    @staticmethod
    def rewrite_path(headers, path):
        hostname = None
        if 'Host' in headers:
            hostname = headers['Host']
            hostname = hostname.replace(':443','')
        else:
            hostname = path.split(':')[0]

        old_path = path
        if 'dsPrsID' in ProxyRewrite.dev1info and 'dsPrsID' in ProxyRewrite.dev2info:
            path = path.replace(ProxyRewrite.dev1info['dsPrsID'], ProxyRewrite.dev2info['dsPrsID']) 

        if hostname.endswith('fmip.icloud.com'):
                path = path.replace(ProxyRewrite.dev1info['UniqueDeviceID'], ProxyRewrite.dev2info['UniqueDeviceID'])
                if path != old_path: print("replace path %s -> %s\n" % (old_path, path))
        elif hostname.endswith('fmf.icloud.com'):
                path = path.replace(ProxyRewrite.dev1info['UniqueDeviceID'], ProxyRewrite.dev2info['UniqueDeviceID'])
                if path != old_path: print("replace path %s -> %s\n" % (old_path, path))
        elif hostname.endswith('fmfmobile.icloud.com'):
                path = path.replace(ProxyRewrite.dev1info['UniqueDeviceID'], ProxyRewrite.dev2info['UniqueDeviceID'])
                if path != old_path: print("replace path %s -> %s\n" % (old_path, path))
        elif hostname.endswith('mobilebackup.icloud.com'):
                path = path.replace(ProxyRewrite.dev1info['UniqueDeviceID'], ProxyRewrite.dev2info['UniqueDeviceID'])
                if path != old_path: print("replace path %s -> %s\n" % (old_path, path))
        elif hostname.endswith('quota.icloud.com'):
                path = path.replace(ProxyRewrite.dev1info['UniqueDeviceID'], ProxyRewrite.dev2info['UniqueDeviceID'])
                if path != old_path: print("replace path %s -> %s\n" % (old_path, path))
        elif hostname.endswith('contacts.icloud.com') and 'aps-token' in ProxyRewrite.dev1info and 'aps-token' in ProxyRewrite.dev2info:
                path = path.replace(ProxyRewrite.dev1info['aps-token'], ProxyRewrite.dev2info['aps-token'])
                if path != old_path: print("replace path %s -> %s\n" % (old_path, path))
        elif hostname.endswith('caldav.icloud.com')  and 'aps-token' in ProxyRewrite.dev1info and 'aps-token' in ProxyRewrite.dev2info:
                path = path.replace(ProxyRewrite.dev1info['aps-token'], ProxyRewrite.dev2info['aps-token'])
                if path != old_path: print("replace path %s -> %s\n" % (old_path, path))
        elif hostname == 'gspe35-ssl.ls.apple.com' or hostname == 'gspe1-ssl.ls.apple.com':
            path = path.replace(ProxyRewrite.dev1info['ProductType'], ProxyRewrite.dev2info['ProductType'])
            if ProxyRewrite.rewriteOSVersion == True:
                path = path.replace(ProxyRewrite.dev1info['BuildVersion'], ProxyRewrite.dev2info['BuildVersion'])
                path = path.replace(ProxyRewrite.dev1info['ProductVersion'], ProxyRewrite.dev2info['ProductVersion'])
                if path != old_path: print("replace path %s -> %s\n" % (old_path, path))
        elif hostname == 'play.itunes.apple.com':
                path = path.replace(ProxyRewrite.dev1info['UniqueDeviceID'], ProxyRewrite.dev2info['UniqueDeviceID'])
                if path != old_path: print("replace path %s -> %s\n" % (old_path, path))
        elif hostname.endswith('buy.itunes.apple.com'):
                path = path.replace(ProxyRewrite.dev1info['UniqueDeviceID'], ProxyRewrite.dev2info['UniqueDeviceID'])
                if path != old_path: print("replace path %s -> %s\n" % (old_path, path))
        elif hostname == 'configuration.apple.com':
                #path = path.replace("9.0.plist", "10.1.plist")
                if path != old_path: print("replace path %s -> %s\n" % (old_path, path))
        elif hostname == 'gsa.apple.com':
                path = path.replace(ProxyRewrite.dev1info['UniqueDeviceID'], ProxyRewrite.dev2info['UniqueDeviceID'])
                if path != old_path: print("replace path %s -> %s\n" % (old_path, path))
        return path

    @staticmethod
    def rewrite_status(path, res):
        if 'albert.apple.com' in path and res.status == 400:
                res.status = 200
                res.reason = 'OK'
                print("replace status 400 -> 200\n")
        #elif 'setup.icloud.com' in path and status == 401:
        #        status = 200
        #        print("replace status 401 -> 200\n")
        return res

    @staticmethod
    def generate_cert(certdir, certKey, issuerCert, issuerKey, hostname, port):
        # remove 'pXX-' from hostname
        if 'icloud.com' in hostname: chostname = re.sub(r'^p\d\d-', '', hostname)
        else: chostname = hostname
        certpath = "%s/%s.crt" % (certdir.rstrip('/'), chostname)

        if os.path.isfile(certpath): return certpath

        if ProxyRewrite.is_courier_push_ip(hostname):
            hostname = "courier.push.apple.com"
        if 'icloud.com' in hostname and 'fmip.icloud.com' not in hostname and 'escrowproxy.icloud.com' not in hostname:
            srvcertname = "server_certs/icloud.com.crt"
        elif 'fmip.icloud.com' in hostname:
            srvcertname = "server_certs/fmip.icloud.com.crt"
        elif hostname == 'xp.apple.com':
            srvcertname = "server_certs/xp.apple.com.crt"
        elif 'itunes.apple.com' in hostname:
            srvcertname = "server_certs/itunes.apple.com.crt"
        elif 'escrowproxy.icloud.com' in hostname:
            srvcertname = "server_certs/escrowproxy.icloud.com.crt"
        elif 'ess.apple.com' in hostname:
            srvcertname = "server_certs/ess.apple.com.crt"
        elif hostname == "courier.push.apple.com":
            srvcertname = "server_certs/courier.push.apple.com.crt"
        elif hostname == 'apps.itunes.com':
            srvcertname = "server_certs/apps.itunes.com.crt"
        else:
            srvcertname = "%s/%s.crt" % ('server_certs', hostname)
        srvcert=None
        altnames=None

        if os.path.isfile(srvcertname):
            st_cert=open(srvcertname, 'rt').read()
            srvcert=crypto.load_certificate(crypto.FILETYPE_PEM, st_cert)
            altnames = ProxyRewrite.altnames(srvcert)
        elif re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$",hostname):
            try:
                st_cert = ssl.get_server_certificate((hostname, port))
                srvcert = crypto.load_certificate(crypto.FILETYPE_PEM, st_cert)
            except ssl.SSLError, e:
                print("get_server_certificate() failed")
                # assume that the cert they want is for courier.push.apple.com
                srvcertname = "server_certs/courier.push.apple.com.crt"
                st_cert=open(srvcertname, 'rt').read()
                srvcert = crypto.load_certificate(crypto.FILETYPE_PEM, st_cert)
            except socket.error, e:
                print("get_server_certificate() failed")
                # assume that the cert they want is for courier.push.apple.com
                srvcertname = "server_certs/courier.push.apple.com.crt"
                st_cert=open(srvcertname, 'rt').read()
                srvcert = crypto.load_certificate(crypto.FILETYPE_PEM, st_cert)

            if srvcert:
                altnames = ProxyRewrite.altnames(srvcert)

        req = crypto.X509Req()
        if srvcert:
            subject = srvcert.get_subject()
            # add in order
            for i, (a, b) in enumerate(subject.get_components()):
                if a == 'CN':
                    req.get_subject().CN = subject.CN
                elif a == 'C':
                    req.get_subject().C = subject.C
                elif a == 'OU':
                    req.get_subject().OU = subject.OU
                elif a == 'O':
                    req.get_subject().O = subject.O
        else:
            req.get_subject().CN = hostname
        req.set_pubkey(certKey)
        req.sign(certKey, "sha1")
        cert = crypto.X509()
        try:
            cert.set_serial_number(int(hashlib.md5(req.get_subject().CN.encode('utf-8')).hexdigest(), 16))
        except SSL.Error:
            epoch = int(time.time() * 1000)
            cert.set_serial_number(epoch)

        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(60 * 60 * 24 * 3650)
        cert.set_issuer(issuerCert.get_subject())
        cert.set_subject(req.get_subject())
        cert.set_pubkey(req.get_pubkey())
        #cert.set_version(2)

        #cert.add_extensions([crypto.X509Extension("authorityKeyIdentifier", critical=False, value="keyid:always", issuer=issuerCert)])

        if srvcert:
            cert.set_serial_number(int(srvcert.get_serial_number()))
            if altnames:
                print("ALTNAMES: %s\n" % altnames)
                #cert.add_extensions([crypto.X509Extension("subjectAltName", False, ", ".join(altnames))])
                cert.add_extensions([crypto.X509Extension('subjectKeyIdentifier', False, 'hash', subject=cert),
                                     crypto.X509Extension("authorityKeyIdentifier", critical=False, value="keyid:always", issuer=issuerCert)])
                for i in range(srvcert.get_extension_count()):
                     ext = srvcert.get_extension(i)
                     name = ext.get_short_name()
                     if (name != "subjectKeyIdentifier" and name != "authorityKeyIdentifier"):
                         cert.add_extensions([ext])
        else:
            cert.add_extensions([
                    crypto.X509Extension("basicConstraints", True, "CA:FALSE"),
                    crypto.X509Extension("extendedKeyUsage", True, "serverAuth"),
                    crypto.X509Extension("keyUsage", True, "keyCertSign, cRLSign"), #, digitalSignature"),
                    crypto.X509Extension('subjectKeyIdentifier', False, 'hash', subject=cert),
                    crypto.X509Extension("authorityKeyIdentifier", critical=False, value="keyid:always", issuer=issuerCert)
            ])

        cert.sign(issuerKey, "sha256")
        with open(certpath, "w") as cert_file:
            cert_file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        return certpath

    @staticmethod
    def altnames(cert):
        # tcp.TCPClient.convert_to_ssl assumes that this property only contains DNS altnames for hostname verification.
        altnames = []
        for i in range(cert.get_extension_count()):
            ext = cert.get_extension(i)
            if ext.get_short_name() == b"subjectAltName":
                try:
                    dec = decode(ext.get_data(), asn1Spec=_GeneralNames())
                except PyAsn1Error:
                    continue
                for i in dec[0]:
                    altnames.append("DNS:%s" % i[0].asOctets())
        return altnames

    @staticmethod
    def extract_certs(data):
        certs = []
        index=0

        while 1: 
            index = data.find("\x30\x82", index)
            if index < 0: break
            length = struct.unpack(">h", data[index+2:index+4])[0] + 5
            if length > len(data):
                print("Length of %d extends past end" % length)
                return
            print("index=%d, length=%d" % (index, length))
            certdata = data[index:index+length]
            certs.append(certdata)
            index = index + length
        return certs
    @staticmethod
    def rewrite_der_cert(data):
        cert=crypto.load_certificate(crypto.FILETYPE_ASN1, data)
        algtype = cert.get_signature_algorithm()
        keysize = cert.get_pubkey().bits()
        print(algtype)
        # create a new key pair
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, keysize)
        derkey = crypto.dump_privatekey(crypto.FILETYPE_PEM, key)
        cert.set_pubkey(key.get_pubkey())
        if (algtype.startswith('sha256')):
            cert.sign(key, "sha256")
        elif (algtype.startswith('sha1')):
            cert.sign(key, "sha1")
        dercert = crypto.dump_certificate(crypto.FILETYPE_ASN1, cert)
        #derkey = crypto.dump_privatekey(crypto.FILETYPE_ASN1, key)
        return dercert

    @staticmethod
    def locationdDecode(body):
        print(repr(body))
        data = bytes(body)
        pos = 0
        instruct = False
        while pos < len(data):
            if data[pos] == '\x00':
                if data[pos+1] == '\x01':
                    if instruct == False:
                        instruct = True
                        print('{')
                    else:
                        print('}')
                        instruct = False
                elif data[pos+1] == '\x00':
                    #dont do anything
                    print("")
                else:
                    datalen=ord(data[pos+1])
                    # this is some kind of substruct 0x12 0x13 0x0A 0x11
                    if data[pos+2] == '\x12':
                        print("DATA1_START")
                        while pos < len(data):
                            pos = pos + 4
                            datalen=ord(data[pos+1])
                            print(str(data[pos+1:pos+1+datalen]))
                    elif data[pos+2] == '\n':
                        print("DATA2_START")
                        pos = pos + 3
                        datalen=ord(data[pos])
                        pos = pos + 1
                        print(binascii.hexlify(data[pos:pos+datalen]))
                        pos = pos + datalen
                    else:
                        print(str(data[pos+2:pos+2+datalen]))
                        pos = pos + datalen
                pos = pos + 2
