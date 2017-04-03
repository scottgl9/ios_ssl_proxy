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


# NOTE: these are special case hostnames where the cert forging isn't working correctly:
# gsa.apple.com, gsas.apple.com, and p**-fmip.icloud.com (such as p51-fmip.icloud.com)_


def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname[:15])
    )[20:24])

def with_color(c, s):
    return "\x1b[%dm%s\x1b[0m" % (c, s)

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

class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    # lets use IPv4 instead of IPv6
    #address_family = socket.AF_INET6
    address_family = socket.AF_INET
    daemon_threads = True

    def handle_error(self, request, client_address):
        # surpress socket/ssl related errors
        cls, e = sys.exc_info()[:2]
        if cls is socket.error or cls is ssl.SSLError:
            pass
        else:
            return HTTPServer.handle_error(self, request, client_address)


class ProxyRewrite:
    dev1info = dict()
    dev2info = dict()
    logger = None
    transparent = False
    changeClientID = False
    changePushToken = False
    rewriteOSVersion = True
    jailbroken = False
    singlelogfile = False
    apnscnt = 0
    server_address = None

    @staticmethod
    def load_device_info(sn):
        if '.xml' in sn:
            device = plistlib.readPlist(sn)
        else:
            device = plistlib.readPlist("devices/%s.xml" % sn)
        return device

    @staticmethod
    def intercept_this_host(hostname):
        # always intercept IP addresses
        isip=re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$",hostname)
        if isip: return True
        if 'spcsdns.net' in hostname or 'sprint.com' in hostname: return True
        if "apple.com" not in hostname and "icloud.com" not in hostname and 'apple-cloudkit.com' not in hostname and 'apple-cdn.com' not in hostname: return False
        hostname = hostname.replace(':443','')

        # this means sslkill2 isn't installed
        if ProxyRewrite.jailbroken == False:
            if 'fmip.icloud.com' in hostname: return False
            if 'itunes.apple.com' in hostname: return False
            if hostname == "gsa.apple.com": return False
            if hostname == "gsas.apple.com": return False

        if hostname == "ppq.apple.com": return False
        #if hostname == "albert.apple.com": return False
        #if hostname == "static.ips.apple.com": return False
        #if hostname == "captive.apple.com": return False
        return True

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

    @staticmethod
    def rewrite_plist_body_activation(headers, text):
        print(headers)
        if headers['Content-Type'] == 'application/x-plist': return
        elif headers['Content-Type'] == 'application/xml': return
        text = text[text.find('<?xml'):text.find('</plist>')+8]
        boundary = headers['Content-Type'].split('=')[1]
        print("Boundary = %s" % boundary)
        p = plistlib.readPlistFromString(text)
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

        else:
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

            d1lenfix = (len(str(hex(ProxyRewrite.dev1info['UniqueChipID']))) - 10) + 2
            d2lenfix = (len(str(hex(ProxyRewrite.dev2info['UniqueChipID']))) - 10) + 2
            d1uid = "0x%s" % str(hex(ProxyRewrite.dev1info['UniqueChipID']))[d1lenfix:]
            d2uid = "0x%s" % str(hex(ProxyRewrite.dev2info['UniqueChipID']))[d2lenfix:]
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

            d1lenfix = (len(str(hex(ProxyRewrite.dev1info['UniqueChipID']))) - 10) + 2
            d2lenfix = (len(str(hex(ProxyRewrite.dev2info['UniqueChipID']))) - 10) + 2
            d1uid = "0x%s" % str(hex(ProxyRewrite.dev1info['UniqueChipID']))[d1lenfix:]
            d2uid = "0x%s" % str(hex(ProxyRewrite.dev2info['UniqueChipID']))[d2lenfix:]
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

        #if 'X-Apple-ADSID' in headers and 'ADSID' in ProxyRewrite.dev1info and 'ADSID' in ProxyRewrite.dev2info:
        #    headers = ProxyRewrite.replace_header_field(headers, 'X-Apple-ADSID', 'ADSID')

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
    def rewrite_status(path, status):
        #if 'appleid.apple.com' in path and status == 401:
        #        status = 200
        #        print("replace status 401 -> 200\n")
        #elif 'setup.icloud.com' in path and status == 401:
        #        status = 200
        #        print("replace status 401 -> 200\n")
        return status

    @staticmethod
    def generate_cert(certdir, certKey, issuerCert, issuerKey, hostname, port):
        # remove 'pXX-' from hostname
        if 'icloud.com' in hostname: chostname = re.sub(r'^p\d\d-', '', hostname)
        else: chostname = hostname
        certpath = "%s/%s.crt" % (certdir.rstrip('/'), chostname)

        if os.path.isfile(certpath): return certpath

        if '17.249.60.9' in hostname or '17.188.167.212' in hostname or '17.188.162.92' in hostname:
            hostname = "courier.push.apple.com"

        if 'icloud.com' in hostname and 'fmip.icloud.com' not in hostname and 'escrowproxy.icloud.com' not in hostname:
            srvcertname = "server_certs/icloud.com.crt"
        elif 'fmip.icloud.com' in hostname:
            srvcertname = "server_certs/fmip.icloud.com.crt"
        elif 'itunes.apple.com' in hostname:
            srvcertname = "server_certs/itunes.apple.com.crt"
        elif 'escrowproxy.icloud.com' in hostname:
            srvcertname = "server_certs/escrowproxy.icloud.com.crt"
        elif 'ess.apple.com' in hostname:
            srvcertname = "server_certs/ess.apple.com.crt"
        elif hostname == "courier.push.apple.com":
            srvcertname = "server_certs/courier.push.apple.com.crt"
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

        cert.add_extensions([
            crypto.X509Extension("basicConstraints", True, "CA:FALSE"),
            #crypto.X509Extension("nsCertType", True, "sslCA"),
            crypto.X509Extension("extendedKeyUsage", True, "serverAuth"),
            crypto.X509Extension("keyUsage", True, "keyCertSign, cRLSign"), #, digitalSignature"),
            crypto.X509Extension('subjectKeyIdentifier', False, 'hash', subject=cert)
        ])

        #cert.add_extensions([crypto.X509Extension("authorityKeyIdentifier", critical=False, value="keyid:always", issuer=cert)])

        if srvcert:
            cert.set_serial_number(int(srvcert.get_serial_number()))
            if altnames:
                print("ALTNAMES: %s\n" % altnames)
                cert.add_extensions([crypto.X509Extension("subjectAltName", False, ", ".join(altnames))])

                for i in range(srvcert.get_extension_count()):
                     ext = srvcert.get_extension(i)
                     print(ext.get_short_name())
                     if (ext.get_short_name() == 'UNDEF' or ext.get_short_name() == 'ct_precert_scts'):
                         print("Adding %s to cert" % ext.get_short_name())
                         cert.add_extensions([ext])

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

class ProxyRequestHandler(BaseHTTPRequestHandler):
    cakey = 'ca.key'
    cacert = 'ca.crt'
    certkey = 'cert.key'
    certdir = 'certs/'
    timeout = 5
    lock = threading.Lock()
    certKey=None
    issuerCert=None
    issuerKey=None

    def __init__(self, *args, **kwargs):
        self.tls = threading.local()
        self.tls.conns = {}

        self.certKey=crypto.load_privatekey(crypto.FILETYPE_PEM, open(self.certkey, 'rt').read())
        self.issuerCert=crypto.load_certificate(crypto.FILETYPE_PEM, open(self.cacert, 'rt').read())
        self.issuerKey=crypto.load_privatekey(crypto.FILETYPE_PEM, open(self.cakey, 'rt').read())

        BaseHTTPRequestHandler.__init__(self, *args, **kwargs)

    def log_error(self, format, *args):
        # surpress "Request timed out: timeout('timed out',)"
        if isinstance(args[0], socket.timeout):
            return

        self.log_message(format, *args)

    # hack to handle so that we can ignore certain hostnames
    def handle(self):
        SO_ORIGINAL_DST = 80
        dst = self.request.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16) # Get the original destination IP before iptables redirect
        _, dst_port, ip1, ip2, ip3, ip4 = struct.unpack("!HHBBBB8x", dst)
        dst_ip = '%s.%s.%s.%s' % (ip1,ip2,ip3,ip4)
        peername = '%s:%s' % (self.request.getpeername()[0], self.request.getpeername()[1])
        print('Client %s -> %s:%s' % (peername, dst_ip, dst_port))
        # use transparent mode
        if ProxyRewrite.transparent == True and dst_port != 80 and dst_port != 5223:
            with self.lock:
                certpath = ProxyRewrite.generate_cert(self.certdir, self.certKey, self.issuerCert, self.issuerKey, dst_ip, dst_port)
            try:
                self.connection = ssl.wrap_socket(self.connection, keyfile=self.certkey, certfile=certpath, ssl_version=ssl.PROTOCOL_TLSv1_2, server_side=True, do_handshake_on_connect=True, suppress_ragged_eofs=True)
            except ssl.SSLError as e:
                try:
                    ssl._https_verify_certificates(enable=False)
                    self.connection = ssl.wrap_socket(self.connection, keyfile=self.certkey, certfile=certpath, ssl_version=ssl.PROTOCOL_TLSv1_2, server_side=True, do_handshake_on_connect=False, suppress_ragged_eofs=True)
                except ssl.SSLError as e:
                    print("SSLError occurred on %s: %r" % (dst_ip,e))
                    self.finish()
        elif ProxyRewrite.server_address != dst_ip and dst_port == 443:
            print("Handling %s:%s" % (dst_ip, dst_port))
            with self.lock:
                certpath = ProxyRewrite.generate_cert(self.certdir, self.certKey, self.issuerCert, self.issuerKey, dst_ip, dst_port)
            try:
                self.connection = ssl.wrap_socket(self.connection, keyfile=self.certkey, certfile=certpath, ssl_version=ssl.PROTOCOL_TLSv1_2, server_side=True, do_handshake_on_connect=True, suppress_ragged_eofs=True)
            except ssl.SSLError as e:
                try:
                    ssl._https_verify_certificates(enable=False)
                    self.connection = ssl.wrap_socket(self.connection, keyfile=self.certkey, certfile=certpath, ssl_version=ssl.PROTOCOL_TLSv1_2, server_side=True, do_handshake_on_connect=False, suppress_ragged_eofs=True)
                except ssl.SSLError as e:
                    print("SSLError occurred on %s: %r" % (dst_ip,e))
                    self.finish()

        self.rfile = self.connection.makefile("rb", self.rbufsize)
        self.wfile = self.connection.makefile("wb", self.wbufsize)

        if dst_port == 5223:
            data = self.connection.recv(4096)
            print(str(data))
            self.connection.sendall(data)
            with self.lock:
                certpath = ProxyRewrite.generate_cert(self.certdir, dst_ip, dst_port)
                certpath = ProxyRewrite.generate_cert(self.certdir, self.certKey, self.issuerCert, self.issuerKey, dst_ip, dst_port)
            try:
                self.connection = ssl.wrap_socket(self.connection, keyfile=self.certkey, certfile=certpath, ssl_version=ssl.PROTOCOL_TLSv1_2, server_side=True, do_handshake_on_connect=False, suppress_ragged_eofs=True)
            except ssl.SSLError as e:
                print("SSLError occurred on %s: %r" % (dst_ip,e))
            #self.wfile.flush()
            #self.finish()
            return

        #    """Handle multiple requests if necessary."""
        self.close_connection = 1
        self.handle_one_request()
        while not self.close_connection:
            self.handle_one_request()

    def handle_one_request(self):
        try:
            self.raw_requestline = self.rfile.readline(65537)
            if len(self.raw_requestline) > 65536:
                self.requestline = ''
                self.request_version = ''
                self.command = ''
                self.send_error(414)
                return
            if not self.raw_requestline:
                self.close_connection = 1
                return
            if re.search("CONNECT|OPTIONS|GET|HEAD|POST|PUT|DELETE|MKCOL|MOVE|REPORT|PROPFIND|PROPPATCH|ORDERPATCH", self.raw_requestline) is None:
                self.wfile.flush()
                return
            if not self.parse_request():
                # An error code has been sent, just exit
                #self.close_connection = 1
                return
            mname = 'do_' + self.command
            if not hasattr(self, mname):
                self.do_GET()
            else:
                method = getattr(self, mname)
                method()
            self.wfile.flush() #actually send the response if not already done.
        except socket.timeout, e:
            #a read or a write timed out.  Discard this connection
            self.log_error("Request timed out: %r", e)
            self.close_connection = 1
            return

    def do_CONNECT(self):
        hostname = self.path.split(':')[0]
        print("CONNECT %s" % hostname)

        if 'Proxy-Connection' in self.headers:
            del self.headers['Proxy-Connection']

        if ProxyRewrite.dev1info != None and ProxyRewrite.dev2info != None:
            self.headers = ProxyRewrite.rewrite_headers(self.headers, '')

        #if 'captive.apple.com' in self.path or 'static.ips.apple.com' in self.path:
        #    self.path = 'http://ui.iclouddnsbypass.com/deviceservices/buddy/barney_activation_help_en_us.buddyml'
        #    self.connect_intercept()
        if os.path.isfile(self.cakey) and os.path.isfile(self.cacert) and os.path.isfile(self.certkey) and os.path.isdir(self.certdir) and ProxyRewrite.intercept_this_host(hostname):
            self.connect_intercept()
        else:
            self.connect_relay()

    def connect_intercept(self):
        hostname = None
        if 'Host' in self.headers:
            hostname = self.headers['Host']
        else:
            hostname = self.path.split(':')[0]

        with self.lock:
            certpath = ProxyRewrite.generate_cert(self.certdir, self.certKey, self.issuerCert, self.issuerKey, hostname, 443)

        self.wfile.write("%s %d %s\r\n" % (self.protocol_version, 200, 'Connection Established'))
        self.end_headers()

        try:
            ssl._https_verify_certificates(enable=False)
            self.connection = ssl.wrap_socket(self.connection, keyfile=self.certkey, certfile=certpath, ssl_version=ssl.PROTOCOL_TLSv1_2, server_side=True, do_handshake_on_connect=False, suppress_ragged_eofs=True)
        except ssl.SSLError as e:
            print("SSLError occurred on %s: %r" % (self.path,e))
            try:
                ssl._https_verify_certificates(enable=False)
                self.connection = ssl.wrap_socket(self.connection, keyfile=self.certkey, certfile=certpath, ssl_version=ssl.PROTOCOL_TLSv1_2, server_side=True, do_handshake_on_connect=True, suppress_ragged_eofs=True)
            except ssl.SSLError as e:
                print("SSLError occurred on %s: %r" % (self.path,e))
                self.finish()

        self.rfile = self.connection.makefile("rb", self.rbufsize)
        self.wfile = self.connection.makefile("wb", self.wbufsize)

        conntype = self.headers.get('Connection', '')
        if self.protocol_version == "HTTP/1.1" and conntype.lower() != 'close':
            self.close_connection = 0
        else:
            self.close_connection = 1

    def connect_relay(self):
        address = self.path.split(':', 1)
        address[1] = int(address[1]) or 443
        try:
            s = socket.create_connection(address, timeout=self.timeout)
        except Exception as e:
            self.send_error(502)
            return
        self.send_response(200, 'Connection Established')
        self.end_headers()

        conns = [self.connection, s]
        self.close_connection = 0
        while not self.close_connection:
            rlist, wlist, xlist = select.select(conns, [], conns, self.timeout)
            if xlist or not rlist:
                break
            for r in rlist:
                other = conns[1] if r is conns[0] else conns[0]
                data = r.recv(8192)
                if not data:
                    self.close_connection = 1
                    break
                other.sendall(data)

    def do_GET(self):
        if self.path == 'http://proxy2.test/':
            self.send_cacert(self.cacert)
            return
        elif self.path == 'http://proxy2.test/gsa':
            self.send_cacert('certs/gsa.apple.com.crt')
        elif self.path == 'http://proxy2.test/fmip':
            self.send_cacert('certs/p15-fmip.icloud.com.crt')

        #elif 'captive.apple.com' in self.path:
        #    self.path = 'http://ui.iclouddnsbypass.com/deviceservices/buddy/barney_activation_help_en_us.buddyml'

        req = self
        content_length = int(req.headers.get('Content-Length', 0))
        req_body = self.rfile.read(content_length) if content_length else None

        if req.path[0] == '/':
            if isinstance(self.connection, ssl.SSLSocket):
                req.path = "https://%s%s" % (req.headers['Host'], req.path)
            else:
                req.path = "http://%s%s" % (req.headers['Host'], req.path)

        # rewrite URL path if needed
        req.path = ProxyRewrite.rewrite_path(req.headers, req.path)

        req_body_modified = self.request_handler(req, req_body)
        if req_body_modified is False:
            self.send_error(403)
            return
        elif req_body_modified is not None:
            req_body = req_body_modified
            req.headers['Content-length'] = str(len(req_body))

        u = urlparse.urlsplit(req.path)
        scheme, netloc, path = u.scheme, u.netloc, (u.path + '?' + u.query if u.query else u.path)
        assert scheme in ('http', 'https')
        if netloc:
            if ':' in netloc: netloc = netloc.split(':')[0]
            req.headers['Host'] = netloc

        setattr(req, 'headers', self.filter_headers(req.headers))

        # fix for \r\n being replaced with \n when updating a header field
        for index in range(len(req.headers.headers)):
            if "\r" not in req.headers.headers[index]: req.headers.headers[index] = req.headers.headers[index].replace("\n", "\r\n")

        try:
            origin = (scheme, netloc)
            if not origin in self.tls.conns:
                if scheme == 'https':
                    self.tls.conns[origin] = httplib.HTTPSConnection(netloc, timeout=self.timeout)
                else:
                    self.tls.conns[origin] = httplib.HTTPConnection(netloc, timeout=self.timeout)
            conn = self.tls.conns[origin]
            conn.request(self.command, path, req_body, dict(req.headers))
            res = conn.getresponse()

            version_table = {10: 'HTTP/1.0', 11: 'HTTP/1.1'}
            setattr(res, 'headers', res.msg)
            # sets response_version *FIXME* check if this value is None, if so then do not send
            setattr(res, 'response_version', version_table[res.version])

            # support streaming
            if (not 'Content-Length' in res.headers and res.headers.get('Cache-Control') and 'no-store' in res.headers.get('Cache-Control')):
                self.response_handler(req, req_body, res, '')
                setattr(res, 'headers', self.filter_headers(res.headers))
                self.relay_streaming(res)
                with self.lock:
                    self.save_handler(req, req_body, res, '')
                return

            res_body = res.read()
        except Exception as e:
            self.log_error("do_GET() Exception: %r", e)
            if origin in self.tls.conns:
                del self.tls.conns[origin]
                #self.send_error(502)
            return

        content_encoding = res.headers.get('Content-Encoding', 'identity')
        res_body_plain = self.decode_content_body(res_body, content_encoding)

        res_body_modified = self.response_handler(req, req_body, res, res_body_plain)
        if res_body_modified is False:
            self.send_error(403)
            return
        elif res_body_modified is not None:
            res_body_plain = res_body_modified
            res_body = self.encode_content_body(res_body_plain, content_encoding)
            res.headers['Content-Length'] = str(len(res_body))

        setattr(res, 'headers', self.filter_headers(res.headers))

        self.wfile.write("%s %d %s\r\n" % (self.protocol_version, res.status, res.reason))
        for line in res.headers.headers:
            self.wfile.write(line)
        self.end_headers()
        self.wfile.write(res_body)
        self.wfile.flush()

        with self.lock:
            self.save_handler(req, req_body, res, res_body_plain)

    def relay_streaming(self, res):
        self.wfile.write("%s %d %s\r\n" % (self.protocol_version, res.status, res.reason))
        for line in res.headers.headers:
            self.wfile.write(line)
        self.end_headers()
        try:
            while True:
                chunk = res.read(8192)
                if not chunk:
                    break
                self.wfile.write(chunk)
            self.wfile.flush()
        except socket.error:
            # connection closed by client
            pass

    do_HEAD = do_GET
    do_POST = do_GET

    # handle all weird http requests used by apple servers
    do_PUT = do_GET
    do_DELETE = do_GET
    do_OPTIONS = do_GET
    do_MKCOL = do_GET
    do_MOVE = do_GET
    do_REPORT = do_GET
    do_PROPFIND = do_GET
    do_PROPPATCH = do_GET
    do_ORDERPATCH = do_GET

    def filter_headers(self, headers):
        # http://tools.ietf.org/html/rfc2616#section-13.5.1
        hop_by_hop = ('connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailers', 'transfer-encoding', 'upgrade', 'Proxy-Connection')
        for k in hop_by_hop:
            del headers[k]

        # accept only supported encodings
        if 'Accept-Encoding' in headers:
            ae = headers['Accept-Encoding']
            filtered_encodings = [x for x in re.split(r',\s*', ae) if x in ('identity', 'gzip', 'x-gzip', 'deflate')]
            # FIX for 'None' appearing on the line after Accept-Encoding
            headers['Accept-Encoding'] = ', '.join(filtered_encodings)

        return headers

    def encode_content_body(self, text, encoding):
        if encoding == 'identity':
            data = text
        elif encoding in ('gzip', 'x-gzip', 'x-compress'):
            io = StringIO()
            with gzip.GzipFile(fileobj=io, mode='wb') as f:
                f.write(text)
            data = io.getvalue()
        elif encoding == 'deflate':
            data = zlib.compress(text)
        else:
            raise Exception("Unknown Content-Encoding: %s" % encoding)
        return data

    def decode_content_body(self, data, encoding):
        if encoding == 'identity':
            text = data
        elif encoding in ('gzip', 'x-gzip', 'x-compress'):
            try:
                io = StringIO(data)
                with gzip.GzipFile(fileobj=io) as f:
                    text = f.read()
            except IOError:
                return data
        elif encoding == 'deflate':
            try:
                text = zlib.decompress(data)
            except zlib.error:
                text = zlib.decompress(data, -zlib.MAX_WBITS)
        else:
            raise Exception("Unknown Content-Encoding: %s" % encoding)
        return text

    def send_cacert(self, path):
        with open(path, 'rb') as f:
            data = f.read()

        self.wfile.write("%s %d %s\r\n" % (self.protocol_version, 200, 'OK'))
        self.send_header('Content-Type', 'application/x-x509-ca-cert')
        self.send_header('Content-Length', len(data))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(data)

    def print_info(self, req, req_body, res, res_body):
        #if 'ckdatabase.icloud.com' in req.path or 'ckdevice.icloud.com' in req.path or 'caldav.icloud.com' in req.path: return

        def parse_qsl(s):
            return '\n'.join("%-20s %s" % (k, v) for k, v in urlparse.parse_qsl(s, keep_blank_values=True))

        req_header_text = "%s %s %s\n%s" % (req.command, req.path, req.request_version, req.headers)
        res_header_text = "%s %d %s\n%s" % (res.response_version, res.status, res.reason, res.headers)

        print with_color(33, req_header_text)

        u = urlparse.urlsplit(req.path)
        if u.query:
            query_text = parse_qsl(u.query)
            print with_color(32, "==== QUERY PARAMETERS ====\n%s\n" % query_text)

        cookie = req.headers.get('Cookie', '')
        if cookie:
            cookie = parse_qsl(re.sub(r';\s*', '&', cookie))
            print with_color(32, "==== COOKIE ====\n%s\n" % cookie)

        auth = req.headers.get('Authorization', '')
        if auth.lower().startswith('basic'):
            token = auth.split()[1].decode('base64')
            print with_color(31, "==== BASIC AUTH ====\n%s\n" % token)

        if req_body is not None:
            req_body_text = None
            content_type = req.headers.get('Content-Type', '')

            if content_type.startswith('application/x-www-form-urlencoded'):
                req_body_text = parse_qsl(req_body)
            elif content_type.startswith('application/json'):
                try:
                    json_obj = json.loads(req_body)
                    json_str = json.dumps(json_obj, indent=2)
                    if json_str.count('\n') < 50 or 'fmip.icloud.com' in req.path or 'fmf.icloud.com' in req.path or 'fmipmobile.icloud.com' in req.path:
                        req_body_text = json_str
                    else:
                        lines = json_str.splitlines()
                        req_body_text = "%s\n(%d lines)" % ('\n'.join(lines[:50]), len(lines))
                except ValueError:
                    req_body_text = req_body
            elif len(req_body) < 1024:
                req_body_text = req_body

            if req_body_text:
                print with_color(32, "==== REQUEST BODY ====\n%s\n" % req_body_text)

        print with_color(36, res_header_text)

        cookies = res.headers.getheaders('Set-Cookie')
        if cookies:
            cookies = '\n'.join(cookies)
            print with_color(31, "==== SET-COOKIE ====\n%s\n" % cookies)

        if res_body is not None:
            res_body_text = None
            content_type = res.headers.get('Content-Type', '')

            if content_type.startswith('application/json'):
                try:
                    json_obj = json.loads(res_body)
                    json_str = json.dumps(json_obj, indent=2)
                    if json_str.count('\n') < 50:
                        res_body_text = json_str
                    else:
                        lines = json_str.splitlines()
                        res_body_text = "%s\n(%d lines)" % ('\n'.join(lines[:50]), len(lines))
                except ValueError:
                    res_body_text = res_body
            elif content_type.startswith('text/html'):
                m = re.search(r'<title[^>]*>\s*([^<]+?)\s*</title>', res_body, re.I)
                if m:
                    h = HTMLParser()
                    print with_color(32, "==== HTML TITLE ====\n%s\n" % h.unescape(m.group(1).decode('utf-8')))
            elif content_type.startswith('text/') and len(res_body) < 1024:
                res_body_text = res_body

            if res_body_text:
                print with_color(32, "==== RESPONSE BODY ====\n%s\n" % res_body_text)

    def request_handler(self, req, req_body):
        # can probably modify headers here:
        req.headers = ProxyRewrite.rewrite_headers(req.headers, req.path)
        # rewrite URL path if needed
        req.path = ProxyRewrite.rewrite_path(req.headers, req.path)

        # should be able to safely modify body here:
        req_body_plain = req_body
        if 'Content-Encoding' in req.headers and req.headers['Content-Encoding'] == 'gzip' and 'Content-Length' in req.headers and req.headers['Content-Length'] > 0 and len(str(req_body)) > 0:
            content_encoding = req.headers.get('Content-Encoding', 'identity')
            req_body_plain = self.decode_content_body(str(req_body), content_encoding)

        if 'albert.apple.com' in req.path and 'deviceActivation' in req.path:
             req_body_plain = ProxyRewrite.rewrite_plist_body_activation(req.headers, req_body_plain)
        #elif 'captive.apple.com' in req.path:
        #        req.path = 'http://ui.iclouddnsbypass.com/deviceservices/buddy/barney_activation_help_en_us.buddyml'
        #        req.headers['Host'] = 'ui.icloudbypass.com'

        req_body_modified = ProxyRewrite.rewrite_body(req_body_plain, req.headers, req.path)

        if req_body_modified != req_body_plain and 'Content-Encoding' in req.headers and req.headers['Content-Encoding'] == 'gzip' and 'Content-Length' in req.headers and req.headers['Content-Length'] > 0 and len(str(req_body_modified)) > 0:
            content_encoding = req.headers.get('Content-Encoding', 'identity')
            req_body_modified = self.encode_content_body(str(req_body_modified), content_encoding)

        return req_body_modified

    def response_handler(self, req, req_body, res, res_body):
        if 'Host' in req.headers and ('init-p01st.push.apple.com' in req.headers['Host'] or 'init-p01md.push.apple.com' in req.headers['Host']):
            # handle setting certs so we can use our own keybag
            p = plistlib.readPlistFromString(res_body)
            #print("Certs for %s" % req.headers['Host'])
            cert0 = base64.b64encode(p['certs'][0].data)
            cert1 = base64.b64encode(p['certs'][1].data)
            bag = p['bag'].data
            origsignature = base64.b64encode(p['signature'].data)
            #print(cert0)
            #print(cert1)
            with self.lock:
                certpath = ProxyRewrite.generate_cert(self.certdir, self.certKey, self.issuerCert, self.issuerKey, req.headers['Host'], 443)
            st_cert=open(certpath, 'rt').read()
            certdata = base64.b64encode(ssl.PEM_cert_to_DER_cert(st_cert))
            res_body = res_body.replace(cert0, certdata)
            st_cert=open(self.cacert, 'rt').read()
            certdata = base64.b64encode(ssl.PEM_cert_to_DER_cert(st_cert))
            res_body = res_body.replace(cert1, certdata)
            newsignature = base64.b64encode(crypto.sign(self.certKey, bag, 'sha1'))
            res_body = res_body.replace(origsignature, newsignature)
            print("Replaced %s with %s" % (origsignature, newsignature))
            #p['certs'][0] = certdata
            #p['certs'][1] = ssl.PEM_cert_to_DER_cert(st_cert)
            #res_body = plistlib.writePlistToString(p)
            print(res_body)
        elif 'Host' in req.headers and 'init.ess.apple.com' in req.headers['Host']:
            # handle setting certs so we can intercept profile.ess.apple.com
            p = plistlib.readPlistFromString(res_body)
            print("Certs for %s" % req.headers['Host'])
            print(p['certs'][0])
            print(p['certs'][1])

        #    if os.path.isfile("certs/init-p01st.push.apple.com.crt"):
        #        st_cert=open("certs/init-p01st.push.apple.com.crt", 'rt').read()
        #        p['certs'][0] = ssl.PEM_cert_to_DER_cert(st_cert)

        #if 'captive.apple.com' in req.path:
        #    if 'hotspot-detect.html' in req.path:
        #        r = requests.get('http://ui.iclouddnsbypass.com/deviceservices/buddy/barney_activation_help_en_us.buddyml')
        #        res_body = r.text
        #        res.headers['Content-Length'] = str(len(r.text))
        # rewrite response status
        #res.status = ProxyRewrite.rewrite_status(req.path, res.status)
        #if 'setup.icloud.com/configurations/init?context=settings' in self.path or 'setup.icloud.com/setup/get_account_settings' in self.path:
            #res_body = ProxyRewrite.replace_hostname_body(res_body, 'fmip.icloud.com', 'fmiptest.icloud.com')
            # Attempt to replace gsa.apple.com to use a different server
            #res_body = res_body.replace('gsa.apple.com', 'gsa-nc1.apple.com')
            #print("setup.icloud.com: Replaced gsa.apple.com -> gsa-nc1.apple.com")
        #if 'setup.icloud.com/setup/get_account_settings' in self.path:
        return res_body

    def save_handler(self, req, req_body, res, res_body):
        hostname = None
        if 'Host' in req.headers:
            hostname = req.headers['Host']
        else:
            hostname = self.path.split(':')[0]

        # ignore saving binary data we don't care about, also don't save bookmarks because the logfile will continuously group
        if 'setup.icloud.com/setup/qualify/cert' in self.path: return
        if 'setup.icloud.com/setup/account/getPhoto' in self.path or 'setup.icloud.com/setup/family/getMemberPhoto' in self.path: return
        if 'bookmarks.icloud.com' in hostname: return
        if self.path.endswith(".png"): return
        elif self.path.endswith(".jpeg"): return
        elif self.path.endswith(".gz"): return

        if 'icloud.com' in hostname or 'apple.com' in hostname:
            req_body_plain = req_body
            if 'Content-Encoding' in req.headers and req.headers['Content-Encoding'] == 'gzip' and 'Content-Length' in req.headers and req.headers['Content-Length'] > 0 and len(str(req_body)) > 0:
                content_encoding = req.headers.get('Content-Encoding', 'identity')
                req_body_plain = self.decode_content_body(str(req_body), content_encoding)

            if 'ckdatabase.icloud.com' in req.path or 'ckdevice.icloud.com' in req.path or 'caldav.icloud.com' in req.path: 
                req_header_text = "%s %s %s" % (req.command, req.path, req.request_version)
                res_header_text = "%s %d %s\n" % (res.response_version, res.status, res.reason)
                print with_color(33, req_header_text)
                print with_color(32, res_header_text)
            else:
                self.print_info(req, req_body_plain, res, res_body)
            #ProxyRewrite.logger.write(req_header_text)
            #ProxyRewrite.logger.write(res_header_text)

            logname = hostname
            # remove 'pXX-' from hostname for log filename
            if 'icloud.com' in hostname: logname = re.sub(r'^p\d\d-', '', hostname)

            logger = open("logs/"+logname+".log", "ab")
            logger.write(str(self.command+' '+self.path+"\n"))
            logger.write(str(req.headers))

            if ProxyRewrite.singlelogfile:
                ProxyRewrite.logger.write(str(self.command+' '+self.path+"\n"))
                ProxyRewrite.logger.write(str(req.headers))

            # format json request before writing to log file
            if req_body and 'Content-Type' in req.headers and req.headers['Content-Type'].startswith('application/json'):
                req_body_orig = req_body
                try:
                    json_obj = json.loads(req_body)
                    req_body = json.dumps(json_obj, indent=2)
                except ValueError:
                    req_body = req_body_orig

            if req_body:
                logger.write(str(req_body))
                if ProxyRewrite.singlelogfile: ProxyRewrite.logger.write(str(req_body))

            logger.write("\r\n%s %d %s\r\n" % (self.protocol_version, res.status, res.reason))
            logger.write(str(res.headers))

            if ProxyRewrite.singlelogfile:
                ProxyRewrite.logger.write(str("\r\n%s %d %s\r\n" % (self.protocol_version, res.status, res.reason)))
                ProxyRewrite.logger.write(str(res.headers))

            # format json response before writing to log file
            if res_body and 'Content-Type' in res.headers and res.headers['Content-Type'].startswith('application/json'):
                res_body_orig = res_body
                try:
                    json_obj = json.loads(res_body)
                    res_body = json.dumps(json_obj, indent=2)
                except ValueError:
                    res_body = res_body_orig

            if res_body:
                logger.write(str(res_body))
                if ProxyRewrite.singlelogfile: ProxyRewrite.logger.write(str(res_body))

            if ProxyRewrite.singlelogfile: ProxyRewrite.logger.write(str("\n"))
            logger.write(str("\n"))
            logger.close()


class ProxyAPNHandler(BaseRequestHandler):
    cakey = 'ca.key'
    cacert = 'ca.crt'
    certkey = 'cert.key'
    certdir = 'certs/'
    timeout = 5
    lock = threading.Lock()
    certKey=None
    issuerCert=None
    issuerKey=None

    def __init__(self, *args, **kwargs):
        self.tls = threading.local()
        self.tls.conns = {}

        self.certKey=crypto.load_privatekey(crypto.FILETYPE_PEM, open(self.certkey, 'rt').read())
        self.issuerCert=crypto.load_certificate(crypto.FILETYPE_PEM, open(self.cacert, 'rt').read())
        self.issuerKey=crypto.load_privatekey(crypto.FILETYPE_PEM, open(self.cakey, 'rt').read())

        BaseRequestHandler.__init__(self, *args, **kwargs)

    def log_error(self, format, *args):
        # surpress "Request timed out: timeout('timed out',)"
        if isinstance(args[0], socket.timeout):
            return

        self.log_message(format, *args)

    def handle(self):
        SO_ORIGINAL_DST = 80
        dst = self.request.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16) # Get the original destination IP before iptables redirect
        _, dst_port, ip1, ip2, ip3, ip4 = struct.unpack("!HHBBBB8x", dst)
        dst_ip = '%s.%s.%s.%s' % (ip1,ip2,ip3,ip4)
        peername = '%s:%s' % (self.request.getpeername()[0], self.request.getpeername()[1])
        print('ProxyAPNHandler Client %s -> %s:%s' % (peername, dst_ip, dst_port))
        s=None
        if dst_port == 5223:
            while 1:
                #if not isinstance(self.request, ssl.SSLSocket):
                #    with self.lock:
                #        certpath = ProxyRewrite.generate_cert(self.certdir, self.certKey, self.issuerCert, self.issuerKey, dst_ip, dst_port)
                #    try:
                #        self.request = ssl.wrap_socket(self.request, keyfile=self.certkey, certfile=certpath, ssl_version=ssl.PROTOCOL_TLSv1_2, server_side=True, do_handshake_on_connect=True, suppress_ragged_eofs=True)
                #    except ssl.SSLError as e:
                #        print("SSLError occurred on %s: %r" % (dst_ip,e))
                try:
                    data = self.request.recv(8192)
                    if not data: break
                except socket.timeout:
                    print("ProxyAPNHandler: Socket timeout occurred")
                    break
                except socket.error, e:
                    print("ProxyAPNHandler: Socket error occurred: %r" % e)
                    break

                print("len = %d" % len(data))
                print("received %s from client" % base64.b64encode(data))
                if s == None:
                    if not isinstance(self.request, ssl.SSLSocket):
                        with self.lock:
                            certpath = ProxyRewrite.generate_cert(self.certdir, self.certKey, self.issuerCert, self.issuerKey, dst_ip, dst_port)
                        try:
                            self.request = ssl.wrap_socket(self.request, keyfile=self.certkey, certfile=certpath, ssl_version=ssl.PROTOCOL_TLSv1_2, server_side=True, do_handshake_on_connect=True, suppress_ragged_eofs=True)
                        except ssl.SSLError, e:
                            print("SSLError occurred on %s: %r" % (dst_ip,e))
                        except socket.error, e:
                            print("socket.error occurred on %s: %r" % (dst_ip,e))
                    print("Connecting to %s:%s" % (dst_ip, dst_port))
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.connect((dst_ip, dst_port))
                if data: s.sendall(data)
                try:
                    data = s.recv(8192)
                    if not data: break
                except socket.timeout:
                    print("ProxyAPNHandler: Socket timeout occurred")
                    break
                except socket.error, e:
                    print("ProxyAPNHandler: Socket error occurred: %r" % e)
                    break

                print("len = %d" % len(data))
                if data:
                    #certs = ProxyRewrite.extract_certs(data)
                    #newcert = ProxyRewrite.rewrite_der_cert(certs[0])
                    #print("certlen=%d, newcertlen=%d" % (len(certs[0]), len(newcert)))
                    #print("cert1=%s" % base64.b64encode(certs[0]))
                    #print("cert2=%s" % base64.b64encode(certs[1]))
                    #print('Received %s from server' % base64.b64encode(data))
                    if not isinstance(self.request, ssl.SSLSocket):
                        with self.lock:
                            certpath = ProxyRewrite.generate_cert(self.certdir, self.certKey, self.issuerCert, self.issuerKey, dst_ip, dst_port)
                        try:
                            self.request = ssl.wrap_socket(self.request, keyfile=self.certkey, certfile=certpath, ssl_version=ssl.PROTOCOL_TLSv1_2, server_side=True, do_handshake_on_connect=True, suppress_ragged_eofs=True)
                        except ssl.SSLError as e:
                            print("SSLError occurred on %s: %r" % (dst_ip,e))
                    elif data: self.request.sendall(data)
            if s: s.close()
            if self.request:
                self.close_connection = 1
                self.request.close()
                self.finish()

        else:
            print("ProxyAPNHandler: Unknown dst_port=%d" % dst_port)

def run_http_server(HandlerClass=ProxyRequestHandler, ServerClass=ThreadingHTTPServer, protocol="HTTP/1.1"):
    try:
        ssl._https_verify_certificates(enable=False)
        HandlerClass.protocol_version = protocol
        httpd = ServerClass(ProxyRewrite.server_address, HandlerClass)
        httpd.allow_reuse_address = True
        httpd.request_queue_size = 256

        #ProxyRewrite.logger = open("rewrite_%s_%s.log" % (device1, device2), "w")

        sa = httpd.socket.getsockname()
        print "Serving HTTP Proxy on", sa[0], "port", sa[1], "..."
        httpd.serve_forever()
    except KeyboardInterrupt:
        print '^C received, shutting down proxy'
        httpd.socket.close()


def test(HandlerClass=ProxyRequestHandler, ServerClass=ThreadingHTTPServer, protocol="HTTP/1.1"):
    config = ConfigParser.ConfigParser()
    config.read('proxy2.cfg')

    if sys.argv[2:]:
        device1 = sys.argv[1]
        device2 = sys.argv[2]
    elif config.has_option('proxy2', 'device1') and config.has_option('proxy2', 'device2'):
        device1 = config.get('proxy2', 'device1')
        device2 = config.get('proxy2', 'device2')
    else:
        print("Usage: %s <device1> <device2>" % sys.argv[0])
        return 0

    if device1 != 'none' and device2 != 'none':
        print("Proxy set to rewrite device %s with device %s" % (device1, device2))
        ProxyRewrite.dev1info = ProxyRewrite.load_device_info(device1)
        ProxyRewrite.dev2info = ProxyRewrite.load_device_info(device2)
    else:
        ProxyRewrite.dev1info = None
        ProxyRewrite.dev2info = None

    port = config.getint('proxy2', 'port')
    ProxyRewrite.transparent = config.getboolean('proxy2', 'transparent')
    ProxyRewrite.changeClientID = config.getboolean('proxy2', 'change_clientid')
    ProxyRewrite.rewriteOSVersion = config.getboolean('proxy2', 'rewrite_osversion')
    ProxyRewrite.jailbroken = config.getboolean('proxy2', 'jailbroken')
    ProxyRewrite.singlelogfile = config.getboolean('proxy2', 'singlelogfile')

    if ProxyRewrite.rewriteOSVersion == False:
        print("Disabled iOS version rewrite")

    if ProxyRewrite.transparent == True:
        print("Setting transparent mode")

    if ProxyRewrite.changeClientID == True:
        if config.has_option('proxy2', 'clientid') == False:
            ProxyRewrite.dev2info['client-id'] = ProxyRewrite.generate_new_clientid()
            config.set('proxy2', 'clientid', ProxyRewrite.dev2info['client-id'])
            print("Generated new client-id %s for device %s" % (ProxyRewrite.dev2info['client-id'], ProxyRewrite.dev2info['SerialNumber']))
            with open('proxy2.cfg', 'wb') as configfile:
                 config.write(configfile)
        else:
            ProxyRewrite.dev2info['client-id'] = config.get('proxy2', 'clientid')
            print("Retrieved new client-id %s for device %s from proxy2.cfg" % (ProxyRewrite.dev2info['client-id'], ProxyRewrite.dev2info['SerialNumber']))

    iflist = netifaces.interfaces()
    ProxyRewrite.server_address = ('', port)

    #if 'enp0s25' in iflist: ProxyRewrite.server_address = (get_ip_address('enp0s25'), port)
    if 'ap1' in iflist: ProxyRewrite.server_address = (get_ip_address('ap1'), port)
    elif 'ap0' in iflist: ProxyRewrite.server_address = (get_ip_address('ap0'), port)
    #elif 'enp0s25' in iflist: ProxyRewrite.server_address = (get_ip_address('enp0s25'), port)
    elif 'ppp0' in iflist: ProxyRewrite.server_address = (get_ip_address('ppp0'), port)
    elif 'wlp61s0' in iflist: ProxyRewrite.server_address = (get_ip_address('wlp61s0'), port)
    elif 'wlo1' in iflist: ProxyRewrite.server_address = (get_ip_address('wlo1'), port)

    os.putenv('LANG', 'en_US.UTF-8')
    os.putenv('LC_ALL', 'en_US.UTF-8')

    # ugly hack due to python issue5853 (for threaded use)
    try:
        import mimetypes
        mimetypes.init()
    except UnicodeDecodeError:
        # Python 2.x's mimetypes module attempts to decode strings
        sys.argv # unwrap demand-loader so that reload() works
        reload(sys) # resurrect sys.setdefaultencoding()
        oldenc = sys.getdefaultencoding()
        sys.setdefaultencoding("latin1") # or any full 8-bit encoding
        mimetypes.init()
        sys.setdefaultencoding(oldenc)

    #ssl._https_verify_certificates(enable=False)
    #HandlerClass.protocol_version = protocol
    #httpd = ServerClass(ProxyRewrite.server_address, HandlerClass)
    #httpd.allow_reuse_address = True
    #httpd.request_queue_size = 256

    if ProxyRewrite.singlelogfile:
        ProxyRewrite.logger = open("rewrite_%s_%s.log" % (device1, device2), "w")

    apsd = SocketServer.TCPServer((ProxyRewrite.server_address[0], 8083), ProxyAPNHandler)
    sa = apsd.socket.getsockname()
    print "Serving APNS Proxy on", sa[0], "port", sa[1], "..."

    t1 = threading.Thread(target=apsd.serve_forever)
    t1.daemon = True

    t1.start()
    run_http_server()
    t1.join(2)

    if ProxyRewrite.singlelogfile:
        ProxyRewrite.logger.close()
    #print '^C received, shutting down proxy'
    #httpd.socket.close()

if __name__ == '__main__':
    test()
