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
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from SocketServer import ThreadingMixIn
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
    apnscnt = 0

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
        if "apple.com" not in hostname and "icloud.com" not in hostname and 'apple-cloudkit.com' not in hostname: return False
        hostname = hostname.replace(':443','')
        #if 'fmip.icloud.com' in hostname: return False
        #if hostname == "gsa.apple.com": return False
        #if hostname == "gsas.apple.com": return False
        if hostname == "ppq.apple.com": return False
        #if hostname == "albert.apple.com": return False
        #if hostname == "static.ips.apple.com": return False
        #if hostname == "captive.apple.com": return False
        return True

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
        text = text[text.find('<?xml'):text.find('</plist>')+8]
        print(headers)
        if headers['Content-Type'] == 'application/x-plist': return
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
            del p['RKCertification']
            del p['RKSignature']
            del p['serverKP']
            del p['signActRequest']

        else:
            attribs = 'BluetoothAddress,BuildVersion,EthernetAddress,ModelNumber,ProductType,ProductVersion,SerialNumber,UniqueDeviceID,UniqueChipID,WifiAddress,DeviceClass'
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

        if "hasCellularCapability</key>\n\t\t<false/>" in val:
            val = val.replace("hasCellularCapability</key>\n\t\t<false/>", "hasCellularCapability</key>\n\t\t<true/>\n\t\t<key>imei</key>\n\t\t<string>%s</string>\n\t\t<key>imei</key>\n\t\t<string>%s</string>" % (ProxyRewrite.dev2info['InternationalMobileEquipmentIdentity'], ProxyRewrite.dev2info['MobileEquipmentIdentifier']))
            print(val)
        if "hasCellularCapability" in val:
            val = val.replace( "\"hasCellularCapability\":false",  "\"hasCellularCapability\":true")
            val = val.replace( "\"hasCellularCapability\": false",  "\"hasCellularCapability\": true")
            print("hasCellularCapability:true")
        #if 'enclosureColor' not in val and 'EnclosureColor' in ProxyRewrite.dev2info:
        #    val = val.replace("deviceColor</key>\n\t\t<string>unknown</string>", "deviceColor</key>\n\t\t<string>%s</string>\n\t\t<key>enclosureColor</key>\n\t\t<string>%s</string>" % (ProxyRewrite.dev2info['DeviceColor'], ProxyRewrite.dev2info['EnclosureColor']))
        #    print("deviceColor:unknown -> deviceColor:%s, enclosureColor:%s\n" % (ProxyRewrite.dev2info['DeviceColor'], ProxyRewrite.dev2info['EnclosureColor']))
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

            if body != oldbody and ProxyRewrite.dev1info[attrib] != ProxyRewrite.dev2info[attrib]:
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

        if 'xp.apple.com' in hostname:
            body = ProxyRewrite.rewrite_body_attribs(body, 'BuildVersion,ProductType,ProductVersion,HardwareModel,HardwarePlatform,DeviceClass', hostname)
            return body
        elif hostname == 'setup.icloud.com' or hostname == 'appleid.cdn-apple.com' or 'fmf.icloud.com' in hostname:
            attribs = 'BuildVersion,DeviceColor,EnclosureColor,HardwareModel,HardwarePlatform,ProductType,ProductVersion,SerialNumber,UniqueDeviceID,TotalDiskCapacity,DeviceClass'
            if 'InternationalMobileEquipmentIdentity' in ProxyRewrite.dev1info:
                attribs = ("%s,%s" % (attribs, 'InternationalMobileEquipmentIdentity'))
            if 'MobileEquipmentIdentifier' in ProxyRewrite.dev1info:
                attribs = ("%s,%s" % (attribs, 'MobileEquipmentIdentifier'))
            if 'aps-token' in ProxyRewrite.dev1info and 'aps-token' in ProxyRewrite.dev2info:
                attribs = ("%s,%s" % (attribs, 'aps-token'))
            body = ProxyRewrite.rewrite_body_attribs(body, attribs, hostname)
            if "hasCellularCapability</key>\n\t\t<false/>" in body:
                body = body.replace("hasCellularCapability</key>\n\t\t<false/>", "hasCellularCapability</key>\n\t\t<true/>\n\t\t<key>imei</key>\n\t\t<string>%s</string>\n\t\t<key>imei</key>\n\t\t<string>%s</string>" % (ProxyRewrite.dev2info['InternationalMobileEquipmentIdentity'], ProxyRewrite.dev2info['MobileEquipmentIdentifier']))
                print(body)
            if "hasCellularCapability" in body:
                body = body.replace( "\"hasCellularCapability\":false", "\"hasCellularCapability\":true,\"imei\":\"%s\"" % (ProxyRewrite.dev2info['InternationalMobileEquipmentIdentity']))
                print(body)
            return body
        elif 'fmfmobile.icloud.com' in hostname:
            attribs = 'BuildVersion,DeviceColor,EnclosureColor,ProductType,ProductVersion,SerialNumber,UniqueDeviceID,TotalDiskCapacity,DeviceClass'
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
        elif 'fmipmobile.icloud.com' in hostname:
            #if 'enclosureColor' not in body and 'EnclosureColor' in ProxyRewrite.dev2info:
                #body = body.replace("deviceColor</key>\n\t\t<string>unknown</string>", "deviceColor</key>\n\t\t<string>%s</string>\n\t\t<key>enclosureColor</key>\n\t\t<string>%s</string>" % (ProxyRewrite.dev2info['DeviceColor'], ProxyRewrite.dev2info['EnclosureColor']))
                #print("deviceColor:unknown -> deviceColor:%s, enclosureColor:%s\n" % (ProxyRewrite.dev2info['DeviceColor'], ProxyRewrite.dev2info['EnclosureColor']))
            attribs = 'BuildVersion,DeviceColor,EnclosureColor,ModelNumber,ProductType,ProductVersion,SerialNumber,UniqueDeviceID,TotalDiskCapacity,WiFiAddress,BluetoothAddress,DeviceClass'
            if 'InternationalMobileEquipmentIdentity' in ProxyRewrite.dev1info:
                attribs = ("%s,%s" % (attribs, 'InternationalMobileEquipmentIdentity'))
            if 'MobileEquipmentIdentifier' in ProxyRewrite.dev1info:
                attribs = ("%s,%s" % (attribs, 'MobileEquipmentIdentifier'))
            if 'aps-token' in ProxyRewrite.dev1info and 'aps-token' in ProxyRewrite.dev2info:
                attribs = ("%s,%s" % (attribs, 'aps-token'))
            body = ProxyRewrite.rewrite_body_attribs(body, attribs, hostname)

            d1uid = str(hex(ProxyRewrite.dev1info['UniqueChipID']))
            d2uid = str(hex(ProxyRewrite.dev2info['UniqueChipID']))
            body = body.replace(d1uid, d2uid)
            print("Replaced %s with %s\n" % (d1uid, d2uid))

            if 'fmipVersion' in ProxyRewrite.dev1info and 'fmipVersion' in ProxyRewrite.dev2info and 'fmipBuildVersion' in ProxyRewrite.dev1info and 'fmipBuildVersion' in ProxyRewrite.dev2info:
                body = ProxyRewrite.rewrite_json_body_attribs(headers, body, {"buildVersion":"fmipVersion", "appVersion":"fmipBuildVersion"}, 'clientContext')

            if "hasCellularCapability</key>\n\t\t<false/>" in body:
                body = body.replace("hasCellularCapability</key>\n\t\t<false/>", "hasCellularCapability</key>\n\t\t<true/>\n\t\t<key>imei</key>\n\t\t<string>%s</string>\n\t\t<key>meid</key>\n\t\t<string>%s</string>" % (ProxyRewrite.dev2info['InternationalMobileEquipmentIdentity'], ProxyRewrite.dev2info['MobileEquipmentIdentifier']))
                print(body)
            #elif "\"hasCellularCapability\":false" in body:
            #    body = body.replace("\"hasCellularCapability\":false", "\"hasCellularCapability\":true,\"imei\":" + ProxyRewrite.dev2info['InternationalMobileEquipmentIdentity'])
            #    print("hasCellularCapability:true")
            return body
        elif 'fmip.icloud.com' in hostname:
            body = ProxyRewrite.rewrite_json_body_attribs(headers, body, {"deviceClass":"DeviceClass","deviceColor":"DeviceColor","enclosureColor":"EnclosureColor"}, 'deviceInfo')

            attribs = 'BuildVersion,DeviceColor,EnclosureColor,HardwarePlatform2,ModelNumber,ProductType,ProductVersion,SerialNumber,UniqueDeviceID,TotalDiskCapacity,WiFiAddress,BluetoothAddress,DeviceClass'
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

            d1uid = str(hex(ProxyRewrite.dev1info['UniqueChipID']))
            d2uid = str(hex(ProxyRewrite.dev2info['UniqueChipID']))
            body = body.replace(d1uid, d2uid)
            print("Replaced %s with %s\n" % (d1uid, d2uid))

            if 'fmipVersion' in ProxyRewrite.dev1info and 'fmipVersion' in ProxyRewrite.dev2info and 'fmipVersion' in body and 'fmipBuildVersion' in ProxyRewrite.dev1info and 'fmipBuildVersion' in ProxyRewrite.dev2info and 'fmipBuildVersion' in body:
                body = ProxyRewrite.rewrite_json_body_attribs(headers, body, {"fmipVersion":"fmipVersion", "fmipBuildVersion":"fmipBuildVersion"}, 'deviceInfo')

            if "hasCellularCapability</key>\n\t\t<false/>" in body and 'InternationalMobileEquipmentIdentity' in ProxyRewrite.dev2info:
                body = ProxyRewrite.rewrite_plist_body_attribs(headers, body, {"imei":"InternationalMobileEquipmentIdentity","meid":"MobileEquipmentIdentifier"}, 'deviceInfo')
                body = body.replace("hasCellularCapability</key>\n\t\t<false/>", "hasCellularCapability</key>\n\t\t<true/>")
            if "hasCellularCapability" in body and 'InternationalMobileEquipmentIdentity' in ProxyRewrite.dev2info:
                body = ProxyRewrite.rewrite_json_body_attribs(headers, body, {"imei":"InternationalMobileEquipmentIdentity","meid":"MobileEquipmentIdentifier"}, 'deviceInfo')
                body = body.replace("\"hasCellularCapability\":false", "\"hasCellularCapability\":true")
                body = body.replace("\"hasCellularCapability\": false", "\"hasCellularCapability\": true")
            return body
        elif 'keyvalueservice.icloud.com' in hostname:
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
        elif 'quota.icloud.com' in hostname:
            attribs = 'BuildVersion,DeviceColor,EnclosureColor,ProductType,ProductVersion,SerialNumber,UniqueDeviceID,TotalDiskCapacity,DeviceClass'
            if 'InternationalMobileEquipmentIdentity' in ProxyRewrite.dev1info:
                attribs = ("%s,%s" % (attribs, 'InternationalMobileEquipmentIdentity'))
            if 'MobileEquipmentIdentifier' in ProxyRewrite.dev1info:
                attribs = ("%s,%s" % (attribs, 'MobileEquipmentIdentifier'))
            if 'aps-token' in ProxyRewrite.dev1info and 'aps-token' in ProxyRewrite.dev2info:
                attribs = ("%s,%s" % (attribs, 'aps-token'))
            body = ProxyRewrite.rewrite_body_attribs(body, attribs, hostname)
            return body
        elif 'ckdevice.icloud.com' in hostname:
            body = ProxyRewrite.rewrite_body_attribs(body, 'BuildVersion,ProductType,ProductVersion', hostname)
            return body
        elif 'ckdatabase.icloud.com' in hostname:
            body = ProxyRewrite.rewrite_body_attribs(body, 'BuildVersion,ProductType,ProductVersion', hostname)
            return body
        elif hostname == 'gsp10-ssl.ls.apple.com':
            body = ProxyRewrite.rewrite_body_attribs(body, 'BuildVersion,ProductType,ProductVersion', hostname)
            return body
        elif hostname == 'sse-ws.apple.com':
            body = ProxyRewrite.rewrite_body_attribs(body, 'BuildVersion,DeviceClass,SerialNumber,ProductType,ProductVersion', hostname)
            return body
        elif 'gs-loc.apple.com' in hostname:
            body = ProxyRewrite.rewrite_body_attribs(body, 'BuildVersion,ProductType,ProductVersion', hostname)
            return body
        elif hostname == 'gsp-ssl.ls.apple.com':
            body = ProxyRewrite.rewrite_body_attribs(body, 'BuildVersion,ProductType,ProductVersion', hostname)
            return body
        elif hostname == 'tbsc.apple.com':
            body = ProxyRewrite.rewrite_body_attribs(body, 'BuildVersion,ProductType,ProductVersion,SerialNumber,UniqueDeviceID', hostname)
            return body
        elif 'gsa.apple.com' in hostname:
            attribs = 'BuildVersion,DeviceColor,EnclosureColor,ProductType,ProductVersion,SerialNumber,UniqueDeviceID'
            if 'aps-token' in ProxyRewrite.dev1info and 'aps-token' in ProxyRewrite.dev2info:
                attribs = ("%s,%s" % (attribs, 'aps-token'))
            attribs = 'BuildVersion,DeviceColor,EnclosureColor,ModelNumber,ProductType,ProductVersion,SerialNumber,UniqueDeviceID,TotalDiskCapacity,HardwareModel,HardwarePlatform,DeviceClass'
            if 'InternationalMobileEquipmentIdentity' in ProxyRewrite.dev1info:
                attribs = ("%s,%s" % (attribs, 'InternationalMobileEquipmentIdentity'))
            if 'MobileEquipmentIdentifier' in ProxyRewrite.dev1info:
                attribs = ("%s,%s" % (attribs, 'MobileEquipmentIdentifier'))
            if 'aps-token' in ProxyRewrite.dev1info and 'aps-token' in ProxyRewrite.dev2info:
                attribs = ("%s,%s" % (attribs, 'aps-token'))

            body = ProxyRewrite.rewrite_body_attribs(body, attribs, hostname)
            return body
        elif 'gsas.apple.com' in hostname:
            attribs = 'BuildVersion,DeviceColor,EnclosureColor,ProductType,ProductVersion,SerialNumber,UniqueDeviceID'
            if 'aps-token' in ProxyRewrite.dev1info and 'aps-token' in ProxyRewrite.dev2info:
                attribs = ("%s,%s" % (attribs, 'aps-token'))
            attribs = 'BuildVersion,DeviceColor,EnclosureColor,ModelNumber,ProductType,ProductVersion,SerialNumber,UniqueDeviceID,TotalDiskCapacity,HardwareModel,HardwarePlatform,DeviceClass'
            if 'InternationalMobileEquipmentIdentity' in ProxyRewrite.dev1info:
                attribs = ("%s,%s" % (attribs, 'InternationalMobileEquipmentIdentity'))
            if 'MobileEquipmentIdentifier' in ProxyRewrite.dev1info:
                attribs = ("%s,%s" % (attribs, 'MobileEquipmentIdentifier'))
            if 'aps-token' in ProxyRewrite.dev1info and 'aps-token' in ProxyRewrite.dev2info:
                attribs = ("%s,%s" % (attribs, 'aps-token'))
            body = ProxyRewrite.rewrite_body_attribs(body, attribs, hostname)
            body = ProxyRewrite.rewrite_plist_body_attribs(headers, body, {"imei":"InternationalMobileEquipmentIdentity","meid":"MobileEquipmentIdentifier","iccid":"IntegratedCircuitCardIdentity","pn":"PhoneNumber"}, 'Request')
            return body
        elif 'buy.itunes.apple.com' in hostname:
            body = ProxyRewrite.rewrite_body_attribs(body, 'BuildVersion,ProductType,ProductVersion,SerialNumber,UniqueDeviceID,HardwareModel,HardwarePlatform,DeviceClass', hostname)
            return body
        elif 'identity.apple.com' in hostname:
            body = ProxyRewrite.rewrite_body_attribs(body, 'BuildVersion,ProductVersion', hostname)
            return body
        elif 'albert.apple.com' in hostname:
            attribs = 'BuildVersion,DeviceColor,EnclosureColor,ProductType,ProductVersion,SerialNumber,UniqueDeviceID'
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

        if 'setup.icloud.com' in hostname or 'gsa.apple.com' in hostname:
            if 'X-Mme-Nas-Qualify' in headers:
                attribs = 'DeviceColor,EnclosureColor,ProductType,SerialNumber,TotalDiskCapacity,UniqueDeviceID,DeviceClass'
                if 'InternationalMobileEquipmentIdentity' in ProxyRewrite.dev1info:
                    attribs = ("%s,%s" % (attribs, 'InternationalMobileEquipmentIdentity'))
                if 'MobileEquipmentIdentifier' in ProxyRewrite.dev1info:
                    attribs = ("%s,%s" % (attribs, 'MobileEquipmentIdentifier'))
                if 'aps-token' in ProxyRewrite.dev1info and 'aps-token' in ProxyRewrite.dev2info:
                    attribs = ("%s,%s" % (attribs, 'aps-token'))
                    headers = ProxyRewrite.b64_rewrite_header_field(headers, 'X-Mme-Nas-Qualify', attribs)
            elif 'x-mme-nas-qualify' in headers:
                attribs = 'DeviceColor,EnclosureColor,ProductType,SerialNumber,TotalDiskCapacity,UniqueDeviceID,DeviceClass'
                if 'InternationalMobileEquipmentIdentity' in ProxyRewrite.dev1info:
                    attribs = ("%s,%s" % (attribs, 'InternationalMobileEquipmentIdentity'))
                if 'MobileEquipmentIdentifier' in ProxyRewrite.dev1info:
                    attribs = ("%s,%s" % (attribs, 'MobileEquipmentIdentifier'))
                if 'aps-token' in ProxyRewrite.dev1info and 'aps-token' in ProxyRewrite.dev2info:
                    attribs = ("%s,%s" % (attribs, 'aps-token'))
                headers = ProxyRewrite.b64_rewrite_header_field(headers, 'x-mme-nas-qualify', attribs)
        elif 'quota.icloud.com' in hostname:
            if 'X-Client-UDID' in headers:
                headers = ProxyRewrite.replace_header_field(headers, 'X-Client-UDID', 'UniqueDeviceID')
            elif 'x-client-udid' in headers:
                headers = ProxyRewrite.replace_header_field(headers, 'x-client-udid', 'UniqueDeviceID')
        elif 'caldav.icloud.com' in hostname:
            if 'X-Apple-DAV-Pushtoken' in headers and 'aps-token' in ProxyRewrite.dev1info and 'aps-token' in ProxyRewrite.dev2info:
                headers = ProxyRewrite.replace_header_field(headers, 'X-Apple-DAV-Pushtoken', 'aps-token')
            elif 'x-apple-dav-pushtoken' in headers and 'aps-token' in ProxyRewrite.dev1info and 'aps-token' in ProxyRewrite.dev2info:
                headers = ProxyRewrite.replace_header_field(headers, 'x-apple-dav-pushtoken', 'aps-token')
        elif 'sharedstreams.icloud.com' in hostname:
            if 'X-Apple-Mme-Sharedstreams-Client-Token' in headers:
                if 'aps-token' in headers:
                    headers = ProxyRewrite.rewrite_header_field(headers, 'X-Apple-Mme-Sharedstreams-Client-Token', 'aps-token,UniqueDeviceID')
                else:
                    headers = ProxyRewrite.rewrite_header_field(headers, 'X-Apple-Mme-Sharedstreams-Client-Token', 'UniqueDeviceID,UniqueDeviceID')
            elif 'x-apple-mme-sharedstreams-client-token' in headers:
                if 'aps-token' in headers:
                    headers = ProxyRewrite.rewrite_header_field(headers, 'x-apple-mme-sharedstreams-client-token', 'aps-token,UniqueDeviceID')
                else:
                    headers = ProxyRewrite.rewrite_header_field(headers, 'x-apple-mme-sharedstreams-client-token', 'UniqueDeviceID,UniqueDeviceID')


        if 'User-Agent' in headers:
            headers = ProxyRewrite.rewrite_header_field(headers, 'User-Agent', 'BuildVersion,HardwarePlatform,ProductName,ProductType,ProductType2,ProductVersion,ProductVersion2,DeviceClass')
        elif 'user-agent' in headers:
            headers = ProxyRewrite.rewrite_header_field(headers, 'user-agent', 'BuildVersion,HardwarePlatform,ProductName,ProductType,ProductType2,ProductVersion,ProductVersion2,DeviceClass')

        if 'X-MMe-Client-Info' in headers:
            headers = ProxyRewrite.rewrite_header_field(headers, 'X-MMe-Client-Info', 'BuildVersion,ProductName,ProductType,ProductVersion,HardwareModel,DeviceClass')
        elif 'x-mme-client-info' in headers:
            headers = ProxyRewrite.rewrite_header_field(headers, 'x-mme-client-info', 'BuildVersion,ProductName,ProductType,ProductVersion,HardwareModel,DeviceClass')

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
            headers = ProxyRewrite.rewrite_header_field(headers, 'X-Apple-Client-Info', 'BuildVersion,ProductName,ProductType,ProductVersion,DeviceClass')
        elif 'x-apple-client-info' in headers:
            headers = ProxyRewrite.rewrite_header_field(headers, 'x-apple-client-info', 'BuildVersion,ProductName,ProductType,ProductVersion,DeviceClass')

        if 'X-Client-Device-Enclosure-Color' in headers:
            headers = ProxyRewrite.replace_header_field(headers, 'X-Client-Device-Enclosure-Color', 'EnclosureColor')

        if 'X-Client-Device-Color' in headers:
            headers = ProxyRewrite.replace_header_field(headers, 'X-Client-Device-Color', 'DeviceColor')
            if 'X-Client-Device-Enclosure-Color' not in headers and 'EnclosureColor' in ProxyRewrite.dev2info:
                headers['X-Client-Device-Enclosure-Color'] = ProxyRewrite.dev2info['EnclosureColor']

        if 'x-apple-translated-wo-url' in headers:
            headers = ProxyRewrite.rewrite_header_field(headers, 'x-apple-translated-wo-url', 'BuildVersion,ProductType,ProductVersion,UniqueDeviceID')

        if 'x-apple-orig-url' in headers:
            headers = ProxyRewrite.rewrite_header_field(headers, 'x-apple-orig-url', 'BuildVersion,ProductType,ProductVersion,UniqueDeviceID')

        if 'X-Apple-MBS-Lock' in headers:
            headers = ProxyRewrite.rewrite_header_field(headers, 'X-Apple-MBS-Lock', 'UniqueDeviceID,UniqueDeviceID')
        elif 'x-apple-mbs-lock' in headers:
            headers = ProxyRewrite.rewrite_header_field(headers, 'x-apple-mbs-lock', 'UniqueDeviceID,UniqueDeviceID')

        if 'X-Apple-Ubiquity-Device-Id' in headers:
            headers = ProxyRewrite.rewrite_header_field(headers, 'X-Apple-Ubiquity-Device-Id', 'UniqueDeviceID,UniqueDeviceID')

        if 'X-iTunes-User-Agent' in headers:
            headers = ProxyRewrite.rewrite_header_field(headers, 'X-iTunes-User-Agent', 'BuildVersion,HardwareModel,ProductName,ProductType,ProductVersion,DeviceClass')

        if 'X-APPLE-UB-PUSHTOKEN' in headers and 'aps-token' in ProxyRewrite.dev1info and 'aps-token' in ProxyRewrite.dev2info:
            headers = ProxyRewrite.replace_header_field(headers, 'X-APPLE-UB-PUSHTOKEN', 'aps-token')

        if 'X-Apple-ATS-Cache-Key' in headers:
            headers = ProxyRewrite.rewrite_header_field(headers, 'x-apple-orig-url', 'BuildVersion,ProductType,ProductVersion')

        if 'X-Apple-TA-Device' in headers:
            headers = ProxyRewrite.rewrite_header_field(headers, 'X-Apple-TA-Device', 'BuildVersion,ProductType,ProductVersion')

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
                
        if 'fmip.icloud.com' in hostname:
                path = path.replace(ProxyRewrite.dev1info['UniqueDeviceID'], ProxyRewrite.dev2info['UniqueDeviceID'])
                if path != old_path: print("replace path %s -> %s\n" % (old_path, path))
        elif 'fmf.icloud.com' in hostname:
                path = path.replace(ProxyRewrite.dev1info['UniqueDeviceID'], ProxyRewrite.dev2info['UniqueDeviceID'])
                if path != old_path: print("replace path %s -> %s\n" % (old_path, path))
        elif 'fmfmobile.icloud.com' in hostname:
                path = path.replace(ProxyRewrite.dev1info['UniqueDeviceID'], ProxyRewrite.dev2info['UniqueDeviceID'])
                if path != old_path: print("replace path %s -> %s\n" % (old_path, path))
        elif 'mobilebackup.icloud.com' in hostname:
                path = path.replace(ProxyRewrite.dev1info['UniqueDeviceID'], ProxyRewrite.dev2info['UniqueDeviceID'])
                if path != old_path: print("replace path %s -> %s\n" % (old_path, path))
        elif 'quota.icloud.com' in hostname:
                path = path.replace(ProxyRewrite.dev1info['UniqueDeviceID'], ProxyRewrite.dev2info['UniqueDeviceID'])
                if path != old_path: print("replace path %s -> %s\n" % (old_path, path))
        elif hostname == 'gspe35-ssl.ls.apple.com' or hostname == 'gspe1-ssl.ls.apple.com':
                path = path.replace(ProxyRewrite.dev1info['ProductType'], ProxyRewrite.dev2info['ProductType'])
                path = path.replace(ProxyRewrite.dev1info['BuildVersion'], ProxyRewrite.dev2info['BuildVersion'])
                path = path.replace(ProxyRewrite.dev1info['ProductVersion'], ProxyRewrite.dev2info['ProductVersion'])
                if path != old_path: print("replace path %s -> %s\n" % (old_path, path))
        elif 'buy.itunes.apple.com' in hostname:
                path = path.replace(ProxyRewrite.dev1info['UniqueDeviceID'], ProxyRewrite.dev2info['UniqueDeviceID'])
                if path != old_path: print("replace path %s -> %s\n" % (old_path, path))
        elif hostname == 'configuration.apple.com':
                path = path.replace("9.0.plist", "10.1.plist")
                if path != old_path: print("replace path %s -> %s\n" % (old_path, path))
        elif hostname == 'gsa.apple.com':
                path = path.replace(ProxyRewrite.dev1info['UniqueDeviceID'], ProxyRewrite.dev2info['UniqueDeviceID'])
                if path != old_path: print("replace path %s -> %s\n" % (old_path, path))
        return path

    @staticmethod
    def rewrite_status(path, status):
        if 'appleid.apple.com' in path and status == 401:
                status = 200
                print("replace status 401 -> 200\n")
        return status

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
                certpath = self.generate_cert(dst_ip)
            try:
                self.connection = ssl.wrap_socket(self.connection, keyfile=self.certkey, certfile=certpath, ssl_version=ssl.PROTOCOL_TLSv1_2, server_side=True, do_handshake_on_connect=True, suppress_ragged_eofs=True)
            except ssl.SSLError as e:
                try:
                    ssl._https_verify_certificates(enable=False)
                    self.connection = ssl.wrap_socket(self.connection, keyfile=self.certkey, certfile=certpath, ssl_version=ssl.PROTOCOL_TLSv1_2, server_side=True, do_handshake_on_connect=False, suppress_ragged_eofs=True)
                except ssl.SSLError as e:
                    print("SSLError occurred on %s: %r" % (dst_ip,e))
                    #self.finish()

        self.rfile = self.connection.makefile("rb", self.rbufsize)
        self.wfile = self.connection.makefile("wb", self.wbufsize)

        if dst_port == 5223:
            print("APNS connection (%s, %s)" % (dst_ip, dst_port))
            #logger = open("logs/apns%d.log" % ProxyRewrite.apnscnt, "wb")
            #ProxyRewrite.apnscnt = ProxyRewrite.apnscnt + 1
            #logger.write(self.rfile.read(128))
            #logger.write(self.rfile.read(32))
            #logger.write(self.rfile.read(32))
            #logger.close()
            #self.rfile.seek(0)

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

    def generate_cert(self, hostname):
        certpath = "%s/%s.crt" % (self.certdir.rstrip('/'), hostname)
        # always use same cert for all *.icloud.com except for *-fmip.icloud.com
        if os.path.isfile(certpath): return certpath
        if 'icloud.com' in hostname and 'fmip.icloud.com' not in hostname:
            srvcertname = "server_certs/icloud.com.crt"
        elif 'fmip.icloud.com' in hostname:
            srvcertname = "server_certs/fmip.icloud.com.crt"
        elif 'itunes.apple.com' in hostname:
            srvcertname = "server_certs/itunes.apple.com.crt"
        else:
            srvcertname = "%s/%s.crt" % ('server_certs', hostname)
        srvcert=None
        altnames=None

        if os.path.isfile(srvcertname):
                st_cert=open(srvcertname, 'rt').read()
                srvcert=crypto.load_certificate(crypto.FILETYPE_PEM, st_cert)
                altnames = ProxyRewrite.altnames(srvcert)
        req = crypto.X509Req()
        if srvcert:
            subject = srvcert.get_subject()
            req.get_subject().CN = subject.CN
            req.get_subject().O = subject.O
            req.get_subject().C = subject.C
            req.get_subject().OU = subject.OU
        else:
            req.get_subject().CN = hostname
        req.set_pubkey(self.certKey)
        req.sign(self.certKey, "sha1")
        cert = crypto.X509()
        try:
            cert.set_serial_number(int(hashlib.md5(req.get_subject().CN.encode('utf-8')).hexdigest(), 16))
        except SSL.Error:
            epoch = int(time.time() * 1000)
            cert.set_serial_number(epoch)

        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(60 * 60 * 24 * 3650)
        cert.set_issuer(self.issuerCert.get_subject())
        cert.set_subject(req.get_subject())
        cert.set_pubkey(req.get_pubkey())
        #cert.set_version(2)

        cert.add_extensions([
            crypto.X509Extension("basicConstraints", True, "CA:FALSE"),
            #crypto.X509Extension("nsCertType", True, "sslCA"),
            crypto.X509Extension("extendedKeyUsage", True, "serverAuth"),
            crypto.X509Extension("keyUsage", True, "keyCertSign, cRLSign"),
            crypto.X509Extension('subjectKeyIdentifier', False, 'hash', subject=cert)
        ])

        if srvcert:
            cert.set_serial_number(int(srvcert.get_serial_number()))
            if altnames:
                print("ALTNAMES: %s\n" % altnames)
                cert.add_extensions([crypto.X509Extension("subjectAltName", False, ", ".join(altnames))])
        cert.sign(self.issuerKey, "sha256")
        with open(certpath, "w") as cert_file:
            cert_file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        return certpath

    def connect_intercept(self):
        hostname = self.path.split(':')[0]

        certpath = self.generate_cert(hostname)

        self.wfile.write("%s %d %s\r\n" % (self.protocol_version, 200, 'Connection Established'))
        self.end_headers()

        try:
            self.connection = ssl.wrap_socket(self.connection, keyfile=self.certkey, certfile=certpath, ssl_version=ssl.PROTOCOL_TLSv1_2, server_side=True, do_handshake_on_connect=True, suppress_ragged_eofs=True)
        except ssl.SSLError as e:
            try:
                ssl._https_verify_certificates(enable=False)
                self.connection = ssl.wrap_socket(self.connection, keyfile=self.certkey, certfile=certpath, ssl_version=ssl.PROTOCOL_TLSv1_2, server_side=True, do_handshake_on_connect=False, suppress_ragged_eofs=True)
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
        elif self.path == 'http://proxy2.gsa/':
            self.send_cacert('certs/gsa.apple.com.crt')
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
        elif encoding in ('gzip', 'x-gzip'):
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
        elif encoding in ('gzip', 'x-gzip'):
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
        if 'ckdatabase.icloud.com' in req.path or 'ckdevice.icloud.com' in req.path: return

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
                    if json_str.count('\n') < 50 or 'fmip.icloud.com' in req.path or 'fmf.icloud.com' in req.path:
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
        #if 'captive.apple.com' in req.path:
        #    if 'hotspot-detect.html' in req.path:
        #        r = requests.get('http://ui.iclouddnsbypass.com/deviceservices/buddy/barney_activation_help_en_us.buddyml')
        #        res_body = r.text
        #        res.headers['Content-Length'] = str(len(r.text))

        # rewrite response status
        #res.status = ProxyRewrite.rewrite_status(req.path, res.status)
        if 'setup.icloud.com/configurations/init?context=settings' in self.path:
            # Attempt to replace gsa.apple.com to use a different server
            res_body = res_body.replace('gsa.apple.com', 'gsa-nc1.apple.com')
            print("setup.icloud.com: Replaced gsa.apple.com -> gsa-nc1.apple.com")
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

        if 'icloud.com' in hostname or 'apple.com' in hostname:
            req_body_plain = req_body
            if 'Content-Encoding' in req.headers and req.headers['Content-Encoding'] == 'gzip' and 'Content-Length' in req.headers and req.headers['Content-Length'] > 0 and len(str(req_body)) > 0:
                content_encoding = req.headers.get('Content-Encoding', 'identity')
                req_body_plain = self.decode_content_body(str(req_body), content_encoding)

            self.print_info(req, req_body_plain, res, res_body)
            req_header_text = "%s %s %s" % (req.command, req.path, req.request_version)
            res_header_text = "%s %d %s\n" % (res.response_version, res.status, res.reason)
            #print with_color(33, req_header_text)
            #print with_color(32, res_header_text)
            ProxyRewrite.logger.write(req_header_text)
            ProxyRewrite.logger.write(res_header_text)

            logname = hostname
            # remove 'pXX-' from hostname for log filename
            if 'icloud.com' in hostname: logname = re.sub(r'p\d\d-', '', hostname)

            logger = open("logs/"+logname+".log", "ab")
            logger.write(str(self.command+' '+self.path+"\n"))
            logger.write(str(req.headers))

            # format json request before writing to log file
            if req_body and 'Content-Type' in req.headers and req.headers['Content-Type'].startswith('application/json'):
                req_body_orig = req_body
                try:
                    json_obj = json.loads(req_body)
                    req_body = json.dumps(json_obj, indent=2)
                except ValueError:
                    req_body = req_body_orig

            if req_body: logger.write(str(req_body))
            logger.write("\r\n%s %d %s\r\n" % (self.protocol_version, res.status, res.reason))
            logger.write(str(res.headers))

            # format json response before writing to log file
            if res_body and 'Content-Type' in res.headers and res.headers['Content-Type'].startswith('application/json'):
                res_body_orig = res_body
                try:
                    json_obj = json.loads(res_body)
                    res_body = json.dumps(json_obj, indent=2)
                except ValueError:
                    res_body = res_body_orig

            if res_body: logger.write(str(res_body))
            logger.write(str("\n"))
            logger.close()

def test(HandlerClass=ProxyRequestHandler, ServerClass=ThreadingHTTPServer, protocol="HTTP/1.1"):
    if sys.argv[3:]:
        port = int('8080') #sys.argv[1])
        device1 = sys.argv[1]
        device2 = sys.argv[2]
        if sys.argv[3] == '-T':
            print("Setting transparent mode")
            ProxyRewrite.transparent = True
    elif sys.argv[2:]:
        port = int('8080') #sys.argv[1])
        device1 = sys.argv[1]
        device2 = sys.argv[2]

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

    iflist = netifaces.interfaces()
    server_address = ('', port)

    if 'ap4' in iflist: server_address = (get_ip_address('ap4'), port)
    elif 'ap0' in iflist: server_address = (get_ip_address('ap0'), port)
    elif 'ppp0' in iflist: server_address = (get_ip_address('ppp0'), port)
    elif 'wlp61s0' in iflist: server_address = (get_ip_address('wlp61s0'), port)
    elif 'wlo1' in iflist: server_address = (get_ip_address('wlo1'), port)

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

    try:
        ssl._https_verify_certificates(enable=False)
        HandlerClass.protocol_version = protocol
        httpd = ServerClass(server_address, HandlerClass)
        httpd.allow_reuse_address = True
        httpd.request_queue_size = 256

        ProxyRewrite.logger = open("requests.log", "w")

        sa = httpd.socket.getsockname()
        print "Serving HTTP Proxy on", sa[0], "port", sa[1], "..."
        httpd.serve_forever()

    except KeyboardInterrupt:
        ProxyRewrite.logger.close()
        print '^C received, shutting down proxy'
        httpd.socket.close()


if __name__ == '__main__':
    test()
