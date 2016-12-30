import argparse
import sys
import os
import plistlib
import base64

class ProxyRewrite:
    dev1info = dict()
    dev2info = dict()
    logger = None

    def __init__(self, device1, device2):
        print("Proxy set to rewrite device %s with device %s" % (device1, device2))
        ProxyRewrite.dev1info = ProxyRewrite.load_device_info(device1)
        ProxyRewrite.dev2info = ProxyRewrite.load_device_info(device2)

    def request(self, flow):
        if 'Host' not in flow.request.headers: return

        hostname = flow.request.headers['Host']
        if "apple.com" not in hostname and "icloud.com" not in hostname: return
        
        flow.request.path = ProxyRewrite.rewrite_path(flow.request.headers, flow.request.path)
        flow.request.headers = ProxyRewrite.rewrite_headers(flow.request.headers)
        
        if flow.request.content == None: return
        flow.request.content = ProxyRewrite.rewrite_body(flow.request.content, flow.request.headers)

    @staticmethod
    def load_device_info(sn):
        device = plistlib.readPlist("devices/%s.xml" % sn)
        return device

    @staticmethod
    def intercept_this_host(hostname):
        if "apple.com" not in hostname and "icloud.com" not in hostname: return False
        hostname = hostname.replace(':443','')
        if hostname == "gsa.apple.com": return False
        if hostname == "gsas.apple.com": return False
        if hostname == "ppq.apple.com": return False
        if hostname == "albert.apple.com": return False
        if hostname == "static.ips.apple.com": return False
        if hostname == "captive.apple.com": return False
        return True

    @staticmethod
    def rewrite_body_this_host(hostname):
        if "apple.com" not in hostname and "icloud.com" not in hostname: return False
        hostname = hostname.replace(':443','')
        if hostname == 'xp.apple.com': return True
        if hostname == 'setup.icloud.com': return True
        if hostname == 'p62-fmf.icloud.com': return True
        if hostname == 'p59-fmf.icloud.com': return True
        if hostname == 'p57-fmf.icloud.com': return True
        if hostname == 'p51-fmf.icloud.com': return True
        if hostname == 'p15-fmf.icloud.com': return True
        if hostname == 'p62-fmfmobile.icloud.com': return True
        if hostname == 'p59-fmfmobile.icloud.com': return True
        if hostname == 'p57-fmfmobile.icloud.com': return True
        if hostname == 'p51-fmfmobile.icloud.com': return True
        if hostname == 'p15-fmfmobile.icloud.com': return True
        return False

    @staticmethod
    def rewrite_body_attribs(body, attribs):
        oldbody = body
        attriblist = attribs.split(',')
        for attrib in attriblist:
        # skip if attribute not in dev1info or dev2info
            if attrib not in ProxyRewrite.dev1info.keys() or attrib not in ProxyRewrite.dev2info.keys(): continue
            body = body.replace(str(ProxyRewrite.dev1info[attrib]).encode(), str(ProxyRewrite.dev2info[attrib]).encode())
            if body != oldbody and ProxyRewrite.dev1info[attrib] != ProxyRewrite.dev2info[attrib]:
                print("Replacing body value %s -> %s" % (str(ProxyRewrite.dev1info[attrib]), str(ProxyRewrite.dev2info[attrib])))
        return body

    @staticmethod
    def rewrite_body(body, headers):
        if body == None: return None

        hostname = ''
        if 'Host' in headers:
            hostname = headers['Host']
            hostname = hostname.replace(':443','')

        if hostname == 'xp.icloud.com':
            old_body = body
            body = ProxyRewrite.rewrite_body_attribs(body, 'BuildVersion,HardwareModel')
            return body
        elif hostname == 'setup.icloud.com' or hostname == 'p62-fmf.icloud.com' or hostname == 'p59-fmf.icloud.com' or hostname == 'p57-fmf.icloud.com' or hostname == 'p51-fmf.icloud.com' or hostname == 'p31-fmf.icloud.com' or hostname == 'p29-fmf.icloud.com' or hostname == 'p15-fmf.icloud.com':
            old_body = body
            attribs = 'BuildVersion,DeviceColor,EnclosureColor,ProductType,ProductVersion,SerialNumber,UniqueDeviceID,TotalDiskCapacity'
            if 'InternationalMobileEquipmentIdentity' in ProxyRewrite.dev1info:
                attribs = ("%s,%s" % (attribs, 'InternationalMobileEquipmentIdentity'))
            if 'MobileEquipmentIdentifier' in ProxyRewrite.dev1info:
                attribs = ("%s,%s" % (attribs, 'MobileEquipmentIdentifier'))
            if 'aps-token' in ProxyRewrite.dev1info:
                attribs = ("%s,%s" % (attribs, 'aps-token'))

            body = ProxyRewrite.rewrite_body_attribs(body, attribs)
            return body
        elif hostname == 'p62-fmfmobile.icloud.com' or hostname == 'p59-fmfmobile.icloud.com' or hostname == 'p57-fmfmobile.icloud.com' or hostname == 'p51-fmfmobile.icloud.com' or hostname == 'p31-fmfmobile.icloud.com' or hostname == 'p29-fmfmobile.icloud.com' or hostname == 'p15-fmfmobile.icloud.com':
            old_body = body
            attribs = 'BuildVersion,DeviceColor,EnclosureColor,ProductType,ProductVersion,SerialNumber,UniqueDeviceID,TotalDiskCapacity,DeviceClass'
            if 'InternationalMobileEquipmentIdentity' in ProxyRewrite.dev1info:
                attribs = ("%s,%s" % (attribs, 'InternationalMobileEquipmentIdentity'))
            if 'MobileEquipmentIdentifier' in ProxyRewrite.dev1info:
                attribs = ("%s,%s" % (attribs, 'MobileEquipmentIdentifier'))
            if 'aps-token' in ProxyRewrite.dev1info:
                attribs = ("%s,%s" % (attribs, 'aps-token'))
            body = ProxyRewrite.rewrite_body_attribs(body, attribs)
            # replace meDeviceId
            d1udid_encoded = base64.b64encode(str(ProxyRewrite.dev1info['UniqueDeviceID']).encode())
            d2udid_encoded = base64.b64encode(str(ProxyRewrite.dev2info['UniqueDeviceID']).encode())
            body = body.replace(d1udid_encoded, d2udid_encoded)
            return body
        elif hostname == 'p62-keyvalueservice.icloud.com' or hostname == 'p59-keyvalueservice.icloud.com' or hostname == 'p57-keyvalueservice.icloud.com' or hostname == 'p51-keyvalueservice.icloud.com' or hostname == 'p31-keyvalueservice.icloud.com' or hostname == 'p29-keyvalueservice.icloud.com' or hostname == 'p15-keyvalueservice.icloud.com':
            old_body = body
            # replace apns-token
            if 'aps-token' in ProxyRewrite.dev1info:
                d1apns_encoded = base64.b64encode(str(ProxyRewrite.dev1info['aps-token']).encode())
                d2apns_encoded = base64.b64encode(str(ProxyRewrite.dev2info['aps-token']).encode())
                body = body.replace(d1apns_encoded, d2apns_encoded)
            return body
        elif hostname == 'p62-quota.icloud.com' or hostname == 'p59-quota.icloud.com' or hostname == 'p57-quota.icloud.com' or hostname == 'p51-quota.icloud.com' or hostname == 'p31-quota.icloud.com' or hostname == 'p29-quota.icloud.com' or hostname == 'p15-quota.icloud.com':
            old_body = body
            attribs = 'BuildVersion,DeviceColor,EnclosureColor,ProductType,ProductVersion,SerialNumber,UniqueDeviceID,TotalDiskCapacity,DeviceClass'
            if 'InternationalMobileEquipmentIdentity' in ProxyRewrite.dev1info:
                attribs = ("%s,%s" % (attribs, 'InternationalMobileEquipmentIdentity'))
            if 'MobileEquipmentIdentifier' in ProxyRewrite.dev1info:
                attribs = ("%s,%s" % (attribs, 'MobileEquipmentIdentifier'))
            if 'aps-token' in ProxyRewrite.dev1info:
                attribs = ("%s,%s" % (attribs, 'aps-token'))
            body = ProxyRewrite.rewrite_body_attribs(body, attribs)
            return body
        elif hostname == 'p62-ckdevice.icloud.com' or  hostname == 'p59-ckdevice.icloud.com' or hostname == 'p57-ckdevice.icloud.com' or hostname == 'p51-ckdevice.icloud.com' or hostname == 'p15-ckdevice.icloud.com':
            old_body = body
            body = ProxyRewrite.rewrite_body_attribs(body, 'BuildVersion,ProductType,ProductVersion')
            return body
        elif hostname == 'p62-ckdatabase.icloud.com' or hostname == 'p59-ckdatabase.icloud.com' or hostname == 'p57-ckdatabase.icloud.com' or hostname == 'p51-ckdatabase.icloud.com' or hostname == 'p15-ckdatabase.icloud.com':
            old_body = body
            body = ProxyRewrite.rewrite_body_attribs(body, 'BuildVersion,ProductType,ProductVersion')
            return body
        elif hostname == 'gsp10-ssl.ls.apple.com':
            old_body = body
            body = ProxyRewrite.rewrite_body_attribs(body, 'BuildVersion,ProductType,ProductVersion')
            return body
        elif hostname == 'sse-ws.apple.com':
            old_body = body
            body = ProxyRewrite.rewrite_body_attribs(body, 'BuildVersion,DeviceClass,SerialNumber,ProductType,ProductVersion')
            return body
        elif hostname == 'gs-loc.apple.com':
            old_body = body
            body = ProxyRewrite.rewrite_body_attribs(body, 'BuildVersion,ProductType,ProductVersion')
            return body
        elif hostname == 'gsp-ssl.ls.apple.com':
            old_body = body
            body = ProxyRewrite.rewrite_body_attribs(body, 'BuildVersion,ProductType,ProductVersion')
            return body
        elif hostname == 'tbsc.apple.com':
            old_body = body
            body = ProxyRewrite.rewrite_body_attribs(body, 'BuildVersion,ProductType,ProductVersion,SerialNumber,UniqueDeviceID')
            return body

        return body

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
            headers[field] = headers[field].replace(ProxyRewrite.dev1info[attrib], ProxyRewrite.dev2info[attrib])
            if headers[field] != oldval:
                print("%s: Replacing field %s: %s -> %s" % (headers['Host'], field, oldval, headers[field]))
        return headers

    @staticmethod
    def b64_rewrite_header_field(headers, field, attribs):
        if field not in headers: return headers
        val = bytearray(base64.b64decode(headers[field]))
        oldval = val

        attriblist = attribs.split(',')
        for attrib in attriblist:
            # skip if attribute not in dev1info or dev2info
            if attrib not in ProxyRewrite.dev1info.keys() or attrib not in ProxyRewrite.dev2info.keys(): continue
            val = val.replace(str(ProxyRewrite.dev1info[attrib]).encode(), str(ProxyRewrite.dev2info[attrib]).encode())
            if headers[field] != oldval:
                print("%s: Replacing %s: %s -> %s" % (headers["Host"], attrib, str(ProxyRewrite.dev1info[attrib]), str(ProxyRewrite.dev2info[attrib])))

        headers[field] = base64.b64encode(val)
        return headers

    @staticmethod
    def rewrite_headers(headers):
        if 'X-Mme-Nas-Qualify' in headers:
            attribs = 'DeviceColor,EnclosureColor,ProductType,SerialNumber,TotalDiskCapacity,UniqueDeviceID,DeviceClass'
            if 'InternationalMobileEquipmentIdentity' in ProxyRewrite.dev1info:
                attribs = ("%s,%s" % (attribs, 'InternationalMobileEquipmentIdentity'))
            if 'MobileEquipmentIdentifier' in ProxyRewrite.dev1info:
                attribs = ("%s,%s" % (attribs, 'MobileEquipmentIdentifier'))
            if 'aps-token' in ProxyRewrite.dev1info:
                attribs = ("%s,%s" % (attribs, 'aps-token'))
            headers = ProxyRewrite.b64_rewrite_header_field(headers, 'X-Mme-Nas-Qualify', attribs)

        if 'x-mme-nas-qualify' in headers:
            attribs = 'DeviceColor,EnclosureColor,ProductType,SerialNumber,TotalDiskCapacity,UniqueDeviceID,DeviceClass'
            if 'InternationalMobileEquipmentIdentity' in ProxyRewrite.dev1info:
                attribs = ("%s,%s" % (attribs, 'InternationalMobileEquipmentIdentity'))
            if 'MobileEquipmentIdentifier' in ProxyRewrite.dev1info:
                attribs = ("%s,%s" % (attribs, 'MobileEquipmentIdentifier'))
            if 'aps-token' in ProxyRewrite.dev1info:
                attribs = ("%s,%s" % (attribs, 'aps-token'))
            headers = ProxyRewrite.b64_rewrite_header_field(headers, 'x-mme-nas-qualify', attribs)

        if 'User-Agent' in headers:
            headers = ProxyRewrite.rewrite_header_field(headers, 'User-Agent', 'BuildVersion,HardwarePlatform,ProductName,ProductType,ProductVersion,ProductVersion2')

        if 'user-agent' in headers:
            headers = ProxyRewrite.rewrite_header_field(headers, 'user-agent', 'BuildVersion,HardwarePlatform,ProductName,ProductType,ProductVersion,ProductVersion2')

        if 'X-MMe-Client-Info' in headers:
            headers = ProxyRewrite.rewrite_header_field(headers, 'X-MMe-Client-Info', 'BuildVersion,ProductName,ProductType,ProductVersion,HardwareModel,DeviceClass')

        if 'x-mme-client-info' in headers:
            headers = ProxyRewrite.rewrite_header_field(headers, 'x-mme-client-info', 'BuildVersion,ProductName,ProductType,ProductVersion,HardwareModel,DeviceClass')

        if 'X-Client-UDID' in headers:
            headers = ProxyRewrite.replace_header_field(headers, 'X-Client-UDID', 'UniqueDeviceID')

        if 'x-client-udid' in headers:
            headers = ProxyRewrite.replace_header_field(headers, 'x-client-udid', 'UniqueDeviceID')

        if 'X-Mme-Device-Id' in headers:
            headers = ProxyRewrite.replace_header_field(headers, 'X-Mme-Device-Id', 'UniqueDeviceID')

        if 'x-mme-device-id' in headers:
            headers = ProxyRewrite.replace_header_field(headers, 'x-mme-device-id', 'UniqueDeviceID')

        if 'Device-UDID' in headers:
            headers = ProxyRewrite.replace_header_field(headers, 'Device-UDID', 'UniqueDeviceID')

        if 'device-udid' in headers:
            headers = ProxyRewrite.replace_header_field(headers, 'device-udid', 'UniqueDeviceID')

        if 'X-AppleID-Device-Udid' in headers:
            headers = ProxyRewrite.replace_header_field(headers, 'X-AppleID-Device-Udid', 'UniqueDeviceID')

        if 'x-appleid-device-udid' in headers:
            headers = ProxyRewrite.replace_header_field(headers, 'x-appleid-device-udid', 'UniqueDeviceID')

        if 'X-Apple-I-SRL-NO' in headers:
            headers = ProxyRewrite.replace_header_field(headers, 'X-Apple-I-SRL-NO', 'SerialNumber')

        if 'x-apple-i-srl-no' in headers:
            headers = ProxyRewrite.replace_header_field(headers, 'x-apple-i-srl-no', 'SerialNumber')

        if 'X-Apple-Client-Info' in headers:
            headers = ProxyRewrite.rewrite_header_field(headers, 'X-Apple-Client-Info', 'BuildVersion,ProductName,ProductType,ProductVersion,DeviceClass')

        if 'x-apple-client-info' in headers:
            headers = ProxyRewrite.rewrite_header_field(headers, 'x-apple-client-info', 'BuildVersion,ProductName,ProductType,ProductVersion,DeviceClass')

        if 'X-Client-Device-Color' in headers:
            headers = ProxyRewrite.replace_header_field(headers, 'X-Client-Device-Color', 'DeviceColor')

        if 'X-Client-Device-Enclosure-Color' in headers:
            headers = ProxyRewrite.replace_header_field(headers, 'X-Client-Device-Enclosure-Color', 'EnclosureColor')

        #if 'X-Apple-DAV-Pushtoken' in headers:
        #    headers = ProxyRewrite.replace_header_field(headers, 'X-Apple-DAV-Pushtoken', 'aps-token')

        #if 'x-apple-dav-pushtoken' in headers:
        #    headers = ProxyRewrite.replace_header_field(headers, 'x-apple-dav-pushtoken', 'aps-token')

        if 'x-apple-translated-wo-url' in headers:
            apple_url = headers['x-apple-translated-wo-url']
            print("x-apple-translated-wo-url" + apple_url)

        if 'x-apple-orig-url' in headers:
            apple_url = headers['x-apple-orig-url']
            print("x-apple-orig-url" + apple_url)

        if 'X-Apple-MBS-Lock' in headers:
            headers = ProxyRewrite.rewrite_header_field(headers, 'X-Apple-MBS-Lock', 'UniqueDeviceID,UniqueDeviceID')

        if 'x-apple-mbs-lock' in headers:
            headers = ProxyRewrite.rewrite_header_field(headers, 'x-apple-mbs-lock', 'UniqueDeviceID,UniqueDeviceID')

        if 'X-Apple-Mme-Sharedstreams-Client-Token' in headers:
            if 'aps-token' in headers:
                headers = ProxyRewrite.replace_header_field(headers, 'X-Apple-Mme-Sharedstreams-Client-Token', 'aps-token,UniqueDeviceID')
            else:
                headers = ProxyRewrite.replace_header_field(headers, 'X-Apple-Mme-Sharedstreams-Client-Token', 'UniqueDeviceID,UniqueDeviceID')

        if 'x-apple-mme-sharedstreams-client-token' in headers:
            if 'aps-token' in headers:
                headers = ProxyRewrite.replace_header_field(headers, 'x-apple-mme-sharedstreams-client-token', 'aps-token,UniqueDeviceID')
            else:
                headers = ProxyRewrite.replace_header_field(headers, 'x-apple-mme-sharedstreams-client-token', 'UniqueDeviceID,UniqueDeviceID')

        return headers

    @staticmethod
    def rewrite_path(headers, path):
        hostname = ''
        if 'Host' in headers:
            hostname = headers['Host']
            hostname = hostname.replace(':443','')

        if hostname == 'p62-fmf.icloud.com' or hostname == 'p59-fmf.icloud.com' or hostname == 'p57-fmf.icloud.com' or hostname == 'p51-fmf.icloud.com' or hostname == 'p31-fmf.icloud.com' or hostname == 'p29-fmf.icloud.com' or hostname == 'p15-fmf.icloud.com':
                old_path = path
                path = path.replace(ProxyRewrite.dev1info['UniqueDeviceID'], ProxyRewrite.dev2info['UniqueDeviceID'])
                print("replace path %s -> %s" % (old_path, path))
        elif hostname == 'p62-fmfmobile.icloud.com' or hostname == 'p59-fmfmobile.icloud.com' or hostname == 'p57-fmfmobile.icloud.com' or hostname == 'p51-fmfmobile.icloud.com' or hostname == 'p31-fmfmobile.icloud.com' or hostname == 'p29-fmfmobile.icloud.com' or hostname == 'p15-fmfmobile.icloud.com':
                old_path = path
                path = path.replace(ProxyRewrite.dev1info['UniqueDeviceID'], ProxyRewrite.dev2info['UniqueDeviceID'])
                print("replace path %s -> %s" % (old_path, path))
        elif (hostname == 'p62-mobilebackup.icloud.com' or hostname == 'p59-mobilebackup.icloud.com' or hostname == 'p57-mobilebackup.icloud.com' or ['Host'] == 'p51-mobilebackup.icloud.com' or hostname == 'p29-mobilebackup.icloud.com' or hostname == 'p15-mobilebackup.icloud.com'):
                old_path = path
                path = path.replace(ProxyRewrite.dev1info['UniqueDeviceID'], ProxyRewrite.dev2info['UniqueDeviceID'])
                print("replace path %s -> %s" % (old_path, path))
        elif hostname == 'p62-quota.icloud.com' or hostname == 'p59-quota.icloud.com' or hostname == 'p57-quota.icloud.com' or ['Host'] == 'p51-quota.icloud.com' or hostname == 'p31-quota.icloud.com' or hostname == 'p29-quota.icloud.com' or hostname == 'p15-quota.icloud.com':
                old_path = path
                path = path.replace(ProxyRewrite.dev1info['UniqueDeviceID'], ProxyRewrite.dev2info['UniqueDeviceID'])
                print("replace path %s -> %s" % (old_path, path))
        elif hostname == 'gspe35-ssl.ls.apple.com' or hostname == 'gspe1-ssl.ls.apple.com':
                old_path = path
                path = path.replace(ProxyRewrite.dev1info['ProductType'], ProxyRewrite.dev2info['ProductType'])
                path = path.replace(ProxyRewrite.dev1info['BuildVersion'], ProxyRewrite.dev2info['BuildVersion'])
                path = path.replace(ProxyRewrite.dev1info['ProductVersion'], ProxyRewrite.dev2info['ProductVersion'])
                print("replace path %s -> %s" % (old_path, path))
        elif hostname == 'p20-buy.itunes.apple.com':
                old_path = path
                path = path.replace(ProxyRewrite.dev1info['UniqueDeviceID'], ProxyRewrite.dev2info['UniqueDeviceID'])
                print("replace path %s -> %s" % (old_path, path))
        elif hostname == 'configuration.apple.com':
                old_path = path
                path = path.replace("9.0.plist", "10.1.plist")
                print("replace path %s -> %s" % (old_path, path))
        return path

def start():
    return ProxyRewrite(sys.argv[1], sys.argv[2])
