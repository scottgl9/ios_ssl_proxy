#!/usr/bin/python2.7
import os
import sys
import base64
import plistlib
import requests
import re
from icloud_pb2 import MBSAccount, MBSBackup, MBSKeySet, MBSFile, MBSFileAuthToken, MBSFileAuthTokens
from httplib import HTTPSConnection

def probobuf_request(host, method, url, body, headers, msg=None):
    print "DEBUG", method, host, url
    h = HTTPSConnection(host)
    #headers["Accept"] = "application/vnd.com.apple.mbs+protobuf"
    r = h.request(method, url, body, headers)
    res = h.getresponse()
    #if res.status != 200:
    print "DEBUG STATUS = %d" % res.status
    length = res.getheader("content-length")
    print "DEBUG STATUS = %d, %s" % (res.status, length)
    if length == None: length = 0
    else: length = int(length)
    data = res.read()
    print(data)
    while len(data) < length:
        d = res.read()
        data += d
    h.close()
    if msg == None:
        return data
    res = msg()
    res.ParseFromString(data)

class iCloud:
    appleid = None
    dsPrsID = None
    mmeAuthToken = None
    aDsID = None
    mobilebackup_host = None
    content_host = None


    def __init__(self, appleid, password):
        self.appleid = appleid
        self.authenticate(appleid, password)

    @staticmethod
    def encode(val1, val2):
        return str(base64.b64encode("%s:%s" % (val1, val2)))

    def authenticate(self, appleid, password):
        headers = {'Authorization': 'Basic %s' % iCloud.encode(appleid, password)}
        r = requests.get('https://setup.icloud.com/setup/authenticate/%s' % appleid, headers=headers)
        if r.status_code == 401:
            print("login failed for %s" % appleid)
            exit(-1)
        elif r.status_code == 200:
            p = plistlib.readPlistFromString(r.text)
            self.dsPrsID = p['appleAccountInfo']['dsPrsID']
            self.mmeAuthToken = p['tokens']['mmeAuthToken']       
            print("dsPrsID=%s, mmeAuthToken=%s" % (self.dsPrsID, self.mmeAuthToken))

    def getAccountSettings(self):
        Client_Info = "<iPhone2,1> <iPhone OS;6.1.6;10B500> <com.apple.AppleAccount/1.0 ((null)/(null))>"
        USER_AGENT_UBD = "ubd (unknown version) CFNetwork/548.1.4 Darwin/11.0.0"
        headers = { 
            'Authorization': 'Basic %s' % iCloud.encode(self.dsPrsID, self.mmeAuthToken),
            "X-MMe-Client-Info": Client_Info,
            "User-Agent": USER_AGENT_UBD
        }
        print('https://setup.icloud.com/setup/get_account_settings')
        r = requests.get('https://setup.icloud.com/setup/get_account_settings', headers=headers)
        if r.status_code == 200:
            p = plistlib.readPlistFromString(r.text)
            self.aDsID = p['appleAccountInfo']['aDsID']
            #print("Updating mmeAuthToken from %s to %s" % (self.mmeAuthToken, p['tokens']['mmeAuthToken']))
            self.mmeAuthToken = p['tokens']['mmeAuthToken']
            mobilebackup_url = p["com.apple.mobileme"]["com.apple.Dataclass.Backup"]["url"]
            content_url = p["com.apple.mobileme"]["com.apple.Dataclass.Content"]["url"]
            self.mobilebackup_host = re.match("https://(.*):443", mobilebackup_url).group(1)
            self.content_host = re.match("https://(.*):443", content_url).group(1)

    def getInitSettings(self):
        print('https://setup.icloud.com/configurations/init?context=settings')
        headers = {'X-MMe-Client-Info': '<iPhone2,1> <iPhone OS;6.1.6;10B500> <com.apple.AppleAccount/1.0 (com.apple.Preferences/1.0)>'}
        r = requests.get('https://setup.icloud.com/configurations/init?context=settings', headers=headers)
        if r.status_code == 200:
            print(r.status_code)

    def getBackupId(self):
        USER_AGENT_MOBILE_BACKUP = "MobileBackup/6.1.6 (10B500; iPhone2,1)"
        Client_Info = "<iPhone2,1> <iPhone OS;6.1.6;10B500> <com.apple.AppleAccount/1.0 ((null)/(null))>"
        auth = "X-MobileMe-AuthToken %s" % base64.b64encode("%s:%s" % (self.dsPrsID, self.mmeAuthToken))
        headers = {"Authorization": auth,
                        "X-MMe-Client-Info": Client_Info,
                        "User-Agent": USER_AGENT_MOBILE_BACKUP,
                        "X-Apple-MBS-Protocol-Version": "1.7" }

        r = requests.get('https://'+self.mobilebackup_host+'/mbs/%s' % self.dsPrsID, headers=headers)
        print(r.status_code)
        print(r.text)

    def mobileBackupRequest(self, method, url, msg=None, body=""):
        USER_AGENT_MOBILE_BACKUP = "MobileBackup/6.1.6 (10B500; iPhone2,1)"
        Client_Info = "<iPhone2,1> <iPhone OS;6.1.6;10B500> <com.apple.AppleAccount/1.0 ((null)/(null))>"
        auth = "X-MobileMe-AuthToken %s" % base64.b64encode("%s:%s" % (self.dsPrsID, self.mmeAuthToken))
        headers = {"Authorization": auth,
                        "X-MMe-Client-Info": Client_Info,
                        "User-Agent": USER_AGENT_MOBILE_BACKUP,
                        "X-Apple-MBS-Protocol-Version": "1.7" }

        return probobuf_request(self.mobilebackup_host, method, url, body, headers, msg)
    
    def getAccount(self):
        return self.mobileBackupRequest("GET", "/mbs/%s" % self.dsPrsID, MBSAccount)

if sys.argv[2:]:
    appleid = sys.argv[1]
    password = sys.argv[2]

icloud = iCloud(appleid, password)
icloud.getAccountSettings()
icloud.getInitSettings()
icloud.getAccountSettings()
#icloud.getBackupId()
account = icloud.getAccount()
print(account)
