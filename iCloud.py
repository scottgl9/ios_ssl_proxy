#!/usr/bin/python2.7
import os
import sys
import base64
import plistlib
import requests

class iCloud:
    appleid = None
    dsPrsID = None
    mmeAuthToken = None
    aDsID = None

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
        headers = {'Authorization': 'Basic %s' % iCloud.encode(self.dsPrsID, self.mmeAuthToken)}
        r = requests.get('https://setup.icloud.com/setup/get_account_settings', headers=headers)
        if r.status_code == 200:
            p = plistlib.readPlistFromString(r.text)
            self.aDsID = p['appleAccountInfo']['aDsID']
            print("aDsID=%s" % self.aDsID)

if sys.argv[2:]:
    appleid = sys.argv[1]
    password = sys.argv[2]

icloud = iCloud(appleid, password)
icloud.getAccountSettings()
