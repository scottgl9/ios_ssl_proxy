#!/usr/bin/python2.7

import requests
import json
import plistlib

class ProxyTSS:
    BoardConfig = None
    BuildID = None
    Manifest = None
    ECID = "7143879912186918"

    def __init__(self, model):
        r = requests.get('http://api.ineal.me/tss/all')
        jobj = json.loads(r.text)
        mobj = jobj[model]
        self.BoardConfig = mobj['board']
        self.BuildID = mobj['firmwares'][0]['build']
        print("%s, %s" % (self.BoardConfig, self.BuildID))
        r = requests.get('http://api.ineal.me/tss/manifest/%s/%s' % (self.BoardConfig, self.BuildID))
        self.Manifest = r.text.replace('<string>$ECID$</string>', '<integer>%s</integer>' % (self.ECID))
        #r = requests.get('http://api.ineal.me/tss/buildmanifest/%s/%s' % (self.BoardConfig, self.BuildID))
        #print(r.text)

    def request_blobs_from_apple(self):
        url = 'http://gs.apple.com/TSS/controller?action=2'
        r = requests.post(url, data=self.Manifest)
        #if not r.status_code == requests.codes.ok:
        #    return { 'MESSAGE': 'TSS HTTP STATUS:', 'STATUS': r.status_code }
        p = plistlib.readPlistFromString(r.text.replace("STATUS=0&MESSAGE=SUCCESS&REQUEST_STRING=", ""))
        
        with open("apticket.cer", "wb") as f: f.write(p['ApImg4Ticket'].data)
        #return parse_tss_response(r.text)

tss = ProxyTSS("iPhone7,1")
tss.request_blobs_from_apple()
