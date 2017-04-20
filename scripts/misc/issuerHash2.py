#!/usr/bin/python2.7

import binascii
import struct
import sys
import os
from OpenSSL import crypto, SSL
import hashlib

if sys.argv[2:]:
        filename = sys.argv[1]
        exphash = sys.argv[2]
else:
    print("Usage: %s <filename> <hash>" % sys.argv[0])
    exit(0)

def remove_bytes(buffer, start, end):
    fmt = '%ds %dx %ds' % (start, end-start, len(buffer)-end)  # 3 way split
    return b''.join(struct.unpack(fmt, buffer))

def testByteRemove(data, exphash):
    
    startlen=1
    startpos=0
    for curlen in range(startlen, len(data)):
        for pos in range(startpos, len(data)):
            if (pos+curlen) > len(data): continue
            issuerdata = remove_bytes(data, pos, pos+curlen)
            #print(issuerdata)
            issuerhash = hashlib.sha1(issuerdata).hexdigest()
            if issuerhash == exphash:
                print("found hash %s with pos %d len %d" % (exphash, pos, curlen))
                exit(0)

TYPE_RSA = crypto.TYPE_RSA
key=None
if os.path.isfile(filename):
    st_cert=open(filename, 'rb').read()
    cert=crypto.load_certificate(crypto.FILETYPE_ASN1, st_cert)
    issuer = cert.get_issuer()
    components=issuer.get_components()
    #print(components)

    complist = [a for a,b in components]
    req = crypto.X509Req()

    # add in order
    #for i, (a, b) in enumerate(components):
    #    if a == 'CN':
    #        req.get_subject().CN = issuer.CN
    #    elif a == 'C':
    #        req.get_subject().C = issuer.C
    #    elif a == 'OU':
    #        req.get_subject().OU = issuer.OU
    #    elif a == 'O':
    #        #if issuer.C != 'JP' or (issuer.C == 'JP' and 'Japan' not in issuer.O):
    #        if len(issuer.O) > 64: req.get_subject().O = issuer.O[:64]
    #        else: req.get_subject().O = issuer.O

    #print(repr(issuer))
    #print(repr(req.get_subject()))
    issuerdata = cert.get_subject().der()
    #else: issuerdata = req.get_subject().der()
    #index = issuerdata.find('1')
    #issuerdata = issuerdata[index:]
    testByteRemove(issuerdata, exphash)

    #with open(("%s.data" % filename), "wb") as f: f.write(issuerdata)

    #issuerhash = hashlib.sha1(issuerdata).hexdigest()

    #print(issuerhash)
