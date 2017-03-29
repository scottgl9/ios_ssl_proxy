#!/usr/bin/python2.7

import binascii
import struct
import sys
import os
from OpenSSL import crypto, SSL
import hashlib

if sys.argv[1:]:
        filename = sys.argv[1]
else:
    print("Usage: %s <filename>" % sys.argv[0])
    exit(0)

TYPE_RSA = crypto.TYPE_RSA
key=None
if os.path.isfile(filename):
    st_cert=open(filename, 'rb').read()
    cert=crypto.load_certificate(crypto.FILETYPE_ASN1, st_cert)
    issuer = cert.get_issuer()
    #if issuer.OU: issuer.OU = '\x01'
    issuerdata = issuer.der()
    index = issuerdata.find('1')
    issuerdata = issuerdata[index:]

    #if issuer.OU: issuerdata = issuerdata[:-12]
    print(repr(issuerdata))
    issuerhash = hashlib.sha1(issuerdata).hexdigest()

    print(issuerhash)
