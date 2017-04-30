#!/usr/bin/python2.7
from OpenSSL import crypto
import time
import os.path
import sys

TYPE_RSA = crypto.TYPE_RSA

def rewrite_der_cert(data, key=None):
    cert=crypto.load_certificate(crypto.FILETYPE_ASN1, data)
    algtype = cert.get_signature_algorithm()
    keysize = cert.get_pubkey().bits()
    print(algtype)
    if key == None:
        # create a new key pair
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, keysize)
        derkey = crypto.dump_privatekey(crypto.FILETYPE_PEM, key)
    cert.set_pubkey(key)
    if (algtype.startswith('sha256')):
        cert.sign(key, "sha256")
    elif (algtype.startswith('sha1')):
        cert.sign(key, "sha1")
    dercert = crypto.dump_certificate(crypto.FILETYPE_ASN1, cert)
    #derkey = crypto.dump_privatekey(crypto.FILETYPE_ASN1, key)
    return dercert

def get_cert_info(data):
    if (data.startswith("\x30\x82")):
        cert=crypto.load_certificate(crypto.FILETYPE_ASN1, data)
    else:
        cert=crypto.load_certificate(crypto.FILETYPE_PEM, data)
    algtype = cert.get_signature_algorithm()
    keysize = cert.get_pubkey().bits()
    return algtype, keysize

if sys.argv[1:]:
        filename = sys.argv[1]
else:
    print("Usage: %s <cert filename>" % sys.argv[0])
    exit(0)
    
st_cert=open(filename, 'rb').read()
print(get_cert_info(st_cert))
#certdata = rewrite_der_cert(st_cert)
#with open(('%s.cert' % filename), 'wb') as outfile:
#    outfile.write(certdata)
