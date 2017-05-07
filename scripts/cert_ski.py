#!/usr/bin/python2.7
from OpenSSL import crypto
import time
import os.path
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Util import asn1
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Util.asn1 import DerSequence, DerObject
import sys
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import binascii

TYPE_RSA = crypto.TYPE_RSA
key=None

if sys.argv[1:]:
    filename = sys.argv[1]
else:
    print("Usage: %s <filename>" % sys.argv[0])
    exit(0)

st_cert=open(filename, 'rb').read()
cert = x509.load_der_x509_certificate(st_cert, default_backend())
print(str(binascii.hexlify(x509.SubjectKeyIdentifier.from_public_key(cert.public_key()).digest)))
