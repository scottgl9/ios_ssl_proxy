#!/usr/bin/python2.7
from OpenSSL import crypto
import time
import os.path

TYPE_RSA = crypto.TYPE_RSA
key=None
if os.path.isfile("cert.key"):
    st_key=open("test.key", 'rt').read()
    key=crypto.load_privatekey(crypto.FILETYPE_PEM, st_key)
else:
    # create a key pair
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)
    with open("test.key", "w") as key_file:
        key_file.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))

st_cert=open("orig.crt", 'rt').read()
cert=crypto.load_certificate(crypto.FILETYPE_PEM, st_cert)
cert.set_pubkey(key)
cert.sign(key, "sha256")
with open("test.crt", "w") as cert_file:
    cert_file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
