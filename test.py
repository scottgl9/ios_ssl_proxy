#!/usr/bin/python2.7
from OpenSSL import crypto
import time

TYPE_RSA = crypto.TYPE_RSA

certKey=crypto.load_privatekey(crypto.FILETYPE_PEM, open("cert.key", 'rt').read())
issuerCert=crypto.load_certificate(crypto.FILETYPE_PEM, open("ca.crt", 'rt').read())
issuerKey=crypto.load_privatekey(crypto.FILETYPE_PEM, open("ca.key", 'rt').read())

req = crypto.X509Req()
req.get_subject().CN = "albert.apple.com"
req.set_pubkey(certKey)
req.sign(certKey, "sha1")
#csrstr = crypto.dump_certificate_request(crypto.FILETYPE_PEM, req)
epoch = int(time.time() * 1000)
cert = crypto.X509()
cert.set_serial_number(epoch)
cert.gmtime_adj_notBefore(0)
cert.gmtime_adj_notAfter(60 * 60 * 24 * 3650)
cert.set_issuer(issuerCert.get_subject())
cert.set_subject(req.get_subject())
cert.set_pubkey(req.get_pubkey())
cert.sign(issuerKey, "sha256")
with open("test.crt", "w") as cert_file:
    cert_file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
