#!/usr/bin/python2.7
from OpenSSL import crypto
import time
import hashlib

TYPE_RSA = crypto.TYPE_RSA

 # create a key pair
key = crypto.PKey()
key.generate_key(crypto.TYPE_RSA, 2048)

with open("ca.key", "w") as key_file:
    key_file.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))

req = crypto.X509Req()
#subject = issuerCert.get_subject()
req.get_subject().CN = "Proxy2 CA"
req.get_subject().O = "Apple Inc."
req.get_subject().OU = "Certificate Authority"
req.get_subject().C = "US"
req.set_pubkey(key)
req.sign(key, "sha1")
cert = crypto.X509()
try:
    cert.set_serial_number(int(hashlib.md5(req.get_subject().CN.encode('utf-8')).hexdigest(), 16))
except OpenSSL.SSL.Error:
    epoch = int(time.time() * 1000)
    cert.set_serial_number(epoch)
cert.gmtime_adj_notBefore(0)
cert.gmtime_adj_notAfter(60 * 60 * 24 * 3650)
cert.set_issuer(req.get_subject())
cert.set_subject(req.get_subject())
subject = req.get_subject()
#subject.OU = "Apple Root CA"
#subject.CN = "Proxy2 CA"
cert.set_issuer(subject)
cert.add_extensions([
    crypto.X509Extension("basicConstraints", True, "CA:TRUE, pathlen:0"),
    crypto.X509Extension("nsCertType", True, "sslCA"),
    crypto.X509Extension("extendedKeyUsage", True, "serverAuth,clientAuth,emailProtection,timeStamping,nsSGC"),
    crypto.X509Extension("keyUsage", True, "keyCertSign, cRLSign"),
    crypto.X509Extension('subjectKeyIdentifier', False, 'hash', subject=cert)
])

#cert.add_extensions([OpenSSL.crypto.X509Extension(b'subjectAltName', True, ', '.join('DNS: %s' % x for x in sans))])
cert.set_pubkey(req.get_pubkey())
cert.sign(key, "sha256")
with open("ca.crt", "w") as cert_file:
    cert_file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
