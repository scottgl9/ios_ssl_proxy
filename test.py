#!/usr/bin/python
import socket
import ssl
from OpenSSL import SSL
from twisted.application import internet, service
from twisted.python import log
from twisted.spread import pb

#s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#s = ssl.wrap_socket(s, ca_certs="server_certs/APNCertChain.crt", cert_reqs=ssl.CERT_REQUIRED)
#s.connect(("17.249.60.13", 443))
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("17.249.60.13", 5223))
ctx = SSL.Context(SSL.TLSv1_2_METHOD)
ctx.set_options(SSL.OP_NO_TLSv1)
ctx.use_certificate_chain_file("APNCertChain.crt")
ctx.set_alpn_protos([b'apns-security-v2'])
sock = SSL.Connection(ctx, s)
sock.set_tlsext_host_name("courier.push.apple.com")
sock.set_alpn_protos([b'apns-security-v2'])
sock.set_connect_state()
#sock.connect(("17.249.60.13", 5223))
while True:
    try:
        sock.do_handshake()
    except SSL.WantReadError:
        select.select([s], [], [])
        continue
    except SSL.Error as e:
        raise ssl.SSLError('bad handshake %v', e)
    break
sslsock = WrappedSocket(ctx, s)

