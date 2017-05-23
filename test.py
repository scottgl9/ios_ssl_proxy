#!/usr/bin/python
import socket
import ssl
from OpenSSL import SSL
#s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#s = ssl.wrap_socket(s, ca_certs="server_certs/APNCertChain.crt", cert_reqs=ssl.CERT_REQUIRED)
#s.connect(("17.249.60.13", 443))
TLSv1_2_METHOD = 6
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ctx = SSL.Context(SSL.TLSv1_2_METHOD)
ctx.load_verify_locations("APNCertChain.crt")
s.connect(("17.249.60.13", 5223))
sock = SSL.Connection(ctx, s)
sock.set_tlsext_host_name("courier.push.apple.com")
sock.set_connect_state()
sock.do_handshake()
#context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
#context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
#context.set_alpn_protocols(["apns-security-v2"])
#context.options |= ssl.OP_NO_TLSv1 | ssl.OP_TLS_BLOCK_PADDING_BUG
#context.verify_mode = ssl.CERT_REQUIRED
#context.load_verify_locations(capath="APNCertChain.crt")
#s = context.wrap_socket(s, server_hostname='courier.push.apple.com')
#s.connect(("17.249.60.13", 5223))
