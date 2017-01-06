#!/bin/sh
rm -f ~/.mitmproxy/mitmproxy-dhparam.pem
cp ca.cer ~/.mitmproxy/mitmproxy-ca.pem
cp ca.cer ~/.mitmproxy/mitmproxy-ca-cert.pem
cp ca.crt ~/.mitmproxy/mitmproxy-ca-cert.cer
openssl pkcs12 -export -inkey ca.key -in ca.crt -out ~/.mitmproxy/mitmproxy-ca-cert.p12
