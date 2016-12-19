#!/bin/sh
# Redirect SSL traffic from NAT'd clients to iSniff as follows:

iptables -t nat -A PREROUTING -p tcp --destination-port 443 -j REDIRECT --to-ports 8080
