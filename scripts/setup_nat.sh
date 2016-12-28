#!/bin/sh
# Redirect SSL traffic from NAT'd clients to iSniff as follows:

sysctl -w net.ipv4.ip_forward=1
iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-ports 8080
iptables -t nat -A PREROUTING -p tcp --destination-port 443 -j REDIRECT --to-ports 8080
iptables -t nat -A PREROUTING -p tcp --destination-port 993 -j REDIRECT --to-ports 8080
iptables -t nat -A PREROUTING -p tcp --destination-port 5223 -j REDIRECT --to-ports 8080
