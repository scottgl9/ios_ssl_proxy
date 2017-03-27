#!/bin/sh
# Redirect SSL traffic from NAT'd clients to iSniff as follows:
# To delete rule:
# iptables -t nat -D PREROUTING -p tcp --destination-port 5223 -j REDIRECT --to-ports 8080

sysctl -w net.ipv4.ip_forward=1
#iptables -t nat -F
iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-ports 8080
#iptables -t nat -A PREROUTING -p tcp --destination-port 389 -j REDIRECT --to-ports 8080
iptables -t nat -A PREROUTING -p tcp --destination-port 443 -j REDIRECT --to-ports 8080
#iptables -t nat -A PREROUTING -p tcp --destination-port 636 -j REDIRECT --to-ports 8080
#iptables -t nat -A PREROUTING -p tcp --destination-port 993 -j REDIRECT --to-ports 8080
#iptables -t nat -A PREROUTING -p tcp --destination-port 5223 -j REDIRECT --to-ports 8080
#iptables -t nat -A PREROUTING -p tcp --destination-port 5228 -j REDIRECT --to-ports 8080
#iptables -t nat -A PREROUTING -p tcp --destination-port 1640 -j REDIRECT --to-ports 8080
#iptables -t nat -A PREROUTING -p tcp --destination-port 2194 -j REDIRECT --to-ports 8080
#iptables -t nat -A PREROUTING -p tcp --destination-port 2195 -j REDIRECT --to-ports 8080
#iptables -t nat -A PREROUTING -p tcp --destination-port 2196 -j REDIRECT --to-ports 8080
#iptables -t nat -A PREROUTING -p tcp --destination-port 2336 -j REDIRECT --to-ports 8080
#iptables -t nat -A PREROUTING -p tcp --destination-port 4398 -j REDIRECT --to-ports 8080
#iptables -t nat -A PREROUTING -p tcp --destination-port 16384 -j REDIRECT --to-ports 8080
#iptables -t nat -A PREROUTING -p tcp --destination-port 16385 -j REDIRECT --to-ports 8080
#iptables -t nat -A PREROUTING -p tcp --destination-port 16386 -j REDIRECT --to-ports 8080
