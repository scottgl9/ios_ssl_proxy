#!/bin/sh
rm -f pf.conf
echo "rdr pass on bridge0 inet proto tcp from 192.168.2.0/24 to any port http -> 127.0.0.1 port 8080" > pf.conf
echo "rdr pass on bridge0 inet proto tcp from 192.168.2.0/24 to any port https -> 127.0.0.1 port 8080" >> pf.conf
#pfctl -v -n -f ./pf.conf
#pfctl -f ./pf.conf
