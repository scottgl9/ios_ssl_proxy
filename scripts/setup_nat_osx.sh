#!/bin/sh
echo "
rdr pass inet proto tcp from any to any port 80 -> 127.0.0.1 port 8080
rdr pass inet proto tcp from any to any port 443 -> 127.0.0.1 port 8080
rdr pass inet proto tcp from any to any port 5223 -> 127.0.0.1 port 8083
" | sudo pfctl -ef -
pfctl -s nat
#pfctl -f ./pf.conf
#networksetup -setsecurewebproxy 'Wi-Fi' 127.0.0.1 8080
#networksetup -setwebproxy 'Wi-Fi' 127.0.0.1 8080
