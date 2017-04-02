#!/bin/bash
# In Ubuntu, copy them into /usr/local/share/ca-certificates and run sudo update-ca-certificates.
#openssl s_client -showcerts -servername $1 -connect $1:443 </dev/null
PORT=443
if [ $# -eq 2 ]; then
    PORT=$2
fi
echo "hostname $1 port $PORT"
ex +'g/BEGIN CERTIFICATE/,/END CERTIFICATE/p' <(echo | openssl s_client -showcerts -connect $1:$PORT) -scq
