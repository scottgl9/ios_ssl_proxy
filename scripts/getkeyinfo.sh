#!/bin/bash
openssl x509 -inform pem -in $1 -pubkey -noout > pub.key
openssl rsa -pubin -inform PEM -text -noout < pub.key
