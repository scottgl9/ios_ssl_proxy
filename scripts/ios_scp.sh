#!/bin/sh

#sshpass -p 'alpine' scp -rv root@192.168.12.173:/System/Library/Security/Certificates.bundle .
sshpass -p 'alpine' scp -rv root@192.168.12.173:/private/var/Keychains/TrustStore.sqlite3 .
