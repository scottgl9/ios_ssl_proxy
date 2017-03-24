#!/bin/sh
# search for hex string in binary file using xxd and grep

FILENAME=$1
HEXSTR=$2
hexdump -e '16/1 "%02x"' $FILENAME | grep -i $HEXSTR
