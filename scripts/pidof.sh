#!/bin/sh
ps -ax | grep -m 1 "$1" | grep -v pidof | awk '{print $1}'
