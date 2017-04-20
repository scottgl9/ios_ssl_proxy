#!/bin/bash
cp -v com.apple.apsd.plist /tmp
plutil -key KeepAlive -remove com.apple.apsd.plist
plutil com.apple.apsd.plist
cp -v /tmp/com.apple.apsd.plist .
