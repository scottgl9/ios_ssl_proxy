#!/bin/sh
idevicesyslog | egrep --invert-match "com_apple_MobileAsset|wirelessproxd" | egrep --color=auto "([a-f0-9]{8} [a-f0-9]{8} [a-f0-9]{8} [a-f0-9]{8} [a-f0-9]{8})|([A-Fa-f0-9]{2}){10,11}"
