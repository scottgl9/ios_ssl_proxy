#!/bin/sh
idevicesyslog | egrep --invert-match "com_apple_MobileAsset|wirelessproxd" | egrep --color=auto "([a-f0-9]{8} [a-f0-9]{8} [a-f0-9]{8} [a-f0-9]{8} [a-f0-9]{8})|[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}|([A-Fa-f0-9]{2}){10,11}"
