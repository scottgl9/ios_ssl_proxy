#!/bin/sh

tar cvpzf var.tar.gz --exclude='/var/mobile/Media/Downloads/*' /private/var
