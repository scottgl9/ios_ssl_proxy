#!/bin/sh
service usbmuxd stop
rm -f /var/lib/lockdown/*
cd /home/scottgl/build/usbmuxd
make uninstall
cd /home/scottgl/build/libimobiledevice
make uninstall
cd /home/scottgl/build/libusbmuxd
make uninstall
./autogen --prefix=/usr
make clean
make
make install
cd /home/scottgl/build/libimobiledevice
./autogen --prefix=/usr
make clean
make
make install
cd /home/scottgl/build/usbmuxd
./autogen --prefix=/usr
make clean
make
make install
cd /home/scottgl/build/libideviceactivation
make uninstall
./autogen --prefix=/usr
make clean
make
make install
service daemon-reload
service usbmuxd start

