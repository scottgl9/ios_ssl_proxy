#!/usr/bin/env python

import os
import sys
import time
import plist
from imobiledevice import *
#LockDownClient

def print_domain_values(ld, domain=None):
    if domain != None:
        print(ld.get_value(domain=domain).keys()) 
    else:
        print(ld.get_value().keys())


def main():
    print(get_device_list())
    lockdown = LockdownClient(iDevice())
    print_domain_values(lockdown)

if __name__ == '__main__':
    main()
