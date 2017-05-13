#!/usr/bin/env python

import os
import sys
import time
import plist
from imobiledevice import *
from subprocess import *
import fcntl
import time

#LockDownClient
##define SYSLOG_RELAY_SERVICE_NAME "com.apple.syslog_relay"

def non_block_read(output):
    fd = output.fileno()
    fl = fcntl.fcntl(fd, fcntl.F_GETFL)
    fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
    try:
        return output.read()
    except:
        return ""

class SyslogClient(BaseService):
        __service_name__ = "com.apple.syslog_relay"

def print_domain_values(ld, domain=None):
    if domain != None:
        print(ld.get_value(domain=domain).keys()) 
    else:
        for item in ld.get_value().keys():
            try:
                val = ld.get_value(key=item)
                if type(val) == plist.Data or type(val) == plist.Dict or type(val) == plist.Array: continue
                print("%s = %s" % (str(item), val))
            except LockdownError:
                continue

def trusted_host_attached(ld):
    if "TrustedHostAttached" in ld.get_value().keys():
        return ld.get_value(key="TrustedHostAttached")
    return False

def lockdown_get_service_client(service_class):
    ld = LockdownClient(iDevice())
    return ld.get_service_client(service_class)

def main():
    print(get_device_list())
    lockdown = LockdownClient(iDevice())
    #print_domain_values(lockdown)
    if trusted_host_attached(lockdown):
        sb = Popen("idevicesyslog | egrep --color=auto \"([a-f0-9]{8} [a-f0-9]{8} [a-f0-9]{8} [a-f0-9]{8} [a-f0-9]{8})|([A-Fa-f0-9]{2}){10,11}\"", shell=True, stdout=PIPE)
        try:
            while 1:
                time.sleep(1)
                output = non_block_read(sb.stdout)
                if output != "": print(output)
        except KeyboardInterrupt:
            sb.kill()

if __name__ == '__main__':
    main()
