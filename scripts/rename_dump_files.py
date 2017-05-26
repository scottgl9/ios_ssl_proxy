#!/usr/bin/python

import os

for filename in os.listdir("."):
    if '.dmp' not in filename: continue
    addr = filename.split('.')[0].replace('dump', '')
    addr = str.format('{:08X}', int(addr, 16))
    newfilename = ("dump0x%s.dmp" % addr)
    if (filename == newfilename): continue
    print("rename %s to %s" % (filename, newfilename))
    os.rename(filename, newfilename)
