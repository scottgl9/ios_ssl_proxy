#!/usr/bin/python2.7
import binascii

data = ''
with open("B262_App.txt","rt") as f:
    for line in f:
        if '@' in line: continue
        if 'q' in line: continue
        data = ('%s%s' % (data, line.replace(' ', '').strip()))
data = binascii.unhexlify(data)

with open("B262_App.bin", "wb") as file:
    file.write(data)
