#!/usr/bin/python2.7
# extracts all DER certs from given filename

import binascii
import struct
import sys
import os

if sys.argv[1:]:
        filename = sys.argv[1]
else:
    print("Usage: %s <filename>" % sys.argv[0])
    exit(0)

def extract_certs(filename):
	count=0
	st_key=bytearray(open(filename, 'rb').read())
        dirname = ("%s_extracted" % os.path.splitext(os.path.basename(filename))[0])
        os.mkdir(dirname, 0755 )

        while 1: 
		index = st_key.find("\x30\x82")
		if index < 0: break
		length = struct.unpack(">h", st_key[index+2:index+4])[0] + 5
                if length > len(st_key):
                    print("Length of %d extends past end" % length)
                    return
		print("index=%d, length=%d" % (index, length))
		certdata = st_key[index:index+length]
		with open(os.path.join(dirname, "%d.cer" % count), "wb") as f:
			f.write(certdata)
                count = count + 1
		st_key = st_key[index+length:]

extract_certs(filename)
