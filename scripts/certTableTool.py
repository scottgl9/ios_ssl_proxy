#!/usr/bin/python2.7
# used to unpack certsTable.data

import binascii
import struct
import sys
import os
from OpenSSL import crypto, SSL

import binascii
import struct
import sys
import os

if sys.argv[1:]:
        cmdtype = sys.argv[1]
else:
    print("Usage: %s unpack|pack" % sys.argv[0])
    exit(0)

def extract_certs(filename):
	count=0
	st_key=bytearray(open(filename, 'rb').read())
        #dirname = ("%s_extracted" % os.path.splitext(os.path.basename(filename))[0])
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

# block_length determines the offset to the next 8 bytes before the cert.
# index_length is the actual length of the certificate, and if index_length < block_length,
# then the rest of the block is padded with 0xFF bytes
# block_length = index_length & 0x10
def unpack_certTable(filename):
        st_key=bytearray(open(filename, 'rb').read())
        index=0
        count=0
        dirname = "certsTable" #% os.path.splitext(os.path.basename(filename))[0])
        #os.mkdir(dirname, 0755 )

        while index < len(st_key):
                index = st_key.find("\x30\x82", index)
                if index < 0: break
                clength = struct.unpack(">h", st_key[index+2:index+4])[0] + 5
                index_length = struct.unpack("<I", st_key[index-4:index])[0]
                block = struct.unpack("<I", st_key[index-8:index-4])[0]
                print("index=%d, index_length=%x, block_length=%x" % (index, index_length, block))
                certdata = st_key[index:index+clength]
                cert=crypto.load_certificate(crypto.FILETYPE_ASN1, bytes(certdata))
                #print(cert.digest('sha1').replace(':',''))
                #print(cert.get_subject())
                with open(os.path.join(dirname, "%d.cer" % count), "wb") as f:
                        f.write(certdata)
                count = count + 1
                index = index + clength

def pack_certTable(path):
       index=0
       count=0
       outf = open("certsTable.data.new", "wb")

       while 1:
           filepath = os.path.join(path, "%d.cer" % count)
           if os.path.isfile(filepath):
               certdata=open(filepath, 'rb').read()
               certlen = len(certdata)
               print("loading %s: len=%x" % (filepath, certlen))
               outf.write(certdata)
           else: break
           count = count + 1
       outf.close()

if cmdtype == 'unpack': 
    print("Unpacking certsTable.data to certsTable directory...")
    unpack_certTable("certsTable.data")
elif cmdtype == 'pack':
    print("Packing certsTable directory to certsTable.data...")
    pack_certTable("./certsTable")
