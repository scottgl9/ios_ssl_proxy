#!/usr/bin/python2.7
# used to unpack certsTable.data
# The certsIndex.data file is a Database Index file that contains an array which can be read using NSData,
# this contains a list of sha1 hashes and offsets. 


import binascii
import struct
import sys
import os
from OpenSSL import crypto, SSL
import hashlib

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
                ilength = struct.unpack("<I", st_key[index-4:index])[0]
                blength = struct.unpack("<I", st_key[index-8:index-4])[0]
                if (ilength + 8) & 7: calclength = ((ilength + 8) & (~7)) + 8
                else: calclength = ilength + 8
                if calclength != blength: print("%x != %x" % (calclength, blength))
                print("index=%d, index_length=%x, block_length=%x, calclength=%x" % (index, ilength, blength, calclength))
                certdata = st_key[index:index+ilength]
                cert=crypto.load_certificate(crypto.FILETYPE_ASN1, bytes(certdata))
                certhash = hashlib.sha1(crypto.dump_publickey(crypto.FILETYPE_ASN1, cert.get_pubkey())).hexdigest()
                print(certhash)
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
               ilength = len(certdata)
               calclength = ilength + 8
               if (ilength + 8) & 7: calclength = ((ilength + 8) & (~7)) + 8
               print("loading %s: len=%x blen=%x" % (filepath, ilength, calclength))
               outf.write(struct.pack("<I", calclength))
               outf.write(struct.pack("<I", ilength))
               outf.write(certdata)
               outf.write("\xFF" * (calclength - ilength - 8))
           else: break
           count = count + 1
       outf.close()

def unpack_indexTable(filename, path):
    inf = open(filename, 'rb')
    outf = open("certsTable/certsIndex.txt", "wb")
    count=0
    while 1:
        hashdata = inf.read(20)
        if hashdata == None: return
        if len(hashdata) <= 0: return
        index = struct.unpack("<I", inf.read(4))[0] + 8
        filepath = os.path.join(path, "%d.cer" % count)
        outf.write("%s %s %d\n" % (filepath, binascii.hexlify(hashdata), index))
        count=count + 1

def pack_indexTable(path):
    outf = open("certsIndex.data.new", "wb")
    with open('certsTable/certsIndex.txt') as f:
        for line in f:
            parts = line.strip().split(' ')
            print(parts)
            indexbin = struct.pack("<I", int(parts[2])-8)
            outf.write(binascii.unhexlify(parts[1]))
            outf.write(indexbin)
    outf.close()


if cmdtype == 'unpack': 
    print("Unpacking certsTable.data to certsTable directory...")
    unpack_certTable("certsTable.data")
    unpack_indexTable("certsIndex.data", "certsTable")
elif cmdtype == 'pack':
    print("Packing certsTable directory to certsTable.data...")
    #pack_certTable("./certsTable")
    pack_indexTable("certsTable")
