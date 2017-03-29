#!/usr/bin/python2.7

import binascii
import struct
import sys
import os
from OpenSSL import crypto, SSL
import hashlib
import hmac

# FOUND HASH ce7bb519fd2c57b5b56c2ac49174f60a208cd04e pos=55 len=56 in certsTable.data 

# found hash ce7bb519fd2c57b5b56c2ac49174f60a208cd04e with pos=55 len=56
# found hash ce7bb519fd2c57b5b56c2ac49174f60a208cd04e with pos=145 len=56
# found hash ce7bb519fd2c57b5b56c2ac49174f60a208cd04e with pos=1592 len=56
# found hash ce7bb519fd2c57b5b56c2ac49174f60a208cd04e with pos=1682 len=56
# found hash 90798777573773b9f45f05b3ce2019618c707825 with pos=6949 len=69
# found hash 90798777573773b9f45f05b3ce2019618c707825 with pos=7052 len=69
# found hash fae3a76047b56651ced60a4780480f38246512c0 with pos=30248 len=81
# found hash fae3a76047b56651ced60a4780480f38246512c0 with pos=30363 len=81
# found hash 3347452ab1b6d6d4468600dae01ee33e4617d280 with pos=13428 len=90
# found hash 3347452ab1b6d6d4468600dae01ee33e4617d280 with pos=13552 len=90
# found hash 5b5db9a8fe00e82f317b0aa9acf56f6b7cab0b71 with pos=17097 len=100
# found hash 5b5db9a8fe00e82f317b0aa9acf56f6b7cab0b71 with pos=17231 len=100
# found hash 8304ff77b4809b2917db62a59a296b01289fa82f with pos=25416 len=117
# found hash 8304ff77b4809b2917db62a59a296b01289fa82f with pos=25571 len=117
# found hash fc43f2c518e5b0175f254eb9a99c744316047876 with pos=5027 len=299
# found hash fc43f2c518e5b0175f254eb9a99c744316047876 with pos=5362 len=299

filename=None
hashstr=None
if sys.argv[1:]:
        filename = sys.argv[1]
        #hashstr = sys.argv[2]
else:
    print("Usage: %s <filename> <sha1 hash>" % sys.argv[0])
    exit(0)

data=bytes(open(filename, 'rb').read())

print("loading file length=%d" % len(data))

initdata = data[55:55+56]
inithash=hashlib.sha1(initdata).hexdigest()
print("hash %s at pos 55 len 56" % inithash)

startlen=4
startpos=0
for curlen in range(startlen, len(data)):
    for pos in range(startpos, len(data)):
        if (pos + curlen) > len(data): continue
        
        curdata = data[pos:pos+curlen]
        #m = hashlib.sha1()
        #m.update(initdata)
        #m.update(curdata)
        #curhash=m.hexdigest()
        curhash=hashlib.sha1(curdata).hexdigest()
        #print("pos=%d len=%d hash=%s" % (pos, curlen, curhash))
        if curhash == "ce7bb519fd2c57b5b56c2ac49174f60a208cd04e":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "67fd2674399188f36bf29b77336e07aaadf49f71":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "3c0265c582e2f0fc3dca1b5b5f860fe404a8d407":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "b52dbdd63f9000847681174d645f708d9c8da57e":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "834e1dfd3bd562d1e1a8bb84469249f1a22af789":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "fc43f2c518e5b0175f254eb9a99c744316047876":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "05d7679b8bbed8ad3ecaf8f4c85c7588fe6bdd60":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "90798777573773b9f45f05b3ce2019618c707825":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "5a6059918442dc35c29b3cde7e4022ca08e82228":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "a86a8205bc23cf30354ec37786c59731215fa0fc":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "e28ea58a7c1888395f7d96668ab3a1520164199a":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "3347452ab1b6d6d4468600dae01ee33e4617d280":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "5b5db9a8fe00e82f317b0aa9acf56f6b7cab0b71":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "49586176acd0b405e296679af41d5e24ad7d0da7":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "edde9bb498370b4f34814c9aab1e25fd00aec5cd":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "138bcd35a0e53dc1683627e3ff36b6219006d109":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "26afc0f153ef794bb7f7137f7efb6cfc6c8bd1aa":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "dcdc8ae1535e06785f83112c85c317eca1cbd66a":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "65a7df62d7f739f1cb6843ab49de8ff390bafd0b":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "a37daa5f36daa889f15bd6753af1304508de0c8a":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "8304ff77b4809b2917db62a59a296b01289fa82f":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "ac934de5e900d1d2d3fe561514fa5891ec6f2b2a":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "798baea2b88b8a383a3a2f54244e8d48528f0cd9":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "f52bd93c48a7f1ad90850f8357f724d3f52c2193":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "4891173ff74a18dabbd2794a1985979c718156c0":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "fae3a76047b56651ced60a4780480f38246512c0":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))

