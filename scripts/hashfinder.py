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
# found hash 4c94e14a51b67b8329922ea7f6ea4cf780b8b0b0 with pos=37873 len=75
# found hash 4c94e14a51b67b8329922ea7f6ea4cf780b8b0b0 with pos=37982 len=75
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
        elif curhash == "67fd2674399188f36bf29b77336e07aaadf49f71":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "67fd2674399188f36bf29b77336e07aaadf49f71":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "5a6059918442dc35c29b3cde7e4022ca08e82228":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "a86a8205bc23cf30354ec37786c59731215fa0fc":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "e28ea58a7c1888395f7d96668ab3a1520164199a":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "3347452ab1b6d6d4468600dae01ee33e4617d280":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "f2ea479e379692cef8444ced2ef2ee0fac75e35d":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "f2ea479e379692cef8444ced2ef2ee0fac75e35d":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "5b5db9a8fe00e82f317b0aa9acf56f6b7cab0b71":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "49586176acd0b405e296679af41d5e24ad7d0da7":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "edde9bb498370b4f34814c9aab1e25fd00aec5cd":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "26afc0f153ef794bb7f7137f7efb6cfc6c8bd1aa":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "138bcd35a0e53dc1683627e3ff36b6219006d109":
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
        elif curhash == "bd344aed1ca71ba11d23fe392cf46e7450930feb":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "e638a10b4adcad2812d50bdd25aa378b03afe6eb":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "3efd41b251f0442934952d8145a73578fa37d699":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "7e8ce92407582d7c67cb2130bd32cbe04be4017a":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "042c4aa2cfb35d8c2e45bf4ae86c338609b86b60":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "4c94e14a51b67b8329922ea7f6ea4cf780b8b0b0":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "d09869d379c1eee845b5bba9cb553afe17058ed4":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "d325dd4865cf158dec66e3b09a8c4be656a9900b":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "6690d79001e66961396ec086b434607660ca4134":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "6ff6cd1a7d8fdd0f6d2bbd6ef81d78d99e8dfe57":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "69a71a02ac6d483b918358483e60fc4be5deb88a":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "3f86e5ef98fe1b3b3b819c150c909467bd6ae592":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "4a73d5620cb284bdffc6283c3ddbfee6ff144d65":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "a28fc734426f730e66a62c7421aa63d6bfa0f42f":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "ffd2a5bc849512bbb650a2bb7d04f6f0358c3dcf":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "17a90c39c493fee2128864e6d63193bb3027e2e1":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "74574c5fd5bcb0851666e12d601b1c96c3d60a31":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "cfd4e05658b53b55e65cdc5c7c0768136b2c62fa":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "2eb089564c2f4d59f8b5f06a0749d9fed0ad345f":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "72cbb1cd244ca8ad48eb5d581292d373894dc702":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "598516ef2913d2e85a76c26d6506309aa188564e":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "dbc10746ecf7428cec3f728dc1d76a9eaa145f6b":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "83e18176434a71e3a00d2afa608d117a8d9cd783":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "b703986b44026a324a8d3f41af0f6a2fa66910ae":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "5e9fdae0cd8403db675f6ea2c8243ad614d28dcd":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "6bc0d2c88fe34730aa2a6fed1639c600aaff0ec4":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "9de6a2d73b66a69a207b585dc47ca40e93047c70":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "215bf2eebec904d49d6072a3894a3ea5948a3688":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "a880c29430ad814682a0942039fbdad2eaccdff3":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "68b654ef0d82d1b962d7b2cc09a51fd9949849da":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "4e91725f9e3bd64b34ba6f31994b543b8e09226a":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "bc3cac07cc117aeb7d7966ff5e97826783c692d6":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "c1259865c501e5abb22c6c42c2d938fd4dcdf9a7":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "c913202c4fd2718b345b86f45f23c8a4230803a6":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "def5969cc08964a25891ede75de8cbba467b6bb0":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "136f24a2c8b41164e8e5b1b9e9a4f52d0e2afde0":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "536caab1d9bded8bbc749a482e70d69fa51d45ee":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "9f4a8322b1cfc6ebd933e2e490b0c89e7b33d735":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "387a2a5cce1d6aa2c1891d5389182e8d02505a37":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "19fb614e56c239b46c8db2b4339255fd1bdf3541":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "670f9628b34073a8c5e9642e6bbfeae6a764f557":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "ff5fb1c01585f8196927e009e229e37df0d61b8f":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "e01b7858b3fc3c49ba7e314ce165d619d12905d9":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "2200ad13581b6e290c2abb84167a41a763496518":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "ee802964c8601f77e2af4f0997d12e38e84f1fc9":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "b3bf3e0a132d4ac356b9128d050f407763add41b":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "41a73072f14fb59ff67fa5c84804cf3b7b34ac63":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "b4bcc787b2566b781ddcceaf30ef9ef1d1000462":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "8d0a2e5e1585391ced286424ac4e41ccf82184a4":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "d3af94dd41d2ac737c32c7dbe7651bc45a52b006":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "07d81e0f3cc8c6730df6f1cb3eec14adeeca53dd":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "f03abb98e293711dfb4d8fd2e32e7294fe91425d":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "5e47d20a20f273d528d5e6c08ecf5b2e25f2b911":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "f1ea418b1cdedae915f2ef7b986b447afb91cd33":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "e3347309e0c10fe832c404d93a87e4078a783b44":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "e4971d84b9fd6eccf1fb3f757c35d0f2183665ce":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "a0f7e4cb6e7b51b5597be6c42aafbfb100a02ff6":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "6eaf91dccc9aacfe8b3a3f90b3eabb36d2d6d421":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "eead83e6edb095758eff8af2aaf637ce2f5eef40":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "5cf523ad0554b9559c3e73afe941c56174ca2925":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "5d5195c57958cb6687c41bafe3faf8cae39ae800":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "b61703ca7cab016eaf1d2081098bd4d85bdfe510":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "522548e33f1eab126c5283cc62b49a969644ccbb":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "78a0517596559665f12afd369535a7a10e717479":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "9c6351dafed4c7b62b9e1877d4a33c840a1e12a9":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "cc79502406a98af43daa28689362b990b88285cd":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "461b81e2a2d805d59e40ca8fbf5290f06c01a0f3":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "f182ed8681bdbffe39d767a2ddada6e1f30ee4e8":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "3a2bc436e153c993237a6e7b7f1b1c717831dfce":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "afdee45fc56562b9245450e104959295f45de377":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "090a10eab121619dbdcd647bd3b038618fde01ee":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "19da1fa8189a5895eb84475b11a30ffa64cd0523":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "16ed8643c493898f804c5ed9596c80128348f0b3":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "ceecef50f02f272a4b6aa5cc882caa02ff111cfd":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "ed095def559a275355be2d0b7ad517d3103fb1dd":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "49399167d8cdb3d3ce3b8a3b6c64181c4fb6f808":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "fa81c4f2b63c9a582c89cca3a5dfe199b7ce9ad0":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "20d335698ae69c33d5b3faae9fc925ffa72537fb":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "309abbc98601e09b3c9252c882b2a27086f6ddb7":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "cd3cca4d3101297f59b66e010109398bd2787dee":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "c7233045bc954f6f311a6cb17dff91530fa16416":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "2200ea437c033232598d6347595a899b8b4deca6":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "23c85a880f4ab998f7f778451cb5f771921a0fa7":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "0734991dbb569ce212834d9e7d1c4dc07c3fed33":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "ccf0e066f1bfa0995e172714da45eaa53b9a0cb7":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "dab7e8c94f3f0a9f1a04d7279d0231dd4d3f0e4b":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "0587a1c9230d295386fc1d5524b4b62ccd2856f9":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "c7072c8a2c34dc68870d1920f8cf289ef4ea61ae":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "2e273bdd8ac90dd6601e1b6a547638e4e565a9d4":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "e1f7be8ac60d69e339927be42035e7afff34c8fb":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "4e0f81971d6342012a12d196626b09bdcc1bee85":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "20524a88f504f441d3e796bad74fec4a120fd715":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "391f460ede149158e34f0881c3ea9f11fd6b7ff6":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "2789aeec302ebbe633999585f625668a04d56f85":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "13d25c9cab9bce5e5d1940711c9a3b2556e397dd":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "67f8bac38acfbe56d5032c7d836c70f749bf4ac4":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "00619b5fd5dba7c42fcc7d5aba8e368794b19ae4":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "b5eeeedff0acbf3fee8ebb878a90aebce262f608":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "490b8bdcc87b38bea6dea985afdbcaba9c4d1046":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "de517d367e105689c4680e530f0df3d55634ff90":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "6cb450454df1f9d5307e498440b6e5fe8e82d04a":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "fe80dbdf0082036cc4d4b3a846e36c7e117d943e":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "7cb99b180b6b0bfff9343dbc5041d42b405a8440":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "cc7fa734b2b8763a3605d223acacff1860283a51":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "549bc53496968e371ad1d3914c71e733ba7721cf":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "3637efcff1f09e7ddb6f5134c3a08ddf6b13b0f8":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "374fe13049fe5fdb840a5ce98778547c4aeb40a0":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "0f670c9d3511aecd204f7bd7996c2146fc8ba738":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "015e48c4630fa8615a81bd81d9887acdae6a5d8d":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "5045b7385e3b00d9334968faa47a8ad21921d267":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "ff51c0f5977bbba38c22858df613c081075b1f03":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "c322f271e2841c794e70db57664af0008b1797ba":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "e503dc1448ee64ea8793cbfa62c0d715062bc67a":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "3c0265c582e2f0fc3dca1b5b5f860fe404a8d407":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "3c0265c582e2f0fc3dca1b5b5f860fe404a8d407":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "2355825a3a7fde1669129aae7aeee11b262adde3":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "1f20d9b038d2c5e7c40c4386c8f3761aae564f4e":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "2a935a150cec8661e98bf30ac715c90827243fc4":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "7eed5aec0e1dbe32af81e41c82b1c3e4e5966e6b":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "be6bf639abde4ad59c121d7f28eda5835e051627":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "b6e44f78d871d1fd680b5b5b25bc6ca5e204ed86":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "6a910f9449e1b49b12beeac6af658d07adc07728":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "142738da111bd7a0d0d16fb0c1d265c0b9801112":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "73f15d7ec58320a152d9b293053812ded7b59550":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "867a1b7e709ff114db8d8e84a028a555b3ea199c":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "7a7322f4078b4282366e41463430bd4be3aa5d2d":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "dd272b948e82f62f504f39ce9282f2c5e8b21964":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "6c847a6a7d297a472bb1f77ae911fa1ffbe0e8c0":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "1caa26fadda95025a46badaf1b4c656f0a41443c":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "06872ee61507db420effdbd27b07b6b2974d7158":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "a798ee8b287a252ef6674e91669d8f17c65d77f0":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "e49375516b5acbe46d1abc216dc08e36a68d21c8":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "a0739607e5a6f19a0b16f2576fd4a8aaeb03e0fc":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "1d6539480fc95d51c63976e3ec0a7bbcb35f3cdc":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "b6d299eada78623ff3c896707571741c335b6492":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "7e06e7533473b897a47ba51a016c6ee0daa520bc":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "ce1368041c6fde8528c72791c46b095e1bd18d51":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "ec823e7e09e935db2a3861ef0f6970e9b93f623e":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "55717deaa62959bb72c40afd010f9992796a9f00":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "7ad0469968c41d47bcde96739c40237ae7ffbbba":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "a888eb1220701cd1d849d3d8b33a5ac4d98cb449":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "56e67b0346cc983138dd97c3476541bd154e11e7":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "55b2cfbb54b3ee7cbb3c36239ef9f6ec45cd16c7":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "9b90dc702f8ccd69e0219e9d56bac6b3a3a5d614":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "b84737cd38323c6d353c2f54d27908a1cacd94d3":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "3774c9aaf7ea4d49d010adbcba449d9691c6adc6":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "43cfb1b6138b10039b59d3096022c4be53d9f6e3":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "b8c3a0b118070f0f240244df195650928461f07b":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "0315707f53dded4622c014541806752b688b0e98":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "dfbde3f69fb5f710b128c32a005179d994d48f03":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "5e211447e2b673b3c8ee9f3f3725085e10459577":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "24e906883d49547237acfd56a460c92bcf12f841":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "a524e415f828d332158930ed22620e1ce93683d1":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "98d99e8d9137b8fbe739cab6b42c8b6f98f084a0":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "78478c1b426190cbecb08a9bbb77e42e5a225631":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "f39d0c41716ed61230b439c378acd65ed009beb5":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "d5aeca26a4d6409105e02b50a1b677da9a9d0879":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "7c67c3e0082fe2f73c925bc10d12c1b4735e9e77":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "940d14b80e26adf64ed8ed9646489980e867469b":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))
        elif curhash == "bd8f76c40b0e0a300e8f4c820fc1c12dc8005cd9":
            print("found hash %s with pos=%d len=%d" % (curhash, pos, curlen))

