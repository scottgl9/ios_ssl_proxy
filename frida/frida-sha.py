#!/usr/bin/python2.7
import frida
import sys

# MobileGestalt functions:
# CFPropertyListRef MGCopyAnswer(CFStringRef property);
# int MGSetAnswer(CFStringRef question, CFTypeRef answer);
# Boolean MGGetBoolAnswer(CFStringRef property);
# MGGetSInt32Answer
# Note: the SHA1 hashes seem to be the SHA1 hashes of DER certificates

session = frida.get_usb_device().attach("Settings")
fo2 = open("CCSHA256.bin", "wb")
fo3 = open("functionlog.txt", "wt")
fo4 = open("CCSHA1.bin", "wb")
#fo5 = open("decode.bin", "wb")
#fo6 = open("aesencrypt.bin", "wb")
script = session.create_script("""
var f1 = Module.findExportByName("libSystem.B.dylib",
    "CC_SHA1");
Interceptor.attach(f1, {
    onEnter: function (args) {
		var bytes = Memory.readByteArray(args[0], args[1].toInt32());
		send("CC_SHA1", bytes);
    }
});
var f2 = Module.findExportByName("libSystem.B.dylib",
    "CC_SHA256");
Interceptor.attach(f2, {
    onEnter: function (args) {
                var bytes = Memory.readByteArray(args[0], args[1].toInt32());
                send("CC_SHA256", bytes);
    }
});
var f3 = Module.findExportByName("libSystem.B.dylib",
    "CC_SHA256_Update");
Interceptor.attach(f3, {
    onEnter: function (args) {
                var bytes = Memory.readByteArray(args[1], args[2].toInt32());
                send("CC_SHA256", bytes);
    }
});
var f4 = Module.findExportByName("libSystem.B.dylib",
    "CC_SHA1_Update");
Interceptor.attach(f4, {
    onEnter: function (args) {
                var bytes = Memory.readByteArray(args[1], args[2].toInt32());
                send("CC_SHA1", bytes);
    }
});
""")
def on_message(message, data):
	if 'payload' in message:
		pname = message['payload']
		print(pname)
		fo3.write(pname+"\n")
		if (pname == "CC_SHA256"):
			fo2.write(data)
		if (pname == "CC_SHA1"):
			fo4.write(data)
	#elif (pname == "CCDigest"):
	#	fo2.write(data)
	#elif (pname == "CCCryptorCreateWithMode"):
	#	fo4.write(data)
	#elif (pname == "CCCryptorGCMAddIV"):
	#	fo5.write(data)
	#elif (pname == "AES_cbc_encrypt"):
	#	fo6.write(data)
try:
    script.on('message', on_message)
    script.load()
    sys.stdin.read()
except KeyboardInterrupt as e:
    fo2.close()
    fo3.close()
    fo4.close()
    #fo5.close()
    #fo6.close()
    sys.exit(0)
