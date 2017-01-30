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
fo = open("SSL.bin", "wb")
#fo2 = open("CCDigest.bin", "wb")
fo3 = open("functionlog.txt", "wt")
#fo4 = open("CCCryptorCreateWithMode", "wb")
#fo5 = open("decode.bin", "wb")
#fo6 = open("aesencrypt.bin", "wb")
script = session.create_script("""
var f1 = Module.findExportByName("libMobileGestalt.dylib", "MGCopyAnswer");
Interceptor.attach(f1, {
    onEnter: function (args) {
        this.dataPtr = ObjC.Object(args[0]);
    },
    onLeave: function (retval) {
	val = ObjC.Object(retval);
	if (this.dataPtr.toString() == 'SerialNumber') {
		retval.replace(ObjC.classes.NSString.stringWithString_("PWNEDBYSCOTT"));
	}
	/*
	if (this.dataPtr.toString() == 'ProductVersion') {
		retval.replace(ObjC.classes.NSString.stringWithString_("10.1.1"));
	}
	*/
	send("MGCopyAnswer: " + this.dataPtr.toString() + "=" + val.toString());
   }
});
""")
def on_message(message, data):
	pname = message['payload']
	print(pname)
	fo3.write(pname+"\n")

try:
    script.on('message', on_message)
    script.load()
    sys.stdin.read()
except KeyboardInterrupt as e:
    fo.close()
    #fo2.close()
    fo3.close()
    #fo4.close()
    #fo5.close()
    #fo6.close()
    sys.exit(0)
