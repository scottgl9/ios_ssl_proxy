/usr/bin/python2.7
import frida
import sys

# Note: the SHA1 hashes seem to be the SHA1 hashes of DER certificates

session = frida.get_usb_device().attach("akd")
script = session.create_script("""
var f2 = Module.findExportByName("Security",
    "SecTrustEvaluate");
Interceptor.attach(f2, {
    onEnter: function (args) {
        this.dataPtr = ObjC.Object(args[1]);
        args[1] = 1;
        log("SecTrustEvaluate(" + 4 + ")");
    },
    onLeave: function (retval) {
        log("SecTrustEvaluate(" + "" + ")");
	retval = 0;
	send("SecTrustEvaluate", this.dataPtr);
    }
});
""")
#def on_message(message, data):
	#pname = message['payload']
	#print(pname)
	#fo3.write(pname+"\n")
	#if (pname == "CFWriteStreamWrite"):
	#	fo.write(data)
	#elif (pname == "SecTrustEvaluate"):
	#	if data != None: fo.write(data)
	#elif (pname == "CCDigest"):
	#	fo2.write(data)
	#elif (pname == "CCCryptorCreateWithMode"):
	#	fo4.write(data)
	#elif (pname == "CCCryptorGCMAddIV"):
	#	fo5.write(data)
	#elif (pname == "AES_cbc_encrypt"):
	#	fo6.write(data)
try:
    #script.on('message', on_message)
    script.load()
    sys.stdin.read()
except KeyboardInterrupt as e:
    sys.exit(0)
