#!/usr/bin/python2.7
import frida
import sys

# MobileGestalt functions:
# CFPropertyListRef MGCopyAnswer(CFStringRef property);
# int MGSetAnswer(CFStringRef question, CFTypeRef answer);
# Boolean MGGetBoolAnswer(CFStringRef property);
# MGGetSInt32Answer
# Note: the SHA1 hashes seem to be the SHA1 hashes of DER certificates
# CONSTANT: kCFStringEncodingMacRoman 0 inline

session = frida.get_usb_device().attach("Settings")
script = session.create_script("""
var f1 = Module.findExportByName("libMobileGestalt.dylib", "MGCopyAnswer");
Interceptor.attach(f1, {
    onEnter: function (args) {
        this.dataPtr = ObjC.Object(args[0]);
    },
    onLeave: function (retval) {
	argstr = this.dataPtr.toString();
	retval = ObjC.Object(retval);
	if (retval.$superClass == "__NSCFString") {
		if (argstr == 'ProductType') {
			//retval.replace(ObjC.classes.NSString.stringWithString_("iPhone7,1"));
		}
		send("MGCopyAnswer: " + this.dataPtr.toString() + "=" + retval.cString());
	} else if (retval.$superClass == "NSMutableString") {
                if (argstr == 'SerialNumber') {
			retval.setString([retval.$superClass stringWithString:@"PWNEDBYSCOTT"]);
                }
                else if (argstr == 'UniqueDeviceID') {
                }

		send("MGCopyAnswer: " + this.dataPtr.toString() + "=" + retval.cString());
	}

	/*
	if (this.dataPtr.toString() == 'SerialNumber') {
		retval.replace(ObjC.classes.NSString.stringWithString_("PWNEDBYSCOTT"));
	}
	else if (this.dataPtr.toString() == 'ProductVersion') {
		retval.replace(ObjC.classes.NSString.stringWithString_("10.1.1"));
	}
	else if (this.dataPtr.toString() == 'UniqueDeviceID') {
	}
	*/
   }
});
var f2 = Module.findExportByName("libMobileGestalt.dylib", "MGGetSInt32Answer");
Interceptor.attach(f2, {
    onEnter: function (args) {
        this.dataPtr = ObjC.Object(args[0]);
    },
    onLeave: function (retval) {
	send("MGGetSInt32Answer: " + this.dataPtr.toString());
    }
});
var f3 = Module.findExportByName("libMobileGestalt.dylib", "MGGetBoolAnswer");
Interceptor.attach(f3, {
    onEnter: function (args) {
        this.dataPtr = ObjC.Object(args[0]);
    },
    onLeave: function (retval) {
	send("MGGetBoolAnswer: " + this.dataPtr.toString());
    }
});
""")
def on_message(message, data):
	if 'payload' in message:
		pname = message['payload']
		print(pname)

try:
    script.on('message', on_message)
    script.load()
    sys.stdin.read()
except KeyboardInterrupt as e:
    sys.exit(0)
