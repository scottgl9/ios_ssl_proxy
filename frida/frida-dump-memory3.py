#!/usr/bin/python
import sys
import frida
import time

def on_message(message, data):
    if 'payload' in message:
        pname = message['payload']
        filename = ("%s.bin" % pname)
        print("Writing %s" % filename)
        fo = open(filename, "wb")
        fo.write(data)
        fo.close()

def main(target_process):
	session = frida.get_usb_device().attach(target_process)
	script = session.create_script("""
                String.prototype.lpad = function(padString, length) {
                    var str = this;
                    while (str.length < length)
                        str = padString + str;
                        return ("0x"+str);
                }
                var modules = Process.enumerateModulesSync();
                var moduledict = {};
                for (var i=0; i<modules.length; i++) {
                    var key = modules[i].base.toString(16).lpad("0", 8);
                    moduledict[key] = modules[i].name+":"+modules[i].size;
                    //console.log(modules[i].name+":"+modules[i].base+":"+modules[i].size);
                }
                for(var key in moduledict) {
                  var value = moduledict[key];
                  console.log(key+":"+value);
                }
""")

        script.on('message', on_message)
        script.load()
        raw_input('[!] Press <Enter> at any time to detach from instrumented program.\n\n')
        session.detach()
        sys.exit(0)

if __name__ == '__main__':
	if len(sys.argv) < 2:
		print 'Usage: %s <process name or PID> <pattern in form "41 42 ?? 43">' % __file__
		sys.exit(1)

	try:
		target_process = int(sys.argv[1])
	except ValueError:
		target_process = sys.argv[1]

	main(target_process)
