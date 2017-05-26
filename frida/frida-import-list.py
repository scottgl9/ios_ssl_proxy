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

def list_imports(target_process):
	session = frida.get_usb_device().attach(target_process)
        print("Listing imports for %s:" % target_process)
        script = session.create_script("""
                var modules = Process.enumerateModulesSync();
                var module;
                for (var i=0; i<modules.length; i++) {
                    module = modules[i];
                    console.log("\t"+module.name+":"+module.base+":"+module.size);
                }
""")

        script.on('message', on_message)
        script.load()
        session.detach()

if __name__ == '__main__':
	if len(sys.argv) < 2:
		print 'Usage: %s <process name or PID>' % __file__
		sys.exit(1)

	try:
		target_process = int(sys.argv[1])
	except ValueError:
		target_process = sys.argv[1]

	list_imports(target_process)
        sys.exit(0)
