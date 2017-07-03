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
                var modules = Process.enumerateModulesSync();
                var module;
                var moduledict = {};
                for (var i=0; i<modules.length; i++) {
                    //moduledict[module.base] = module.name;
                    console.log(module.name+":"+module.base+":"+module.size);
                }
		var ranges = Process.enumerateRangesSync({protection: 'r--', coalesce: true});
                var range;
                for (var j=0; j<ranges.length; j++) {
                        range = ranges[j]; //ranges.pop();
			console.log(range.base+":"+range.size+":"+range.protection);
                        for(var i=0; i<modulelist.length; i++) {
                            name = modulelist[i].name;
                            if (name == "%s") {
                                start = modulelist[i].start;
                                end = modulelist[i].end;
                                //console.log(name+":"+start+":"+end);
                                if (parseInt(range.base,16) <= end && parseInt(range.base,16) >= start) {
                                    console.log(modulelist[i].name);
                                    console.log(range.base+':'+range.size+':'+range.protection);
                                    var bytes = Memory.readByteArray(range.base, range.size);
                                    //send(range.base, bytes);
                                }

                            }
                        }
		}
""" % target_process)

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
