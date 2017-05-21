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
                var lastmodule="";
                var lastmodulebase=0;
                var modulelist = [];
                while (1) {
                    module = modules.pop();
                    if (!module) { break; }
                    if (lastmodule == "") {
                        lastmodule = module.name;
                        lastmodulebase = module.base;
                        continue;
                    }
                    line = { "name":module.name, "start":parseInt(module.base,16), "end":parseInt(lastmodulebase,16) };
                    modulelist.push(line);
                    lastmodule = module.name;
                    lastmodulebase = module.base;
                }
		var ranges = Process.enumerateRangesSync({protection: 'r--', coalesce: true});
		var range;
                while (1) {
			range = ranges.pop();
			if(!range){
				break;
			}
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
                                    send(range.base, bytes);
                                }

                            } else if (name == "ApplePushService") {
                                if (parseInt(range.base,16) >= modulelist[i].start && range.size < 1000000) {
                                    console.log(modulelist[i].name+":"+range.size);
                                    var bytes = Memory.readByteArray(range.base, range.size);
                                    send(range.base, bytes);
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
