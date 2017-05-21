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
		var ranges = Process.enumerateRangesSync({protection: 'r--', coalesce: true});
		var range;
                while (1) {
			range = ranges.pop();
			if(!range){
				break;
                        }
                        if (range.size < 1048576) {
                            console.log(range.base+":"+range.size);
                            var bytes = Memory.readByteArray(range.base, range.size);
                            send('%s'+range.base, bytes);
                        } else {
                            //base = range.base
                            console.log("Splitting "+range.base+":"+range.size);
                            //splitcnt = range.size / 1048576
                            //for(var i = 0; i < (splitcnt-1); i++) {
                            var bytes = Memory.readByteArray(range.base, 1048576);
                            //    console.log(range.base);
                            send('%s'+range.base, bytes);
                                //range.base.add(1048576)
                            //}
                        }
		}
""" % (target_process, target_process))

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
