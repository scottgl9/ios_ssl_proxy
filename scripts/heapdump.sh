#!/bin/bash
if [ "$1" == "" ]
	then
		echo "Usage: ./$0 <binary_name>"
		exit 1
fi
rm -f gdbcmd.txt
PID=`pidof $1`
echo "App Pid: $PID"
echo "info mach-regions" > tmp.txt
gdb --pid="$PID" --batch --command=tmp.txt 2>/dev/null | grep sub-regions | awk '{print $3,$5}' | while read range; do
	echo "mach-regions: $range"
	cmd="dump binary memory dump`echo $range| awk '{print $1}'`.dmp $range"
	echo "$cmd" >> gdbcmd.txt
done
rm -f tmp.txt
echo -n "Dumping memory: "
gdb --pid=$PID --batch --command=gdbcmd.txt &>>/dev/null
echo "Done"
