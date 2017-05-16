all:
	gcc idevicesyslog.c common/utils.c -I/usr/include -L/usr/lib/x86_64-linux-gnu -lssl -lcrypto -lplist -lplist++ -limobiledevice -o idevicesyslog

clean:
	rm -f idevicesyslog
