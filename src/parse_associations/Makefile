parse_tcpdump: parse_tcpdump.cpp parse.h
	g++ -I "/cs/home/ck204/Documents/CS4098/src/inc/libpcap-1.9.0" parse_tcpdump.cpp -L/cs/home/ck204/Documents/CS4098/src/inc/libpcap-1.9.0 -lpcap -ldbus-1 -Wall -o parse_tcpdump
parse_syslog: parse_syslog.cpp parse.h
	g++ parse_syslog.cpp -ldbus-1 -Wall -o parse_syslog
clean:
	rm -f *.o
