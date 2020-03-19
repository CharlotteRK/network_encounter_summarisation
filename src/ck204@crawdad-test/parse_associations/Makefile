parse_tcpdump: parse_tcpdump.cpp parse.h
	g++ -g parse_tcpdump.cpp -L"../inc/libpcap-1.9.0" "../inc/libdbus-1.so" -I"../inc/libpcap-1.9.0" -ldbus-1 -lpcap -Wall -o parse_tcpdump

clean:
	rm -f *.o
