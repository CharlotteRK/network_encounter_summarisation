#include <pcap.h>
#include <stdio.h>
#include <iostream>
#include <stdlib.h>

int main(int argc,char *argv[]) {
	if (argc < 2) {
		printf("error: no file argument given");
		exit(1);
	}
	std::string file = argv[1];
	printf("File: %s\n", file.c_str());
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_offline(file.c_str(), errbuf);
	
	struct pcap_pkthdr* header;
	const u_char* data;
	u_int packetCount = 0;
	
	u_int totLength = 0;
	
	while (int returnValue = pcap_next_ex(pcap, &header, &data) > 0) {
		
		totLength = totLength + header->len;
		packetCount++;
		
	}
	
	printf("Mean packet length: %d\n", totLength/packetCount);
	printf("Packet Count: %d\n\n", packetCount);
	
}
