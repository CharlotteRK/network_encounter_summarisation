
#include <pcap.h>
#include <stdio.h>
#include <iostream>
#include <stdlib.h>

int main(void) {
	char* file = "../../AcadBldg16";
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_offline(file, errbuf);
	
	struct pcap_pkthdr *header;
	const u_char *data;
	u_int packetCount = 0;
	
	while (int returnValue = pcap_next_ex(pcap, &header, &data) >= 0) {
		printf("Time: %ld\n\n", header->ts.tv_sec);
		packetCount++;
		
	}
	printf("Packet Count: %d\n\n", packetCount);
	return EXIT_SUCCESS;
}
