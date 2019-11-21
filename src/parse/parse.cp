#include <pcap.h>
#include <stdio.h>
#include <iostream>
#include <stdlib.h>
#include <cstring>
#include "parse.h"


char UNKNOWN_FILE_FORMAT[20] = "unknown file format";
char TRUNCATED_DUMP_FILE[20] = "truncated dump file";
int ETHERNET_TYPE = 1;
int IEEE802_11_TYPE = 2;
int ETHERNET_SIZE = 14;

int main(int argc,char *argv[]) {

	std::string file = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE]  = {'\0'};
	pcap_t* pcap = pcap_open_offline(file.c_str(), errbuf);
	if (errbuf[0] != '\0') {
		printf("Error in parse: %s\n", errbuf);
	}
	struct pcap_pkthdr* header;
	const u_char* data;
	u_int packetCount = 0;
	u_int totLength = 0;
	char err[20] = {'\0'};

	//Find size of the data link header
	/*TODO: I thought I should be getting 802.11 files here but all which I
			have checked are coming out as ethernet*/
	int dataLinkOffest;
	int pkt_link_type;
	if (pcap_datalink(pcap) == DLT_EN10MB) {
		printf("Found ethernet file!!\n");
		dataLinkOffest = ETHERNET_SIZE;
		pkt_link_type = ETHERNET_TYPE;
	}
	else if (pcap_datalink(pcap) == DLT_IEEE802_11) {
		dataLinkOffest = 22;
		pkt_link_type = IEEE802_11_TYPE;
		printf("Found 802.11 file!!\n");
	}
	u_char dataLinkHeader[dataLinkOffest];

	strncpy(err, errbuf, 19);
	if (strcmp(err, TRUNCATED_DUMP_FILE) != 0 && strcmp(err, UNKNOWN_FILE_FORMAT) != 0) {
		struct bpf_program prog;
		pcap_compile(pcap, &prog, "ether", 0, PCAP_NETMASK_UNKNOWN);
		pcap_setfilter(pcap, &prog);
		while (int returnValue = pcap_next_ex(pcap, &header, &data) > 0) {
			totLength = totLength + header->len;

			//isolate the headers
			const struct ether_hdr* ethernet;
			const struct ip_hdr* ip;
			const struct tcp_hdr* tcp;

			if (pkt_link_type == ETHERNET_TYPE) {
				ethernet = (struct ether_hdr*)(data);
				if (ntohs(ethernet->ethertype) == 0x0800) { //IPv4 Packet
					ip = (struct ip_hdr*)(data + dataLinkOffest);
					u_short size_ip = ip->len;

					tcp = (struct tcp_hdr*)(data + dataLinkOffest + size_ip);
					printf("source address: %u.%u.%u.%u\n", ip->src.s_addr >> 24, (ip->src.s_addr >> 16) & 0xff, (ip->src.s_addr >> 8) & 0xff, ip->src.s_addr & 0xff );
					printf("destin address: %u.%u.%u.%u\n", ip->dst.s_addr >> 24, (ip->dst.s_addr >> 16) & 0xff, (ip->dst.s_addr >> 8) & 0xff, ip->dst.s_addr & 0xff );
				}
				else {
					printf("Ethertype: %x\n", ntohs(ethernet->ethertype));
				}
			}

			packetCount++;
		}
		if (packetCount > 0) {
			//output some stuff			
		}
	}
}
