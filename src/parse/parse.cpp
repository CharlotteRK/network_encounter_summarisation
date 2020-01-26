#include <pcap.h>
#include <stdio.h>
#include <iostream>
#include <stdlib.h>
#include <map>
#include <cstring>
#include "parse.h"


char UNKNOWN_FILE_FORMAT[20] = "unknown file format";
char TRUNCATED_DUMP_FILE[20] = "truncated dump file";
int ETHERNET_TYPE = 1;
int IEEE802_11_TYPE = 2;
int ETHERNET_SIZE = 14;
std::map<char*, long int*, comp_mac> association_map;

int main(int argc,char *argv[]) {

	std::string file = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE]  = {'\0'};
	pcap_t* pcap = pcap_open_offline(file.c_str(), errbuf);
	if (errbuf[0] != '\0') {
		fprintf(stderr, "Error in parse: %s\n", errbuf);
		exit(1);
	}
	struct pcap_pkthdr* header;
	const u_char* data;
	u_int packetCount = 0;
	char err[20] = {'\0'};
	//Find size of the data link header
	int dataLinkOffest;
	int pkt_link_type;
	if (pcap_datalink(pcap) == DLT_EN10MB) {
		//Found ethernet file
		dataLinkOffest = ETHERNET_SIZE;
		pkt_link_type = ETHERNET_TYPE;
	}
	else if (pcap_datalink(pcap) == DLT_IEEE802_11_RADIO) {
		//dataLinkOffest = 22;
		dataLinkOffest = 18;
		pkt_link_type = IEEE802_11_TYPE;
		//Found 802.11 file
	}
	else if (pcap_datalink(pcap) == DLT_PRISM_HEADER) {
		//dataLinkOffest = 22;
		dataLinkOffest = 144;
		pkt_link_type = IEEE802_11_TYPE;
		//Found 802.11 file
	}
	else {
		fprintf(stderr, "Found %d!!\n", pcap_datalink(pcap));
	}
	u_char dataLinkHeader[dataLinkOffest];
	strncpy(err, errbuf, 19);
	if (strcmp(err, TRUNCATED_DUMP_FILE) != 0 && strcmp(err, UNKNOWN_FILE_FORMAT) != 0) {
		struct bpf_program prog;
		pcap_compile(pcap, &prog, "ether", 0, PCAP_NETMASK_UNKNOWN);
		pcap_setfilter(pcap, &prog);
		while (pcap_next_ex(pcap, &header, &data) > 0) {
			//isolate the headers
			const struct ether_hdr* ethernet;
			const struct ip_hdr* ip;
			const struct tcp_hdr* tcp;
			char* macs_1 = (char*) malloc(35*sizeof(char));
			char* macs_2 = (char*) malloc(35*sizeof(char));
			long int* times = (long int*) malloc(3*sizeof(long int));
			long int dest_ap = 0;

			if(pkt_link_type == IEEE802_11_TYPE) {
				const struct act_ieee80211_hdr* link;
				link = (struct act_ieee80211_hdr*)(data + dataLinkOffest);
				dest_ap = (ntohl(link->fc) >> 16 & 2) ? 1 : 0;
				sprintf(macs_1, "%02x:%02x:%02x:%02x:%02x:%02x,%02x:%02x:%02x:%02x:%02x:%02x",\
				link->source[0], link->source[1], link->source[2],\
				link->source[3], link->source[4], link->source[5],\
				link->transmitter[0], link->transmitter[1], link->transmitter[2],\
				link->transmitter[3], link->transmitter[4], link->transmitter[5]);
				sprintf(macs_2, "%02x:%02x:%02x:%02x:%02x:%02x,%02x:%02x:%02x:%02x:%02x:%02x",\
				link->transmitter[0], link->transmitter[1], link->transmitter[2],\
				link->transmitter[3], link->transmitter[4], link->transmitter[5],\
				link->source[0], link->source[1], link->source[2],\
				link->source[3], link->source[4], link->source[5]);
			}

			else if (pkt_link_type == ETHERNET_TYPE) {
				ethernet = (struct ether_hdr*)(data);
				if (ntohs(ethernet->ethertype) == 0x0800) { //IPv4 Packet
					ip = (struct ip_hdr*)(data + dataLinkOffest);
					u_short size_ip = 4*(ip->vhl & 15);
					if(ip->prot == 0x06) {
						tcp = (struct tcp_hdr*)(data + dataLinkOffest + size_ip);
						dest_ap = ((ntohl(tcp->oflags) >> 16 & 2) ? 1 : 0)&&!((ntohl(tcp->oflags) >> 16 & 16) ? 1 : 0);
					}
					sprintf(macs_1, "%02x:%02x:%02x:%02x:%02x:%02x,%02x:%02x:%02x:%02x:%02x:%02x",\
					ethernet->src_host[0], ethernet->src_host[1], ethernet->src_host[2],\
					ethernet->src_host[3], ethernet->src_host[4], ethernet->src_host[5],\
					ethernet->dest_host[0], ethernet->dest_host[1], ethernet->dest_host[2],\
					ethernet->dest_host[3], ethernet->dest_host[4], ethernet->dest_host[5]);
					sprintf(macs_2, "%02x:%02x:%02x:%02x:%02x:%02x,%02x:%02x:%02x:%02x:%02x:%02x",\
					ethernet->dest_host[0], ethernet->dest_host[1], ethernet->dest_host[2],\
					ethernet->dest_host[3], ethernet->dest_host[4], ethernet->dest_host[5],\
					ethernet->src_host[0], ethernet->src_host[1], ethernet->src_host[2],\
					ethernet->src_host[3], ethernet->src_host[4], ethernet->src_host[5]);
				}
			}

			std::map<char*, long int*>::iterator i_1 = association_map.find(macs_1);
			std::map<char*, long int*>::iterator i_2 = association_map.find(macs_2);
			std::map<char*, long int*>::iterator i = i_1;
			if(i_1 == association_map.end()) {
				i = i_2;
			}
			if (i == association_map.end()) {
				times[0] = header->ts.tv_sec;
				times[1] = 0;
				times[2] = dest_ap;
				std::pair<char*, long int*> association = std::make_pair(macs_1, times);
				association_map.insert(association);
			}
			else {
				if (header->ts.tv_sec - i->second[1] >= 30*60 && i->second[1] != 0) {
					if (i->second[0] != i->second[1]) {
						printf("%s,%ld,%ld,%ld\n", macs_1, i->second[0], i->second[1], i->second[2]);
					}
					i->second[0] = header->ts.tv_sec;
					i->second[1] = header->ts.tv_sec;
				}
				else {
					i->second[1] = header->ts.tv_sec;
				}
				if (dest_ap) {
					i->second[2] = dest_ap;
				}
				free(macs_2);
			}
			packetCount++;
		}
		if (packetCount > 0) {
			std::map<char*, long int*>::iterator i = association_map.begin();
			while(i != association_map.end()) {
				if (i->second[0] != i->second[1] && i->second[1] != 0 && strcmp(i->first, "") != 0) {
					printf("%s,%ld,%ld,%ld\n", i->first, i->second[0], i->second[1], i->second[2]);
				}
				free(i->first);
				free(i->second);
				i++;
			}
		}
	}
}
