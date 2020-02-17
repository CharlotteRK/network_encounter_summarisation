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
	//Set up input
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
		dataLinkOffest = 18;
		pkt_link_type = IEEE802_11_TYPE;
		//Found 802.11 file
	}
	else if (pcap_datalink(pcap) == DLT_PRISM_HEADER) {
		dataLinkOffest = 144;
		pkt_link_type = IEEE802_11_TYPE;
		//Found 802.11 file
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
			//if an 802.11 type file has been found (prism or radio header)
			if(pkt_link_type == IEEE802_11_TYPE) {
				const struct act_ieee80211_hdr* link;
				link = (struct act_ieee80211_hdr*)(data + dataLinkOffest);
				//const u_char broadcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
				if(link->mac3[0] & 1) {
					continue; //skip broadcast packets
				}
				const u_char* src;
				const u_char* dest;
				//identify if the destination address is an access point
				if (link->fc & 1) {
					if (link->fc & 2) {
						//to DS and from DS (11)
						dest = link->mac3;
						src = link->mac4;
					}
					else {
						//to DS (01)
						dest = link->mac3;
						src = link->mac2;
						if(memcmp(link->mac1, link->mac3, 6) == 0) {
							dest_ap = 1;
						}
					}
				}
				else if (!(link->fc & 2)){
					//no DS bits set (00)
					dest = link->mac1;
					src = link->mac2;
				}
				else {
					//from DS (10)
					dest = link->mac1;
					src = link->mac3;
					if(memcmp(link->mac2, link->mac1, 6) == 0) {
						dest_ap = 1;
					}
				}
				//save source and destination macs in both orders
				sprintf(macs_1, "%02x:%02x:%02x:%02x:%02x:%02x,%02x:%02x:%02x:%02x:%02x:%02x",\
				*src, *(src + 1), *(src + 2),\
				*(src + 3), *(src + 4), *(src + 5),\
				*dest, *(dest + 1), *(dest + 2),\
				*(dest + 3), *(dest + 4), *(dest + 5));
				sprintf(macs_2, "%02x:%02x:%02x:%02x:%02x:%02x,%02x:%02x:%02x:%02x:%02x:%02x",\
				*dest, *(dest + 1), *(dest + 2),\
				*(dest + 3), *(dest + 4), *(dest + 5),\
				*src, *(src + 1), *(src + 2),\
				*(src + 3), *(src + 4), *(src + 5));

			}
			//if an ethernet type file has been identified
			else if (pkt_link_type == ETHERNET_TYPE) {
				ethernet = (struct ether_hdr*)(data);
				//const u_char broadcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
				if(ethernet->dest_host[6] & 1) {
					continue;
				}
				if (ntohs(ethernet->ethertype) == 0x0800) { //IPv4 Packet
					ip = (struct ip_hdr*)(data + dataLinkOffest);
					u_short size_ip = 4*(ip->vhl & 15);
					if(ip->prot == 0x06) { //TCP packet
						tcp = (struct tcp_hdr*)(data + dataLinkOffest + size_ip);
						dest_ap = ((ntohl(tcp->oflags) >> 16 & 2) ? 1 : 0)&&!((ntohl(tcp->oflags) >> 16 & 16) ? 1 : 0);
					}
					//save source and destination macs in both orders
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
			//search existing map of associations for the macs (in either order)
			std::map<char*, long int*>::iterator i_1 = association_map.find(macs_1);
			std::map<char*, long int*>::iterator i_2 = association_map.find(macs_2);
			std::map<char*, long int*>::iterator i = i_1;
			if(i_1 == association_map.end()) { //macs_1 not found
				i = i_2;
				dest_ap = 0; //order of macs is switched so no longer relevant
			}
			if (i == association_map.end()) {
				times[0] = header->ts.tv_sec;
				times[1] = 0;
				times[2] = dest_ap;
				std::pair<char*, long int*> association = std::make_pair(macs_1, times);
				association_map.insert(association);
			}
			else {
				if (header->ts.tv_sec - i->second[1] >= 30*60 && i->second[1] != 0) { //using 30 second timeout
					if (i->second[0] != i->second[1]) {
						//output association between two macs as timeout is hit
						printf("%s,%ld,%ld,%ld\n", macs_1, i->second[0], i->second[1], i->second[2]);
					}
					i->second[0] = header->ts.tv_sec;
					i->second[1] = header->ts.tv_sec;
				}
				else {
					i->second[1] = header->ts.tv_sec; //update end time of association
				}
				if (dest_ap) {
					i->second[2] = dest_ap; //update if proof has been found to the destination being an AP
				}
				free(macs_1);
			}
			free(macs_2);
			packetCount++;
		}
		//output unclosed associations (no wrap over multiple file associations)
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
