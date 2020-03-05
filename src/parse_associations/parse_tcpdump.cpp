#include <pcap.h>
#include <stdio.h>
#include <iostream>
#include <stdlib.h>
#include <map>
#include <cstring>
#include "parse.h"


std::map<char*, long int*, comp_mac> association_map;

void getMacsCombo(const u_char* mac1, const u_char* mac2, char* macs) {
	sprintf(macs, "%02x:%02x:%02x:%02x:%02x:%02x,%02x:%02x:%02x:%02x:%02x:%02x",\
	mac1[0], mac1[1], mac1[2], mac1[3], mac1[4], mac1[5],\
	mac2[0], mac2[1], mac2[2], mac2[3], mac2[4], mac2[5]);
}

void getMacsCombo(u_char mac1[6], u_char mac2[6], char* macs) {
	sprintf(macs, "%02x:%02x:%02x:%02x:%02x:%02x,%02x:%02x:%02x:%02x:%02x:%02x",\
	*mac1, *(mac1 + 1), *(mac1 + 2),\
	*(mac1 + 3), *(mac1 + 4), *(mac1 + 5),\
	*mac2, *(mac2 + 1), *(mac2 + 2),\
	*(mac2 + 3), *(mac2 + 4), *(mac2 + 5));
}

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
	char err[ERR_LEN] = {'\0'};


	//Find size and type of the data link header
	int dataLinkOffest;
	int pkt_link_type;
	if (pcap_datalink(pcap) == DLT_EN10MB) {
		dataLinkOffest = ETHERNET_SIZE;
		pkt_link_type = ETHERNET_TYPE;
		//Found ethernet file
	}
	else if (pcap_datalink(pcap) == DLT_IEEE802_11_RADIO) {
		dataLinkOffest = IEEE802_11_SIZE_RADIO;
		pkt_link_type = IEEE802_11_TYPE;
		//Found 802.11 file
	}
	else if (pcap_datalink(pcap) == DLT_PRISM_HEADER) {
		dataLinkOffest = IEEE802_11_SIZE_PRISM;
		pkt_link_type = IEEE802_11_TYPE;
		//Found 802.11 file
	}

	//Read file, one packet at a time
	strncpy(err, errbuf, ERR_LEN - 1);
	if (strcmp(err, TRUNCATED_DUMP_FILE) != 0 && strcmp(err, UNKNOWN_FILE_FORMAT) != 0) {
		while (pcap_next_ex(pcap, &header, &data) > 0) {

			//isolate the headers
			const struct ether_hdr* ethernet;
			const struct ip_hdr* ip;
			const struct tcp_hdr* tcp;
			char* macs_1 = (char*) malloc(FORMATTED_MACS_LEN*sizeof(char));
			char* macs_2 = (char*) malloc(FORMATTED_MACS_LEN*sizeof(char));
			long int* times = (long int*) malloc(3*sizeof(long int));
			long int dest_ap = 0;
	

			//if an 802.11 type file has been found (prism or radio header)
			if(pkt_link_type == IEEE802_11_TYPE) {
				const struct act_ieee80211_hdr* link;
				link = (struct act_ieee80211_hdr*)(data + dataLinkOffest);
				if(link->mac3[0] & 1) { //Identify and skip broadcast packets
					continue;
				}
				const u_char* src;
				const u_char* dest;

				//identify if the destination address is an access point using DS bits
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
						if(memcmp(link->mac1, link->mac3, MAC_LEN) == 0) {
							dest_ap = 1; //The destination is recognised as an access point
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
					if(memcmp(link->mac2, link->mac1, MAC_LEN) == 0) {
						dest_ap = 1; //The destination is recognised as an access point
					}
				}

				//save source and destination macs in both orders
				getMacsCombo(src, dest, macs_1);
				getMacsCombo(dest, src, macs_2);

			}


			//if an ethernet type file has been identified
			else if (pkt_link_type == ETHERNET_TYPE) {
				ethernet = (struct ether_hdr*)(data);
				const u_char broadcast[MAC_LEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
				if(memcmp(ethernet->dest_host, broadcast, MAC_LEN) == 0) { //Identify and skip broadcast packets
					continue;
				}
				if (ntohs(ethernet->ethertype) == IPV4_ETHERTYPE) { //IPv4 Packet
					ip = (struct ip_hdr*)(data + dataLinkOffest);
					u_short size_ip = 4*(ip->vhl & 15);
					if(ip->prot == TCP_PROTOCOL) { //TCP packet can be used to identify access points
						tcp = (struct tcp_hdr*)(data + dataLinkOffest + size_ip);
						dest_ap = ((ntohl(tcp->oflags) >> 16 & 2) ? 1 : 0)&&!((ntohl(tcp->oflags) >> 16 & 16) ? 1 : 0);
					}
					//save source and destination macs in both orders
					getMacsCombo(ethernet->src_host, ethernet->dest_host, macs_1);
					getMacsCombo(ethernet->dest_host, ethernet->src_host, macs_2);
				}
				else {
					continue; //Only look at IPV4 packets
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
			//Neither order of macs is found, so add it to the map
			if (i == association_map.end()) {
				times[0] = header->ts.tv_sec; //Timestamp of beginning of association
				times[1] = 0; //End of association initialised to 0
				times[2] = dest_ap; //Is the destination an access point?
				std::pair<char*, long int*> association = std::make_pair(macs_1, times);
				association_map.insert(association);
			}
			else {
				//Association between these macs is ongoing, check for timeout
				if (header->ts.tv_sec - i->second[1] >= TIMEOUT && i->second[1] != 0) { //using 30 minute timeout
					//timeout is hit, output association between two macs and reset start time
					if (i->second[0] != i->second[1]) { //if the association is less than 1 second long don't output it
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

		//output unclosed associations once whole file is read (no wrap over multiple file associations)
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
