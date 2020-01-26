#ifndef PARSE_HEADER
#define PARSE_HEADER
#include <netinet/in.h>
/* IP header */
struct ip_hdr {
	u_char vhl;		//version + header len
	u_char tos;		//type of service
	u_short len;		//length
	u_short id;		//identification
	u_short off;		//flags + offset
	u_char ttl;		//time to live
	u_char prot;		//protocol
	u_short cksum;		//checksum
	struct in_addr src,dst; //source and dest ip
};

/*802.11 header (radiotap)*/
struct ieee80211_hdr {
  u_char version;
  u_char pad;
  u_short len;
  u_int present;
};

struct act_ieee80211_hdr {
	u_short fc; //frame control
	u_short di; //duration/friame id
	u_char reciever[6]; //reciever MAC
	u_char transmitter[6]; //transmitter MAC
	u_char source[6]; //source host MAC
	u_short seq; //sequence control
};

/* TCP header */
struct tcp_hdr {
	u_short src_port;	//source port 16
	u_short dest_port;	//destination port 16
	u_int seq_no;		//sequence number 32
	u_int ack_no;		//acknowledgement number 32
	u_short oflags;		//data offset + flag values 16
	u_short win_sz;		//window size 16
	u_short cksum;		//checksum 16
	u_short urgent;		//urgent pointer? 16
};

/* Ethernet header */
struct ether_hdr {
	u_char dest_host[6]; //destination host MAC
	u_char src_host[6]; //source host MAC
	u_short ethertype; //ethertype
};

struct comp_mac {
	bool operator() (char const* mac1, char const* mac2) const {
		return std::strcmp(mac1, mac2) < 0;
	}
};
#endif
