#ifndef PARSE_HEADER
#define PARSE_HEADER
#include <netinet/in.h>
/* IP header */
struct ip_hdr {
	u_char vhl;		//???
	u_char tos;		//type of service
	u_short len;		//length
	u_short id;		//identification
	u_short off;		//offset
	u_char ttl;		//time to live
	u_char prot;		//protocol
	u_short cksum;		//checksum
	struct in_addr src,dst; //source and dest ip
};

/* TCP header */
struct tcp_hdr {
	u_short src_port;	//source port
	u_short dest_port;	//destination port
	u_int seq_no;		//sequence number
	u_int ack_no;		//acknowledgement number
	u_char off;		//data offset
	u_char flags;		//flag values
	u_short win_sz;		//window size
	u_short cksum;		//checksum
	u_short urgent;		//urgent pointer?
};

/* Ethernet header */
struct ether_hdr {
	u_char dest_host[6]; //destination host ip
	u_char src_host[6]; //source host ip
	u_short ethertype; //ethertype
};
#endif
