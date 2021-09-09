#include "bpf_helpers.h"

#define ETH_ALEN 6

struct ethhdr {
  __u8 h_dest[6];
  __u8 h_source[6];
  __u16 h_proto;
} __attribute__((packed));

// IPv4 header
// #include <linux/ip.h>
struct iphdr {
  __u8 ihl : 4;
  __u8 version : 4;
  __u8 tos;
  __u16 tot_len;
  __u16 id;
  __u16 frag_off;
  __u8 ttl;
  __u8 protocol;
  __u16 check;
  __u32 saddr;
  __u32 daddr;
} __attribute__((packed));

struct arphdr {
	__u16 ar_hrd;
	__u16 ar_pro;
	__u8 ar_hln;
	__u8 ar_pln;
	__u16 ar_op;
	__u8 ar_sha[ETH_ALEN];
	__u8 ar_sip[4];
	__u8 ar_dha[ETH_ALEN];
	__u8 ar_dip[4];
};

struct icmphdr {
  __u8		type;
  __u8		code;
  __u16	checksum;
};

struct icmp_echo {
	__u16 ident;
	__u16 seq;
};

struct icmp_dst_unreach {
	__u16 unused;
	__u16 next_hop;
};

struct if_info {
	__u32 ifindex;
	__u32 addr;
};

struct tcphdr {
	__u16 src;
	__u16 dst;
	__u32 seq;
	__u32 ack_seq;
	union {
		struct {
			__u16 ns : 1,
			reserved : 3,
			doff : 4,
			fin : 1,
			syn : 1,
			rst : 1,
			psh : 1,
			ack : 1,
			urg : 1,
			ece : 1,
			cwr : 1;
		};
	};
	__u16 window;
	__u16 check;
	__u16 urg_ptr;
};

struct udphdr {
	__u16 source;
	__u16 dest;
	__u16 len;
	__u16 check;
};

struct pseudohdr {
	__u32 source;
	__u32 dest;
	__u8 zero;
	__u8 protocol;
	__u16 len;
};
