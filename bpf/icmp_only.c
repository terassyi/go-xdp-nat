#include "bpf_helpers.h"

#define AF_INET 2
#define ETH_ALEN 6

#define DEBUG 1


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

BPF_MAP_DEF(if_redirect) = {
    .map_type = BPF_MAP_TYPE_DEVMAP,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 64,
};
BPF_MAP_ADD(if_redirect);

BPF_MAP_DEF(ifindex_map) = {
	.map_type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u32),
	.value_size  = sizeof(__u32),
	.max_entries = 2,
};
BPF_MAP_ADD(ifindex_map);

BPF_MAP_DEF(ifaddr_map) = {
	.map_type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 16,
};
BPF_MAP_ADD(ifaddr_map);

BPF_MAP_DEF(if_mac_map) = {
	.map_type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u8) * 6,
	.max_entries = 2,
};
BPF_MAP_ADD(if_mac_map);

// BPF_MAP_DEF(nat_table) = {
// 	
// };
// BPF_MAP_ADD(nat_table);

static inline __u16 ntohs(__u16 val) {
	return (val << 8) + (val >> 8);
}

static inline __u16 htons(__u16 val) {
	return (val << 8) + (val >> 8);
}

static inline __u32 htonl(__u32 addr) {
	return (addr << 24) + ((addr & 0x0000ff00) << 8) + ((addr & 0x00ff0000) >> 8) + (addr >> 24);
}

static inline __u16 checksum(__u16 *buf, __u32 bufsize) {
	__u32 sum = 0;
	while (bufsize > 1) {
		sum += *buf;
		buf++;
		bufsize -= 2;
	}
	if (bufsize == 1) {
		sum += *(__u8 *)buf;
	}
	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);

	return ~sum;
}

static inline __u16 update_ip_checksum_u16(__u16 old_check, __u16 old, __u16 new) {
	__u32 sum;
	old_check = ~ntohs(old_check);
	old = ~old;
	sum = (__u32)old_check + old + new;
	return htons(~((__u16)(old_check >> 16) + (sum & 0xffff)));
}

static inline __u16 update_ip_checksum_u32(__u16 old_check, __u32 old, __u32 new) {
	__u16 old_a = (__u16)(old >> 16);
	__u16 new_a = (__u16)(new >> 16);
	__u16 old_b = (__u16)(old & 0x0000ffff);
	__u16 new_b = (__u16)(new & 0x0000ffff);
	__u16 sum_a = update_ip_checksum_u16(old_check, old_a, new_a);
	return update_ip_checksum_u16(sum_a, old_b, new_b);
}


SEC("xdp")
int icmp_only(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
	__u32 ingress_ifindex = ctx->ingress_ifindex;
    struct ethhdr *ether = data;
    struct iphdr *ip;
    if (data + sizeof(*ether) > data_end) {
        return XDP_PASS;
    }

    __u16 h_proto = ether->h_proto;

	__u32 in_key = 0;
	__u32 out_key = 1;
	__u32 *in = bpf_map_lookup_elem(&ifindex_map, &in_key);
	__u32 *out = bpf_map_lookup_elem(&ifindex_map, &out_key);
	if (!in || !out ) {
		return XDP_PASS;
	}
	__u32 *in_addr = bpf_map_lookup_elem(&ifaddr_map, in);
	__u32 *out_addr = bpf_map_lookup_elem(&ifaddr_map, out);
	if (!in_addr || !out_addr ) {
		return XDP_PASS;
	}
	__u8 *in_mac = bpf_map_lookup_elem(&if_mac_map, in);
	__u8 *out_mac = bpf_map_lookup_elem(&if_mac_map, out);
	if (!in_mac || !out_mac) {
		return XDP_PASS;
	}
	if (h_proto == 0x0608) {
		// proxy arp
		if (ingress_ifindex != *in) {
			bpf_printk("proxy arp only handle packets from in interface.");
			return XDP_PASS;
		}
		data += sizeof(*ether);
		struct arphdr *arp = data;
		if (data + sizeof(*arp) > data_end) {
			return XDP_PASS;
		}
		if (arp->ar_hrd != 0x0100 || arp->ar_pro != 0x08) {
			return XDP_PASS;
		}
		if (arp->ar_op != 0x100) { // only handle request
			return XDP_PASS;
		}

		// build reply arp packet
		arp->ar_op = 0x0200;
		arp->ar_hrd = 0x0100;
		arp->ar_pro = 0x08;
		arp->ar_hln = ETH_ALEN;
		arp->ar_pln = 4;

		memcpy(arp->ar_dha, arp->ar_sha, ETH_ALEN);
		memcpy(arp->ar_sha, in_mac, ETH_ALEN);
		memcpy(in_addr, arp->ar_dip, 4);
		memcpy(arp->ar_dip, arp->ar_sip, 4);
		memcpy(arp->ar_sip, in_addr, 4);

		// build reply ether header
		memcpy(ether->h_dest, arp->ar_dha, ETH_ALEN);
		memcpy(ether->h_source, in_mac, ETH_ALEN);
		bpf_printk("proxy arp reply sent.");
		
		return XDP_TX;

	}
    if (h_proto != 0x08U) {  // htons(ETH_P_IP) -> 0x08U
        return XDP_PASS;
    }
	data += sizeof(*ether);
    ip = data;
    if ((void *)ip + sizeof(*ip) > data_end) {
        return XDP_PASS;
    }

    if (ip->protocol != 0x01) { // IPPROTO_ICMP = 1
        return XDP_PASS;
    }
  	data += ip->ihl * 4;
	struct icmphdr *icmp = data;
	if (data + sizeof(*icmp) > data_end) {
		return XDP_PASS;
	}
	if (icmp->type == 0 || icmp->type == 8) {
		data += sizeof(*icmp);
		struct icmp_echo *echo = data;
		if (data + sizeof(*echo) > data_end) {
			return XDP_PASS;
		}
	}

	// ingress handle
	if (ingress_ifindex == *in) {
		struct bpf_fib_lookup fib_params;
		__builtin_memset(&fib_params, 0, sizeof(fib_params));
		fib_params.family = AF_INET;
		fib_params.ipv4_src = ip->saddr;
		fib_params.ipv4_dst = ip->daddr;
		fib_params.ifindex = ingress_ifindex;
		int rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);
		if ((rc != BPF_FIB_LKUP_RET_SUCCESS) && (rc != BPF_FIB_LKUP_RET_NO_NEIGH)) {
			bpf_printk("dropping packet\n");
			return XDP_DROP;
		} else if (rc == BPF_FIB_LKUP_RET_NO_NEIGH) {
			bpf_printk("passing packet, lookup returned %d\n", BPF_FIB_LKUP_RET_NO_NEIGH);
			return XDP_PASS;
		}
		bpf_printk("ip->check old = %x\n", htons(ip->check));
		ip->saddr = htonl(*out_addr);
		ip->check = 0;
		ip->check = checksum((__u16 *)ip, sizeof(*ip));
		bpf_printk("ip->check new = %x\n", htons(ip->check));

		memcpy(ether->h_dest, fib_params.dmac, ETH_ALEN);
		memcpy(ether->h_source, fib_params.smac, ETH_ALEN);

    	return bpf_redirect_map(&if_redirect, *out, 0);
	} else if (ingress_ifindex == *out) {
		__u32 maped_local_addr_index = 0;
		__u32 *maped_local_addr = bpf_map_lookup_elem(&ifaddr_map, &maped_local_addr_index);
		if (!maped_local_addr) {
			bpf_printk("mapped local address is not found.\n");
			return XDP_PASS;
		}
		ip->daddr = htonl(*maped_local_addr);
		ip->check = 0;
		ip->check = checksum((__u16 *)ip, sizeof(*ip));

		struct bpf_fib_lookup fib_params;
		__builtin_memset(&fib_params, 0, sizeof(fib_params));
		fib_params.family = AF_INET;
		fib_params.ipv4_src = ip->saddr;
		fib_params.ipv4_dst = ip->daddr;
		fib_params.ifindex = ingress_ifindex;
		int rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);
		if ((rc != BPF_FIB_LKUP_RET_SUCCESS) && (rc != BPF_FIB_LKUP_RET_NO_NEIGH)) {
			bpf_printk("dropping packet\n");
			return XDP_DROP;
		} else if (rc == BPF_FIB_LKUP_RET_NO_NEIGH) {
			bpf_printk("passing packet, lookup returned %d\n", BPF_FIB_LKUP_RET_NO_NEIGH);
			return XDP_PASS;
		}
		memcpy(ether->h_dest, fib_params.dmac, ETH_ALEN);
		memcpy(ether->h_source, fib_params.smac, ETH_ALEN);

    	return bpf_redirect_map(&if_redirect, *in, 0);

	} else {
		bpf_printk("unknown ifindex.\n");
		return XDP_PASS;
	}
	bpf_printk("in ifindex: %d\n", ingress_ifindex);
	bpf_printk("in_addr: %d // ip->saddr: %d\n", *in_addr, ip->saddr);
	bpf_printk("out_addr: %d // ip->daddr: %d\n", *out_addr, ip->daddr);

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
