#include "bpf_helpers.h"
#include "packet.h"

#define DEBUG 1
#define ETH_ALEN 6
#define AF_INET 2

BPF_MAP_DEF(if_redirect) = {
    .map_type = BPF_MAP_TYPE_DEVMAP,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 64,
};
BPF_MAP_ADD(if_redirect);

BPF_MAP_DEF(if_index_map) = {
	.map_type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u32),
	.value_size  = sizeof(__u32),
	.max_entries = 2,
};
BPF_MAP_ADD(if_index_map);

BPF_MAP_DEF(if_addr_map) = {
	.map_type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 16,
};
BPF_MAP_ADD(if_addr_map);

BPF_MAP_DEF(if_mac_map) = {
	.map_type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u8) * 6,
	.max_entries = 2,
};
BPF_MAP_ADD(if_mac_map);

BPF_MAP_DEF(nat_table) = {
	.map_type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u16),
	.value_size = sizeof(__u16),
	.max_entries = 128,
};
BPF_MAP_ADD(nat_table);

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

SEC("xdp")
int nat_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
	__u32 ingress_ifindex = ctx->ingress_ifindex;

	// get map data
	__u32 in_key = 0;
	__u32 out_key = 1;
	__u32 *in_ifindex = bpf_map_lookup_elem(&if_index_map, &in_key);
	__u32 *out_ifindex = bpf_map_lookup_elem(&if_index_map, &out_key);
	if (!in_ifindex || !out_ifindex ) {
		bpf_printk("failed to get interface index. pass.");
		return XDP_PASS;
	}
	__u32 *in_addr = bpf_map_lookup_elem(&if_addr_map, in_ifindex);
	__u32 *out_addr = bpf_map_lookup_elem(&if_addr_map, out_ifindex);
	if (!in_addr || !out_addr ) {
		bpf_printk("failed to get addr. pass.");
		return XDP_PASS;
	}
	__u8 *in_mac = bpf_map_lookup_elem(&if_mac_map, in_ifindex);
	__u8 *out_mac = bpf_map_lookup_elem(&if_mac_map, out_ifindex);
	if (!in_mac || !out_mac) {
		bpf_printk("failed to get mac addr. pass.");
		return XDP_PASS;
	}
	__u32 mapped_local_addr_key = 0;
	__u32 *mapped_local_addr = bpf_map_lookup_elem(&if_addr_map, &mapped_local_addr_key);
	if (!mapped_local_addr) {
		bpf_printk("failed to get mapped local address. pass.");
		return XDP_PASS;
	}

    struct ethhdr *ether = data;
    if (data + sizeof(*ether) > data_end) {
        return XDP_PASS;
    }

	// arp
	if (ether->h_proto == 0x0608) {
		data += sizeof(*ether);
		struct arphdr *arp = data;
		if (data + sizeof(*arp) > data_end) {
			return XDP_PASS;
		}
		if (ingress_ifindex != *in_ifindex) {
			return XDP_PASS;
		}
		if (arp->ar_hrd != 0x0100 || arp->ar_pro != 0x08) {
			return XDP_PASS;
		}
		if (arp->ar_op != 0x100) {
			return XDP_PASS;
		}
		// build reply
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

		memcpy(ether->h_dest, arp->ar_dha, ETH_ALEN);
		memcpy(ether->h_source, in_mac, ETH_ALEN);

		return XDP_TX;
	}
	
	// ip packet handle
	if (ether->h_proto != 0x08U) {
		return XDP_PASS;
	}
	data += sizeof(*ether);
	struct iphdr *ip = data;
	if (data + sizeof(*ip) > data_end) {
		return XDP_PASS;
	}
	data += ip->ihl * 4;

	// handle packet from ingress interface.
	if (ingress_ifindex == *in_ifindex) {
		//if (ip->daddr == *in_addr) {
		//	bpf_printk("destination is local interface.");
		//	return XDP_PASS;
		//}
		struct bpf_fib_lookup fib_params;
		__builtin_memset(&fib_params, 0, sizeof(fib_params));
		fib_params.family = AF_INET;
		fib_params.ipv4_src = ip->saddr;
		fib_params.ipv4_dst = ip->daddr;
		fib_params.ifindex = ingress_ifindex;
		int rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);
		if ((rc != BPF_FIB_LKUP_RET_SUCCESS) && (rc != BPF_FIB_LKUP_RET_NO_NEIGH)) {
			bpf_printk("fib lookup failed.");
			return XDP_DROP;
		} else if (rc == BPF_FIB_LKUP_RET_NO_NEIGH) {
			bpf_printk("fib lookup result no neigh.");
			return XDP_PASS;
		}
		
		if (ip->protocol == 0x01) {
			// icmp
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
				// update static nat table
				__u16 ident = echo->ident;
				__u16 *exist = bpf_map_lookup_elem(&nat_table, &ident);
				if (!exist) {
					if (bpf_map_update_elem(&nat_table, &ident, &ident, 0) != 0) {
						bpf_printk("failed: bpf_map_update_elem()");
						return XDP_PASS;
					}
					bpf_printk("register %d", ident);
				} else {
					bpf_printk("%d is already registered", ident);
				}
				
			}
			ip->saddr = *out_addr;
			ip->check = 0;
			ip->check = checksum((__u16 *)ip, sizeof(*ip));
			memcpy(ether->h_dest, fib_params.dmac, ETH_ALEN);
			memcpy(ether->h_source, fib_params.smac, ETH_ALEN);

			
			return bpf_redirect_map(&if_redirect, *out_ifindex, 0);
		} 
		if (ip->protocol == 0x06) {
			// tcp 
			struct tcphdr *tcp = data;
			if (data + sizeof(*tcp) > data_end) {
				return XDP_PASS;
			}
			struct pseudohdr pseudo;
			pseudo.source = ip->saddr;
			pseudo.dest = ip->daddr;
			pseudo.protocol = 0x06;
			pseudo.len = ip->tot_len - (ip->ihl * 4);
		} else if (ip->protocol == 0x11) {
			// udp 
			struct udphdr *udp = data;
			if (data + sizeof(*udp) > data_end) {
				return XDP_PASS;
			}
			struct pseudohdr pseudo;
			pseudo.source = ip->saddr;
			pseudo.dest = ip->daddr;
			pseudo.protocol = 0x11;
			pseudo.len = ip->tot_len - (ip->ihl * 4);
		}
	} else if (ingress_ifindex == *out_ifindex) {


		//ip->daddr = *mapped_local_addr;
		//ip->check = 0;
		//ip->check = checksum((__u16 *)ip, sizeof(*ip));


		if (ip->protocol == 0x01) {
			// icmp
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
				__u16 ident = echo->ident;
				__u16 *registered_ident = bpf_map_lookup_elem(&nat_table, &ident);
				if (!registered_ident) {
					bpf_printk("icmp echo identifier is not registerd.");
					return XDP_PASS;
				}
				bpf_printk("registered ident = %d", *registered_ident);
			}

			ip->daddr = *mapped_local_addr;
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
			
			return bpf_redirect_map(&if_redirect, *in_ifindex, 0);
		} else if (ip->protocol == 0x06) {
			// tcp 
			struct tcphdr *tcp = data;
			if (data + sizeof(*tcp) > data_end) {
				return XDP_PASS;
			}
			struct pseudohdr pseudo;
			pseudo.source = ip->saddr;
			pseudo.dest = ip->daddr;
			pseudo.protocol = 0x06;
			pseudo.len = ip->tot_len - (ip->ihl * 4);
			pseudo.zero = 0;

		} else if (ip->protocol == 0x11) {
			// udp 
			struct udphdr *udp = data;
			if (data + sizeof(*udp) > data_end) {
				return XDP_PASS;
			}
			struct pseudohdr pseudo;
			pseudo.source = ip->saddr;
			pseudo.dest = ip->daddr;
			pseudo.protocol = 0x11;
			pseudo.len = ip->tot_len - (ip->ihl * 4);
			pseudo.zero = 0;
		} else {
			return XDP_PASS;
		}
	} else {
		return XDP_PASS;
	}
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
