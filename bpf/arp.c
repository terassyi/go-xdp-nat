#include "bpf_helpers.h"
#include "packet.h"

#define ETH_ALEN 6

int proxy_arp_handle(struct xdp_md *ctx, __u32 in_ifindex, __u8 *in_mac) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
	struct ethhdr *ether = data;
	if (data + sizeof(*ether) > data_end) {
		return XDP_PASS;
	}
	data += sizeof(*ether);
	struct arphdr *arp = data;
	if (data + sizeof(*arp) > data_end) {
		return XDP_PASS;
	}
	__u32 ingress_ifindex = ctx->ingress_ifindex;
	if (ingress_ifindex != in_ifindex) {
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
	__u32 *tmp;
	memcpy(tmp, arp->ar_dip, 4);
	memcpy(arp->ar_dip, arp->ar_sip, 4);
	memcpy(arp->ar_sip, tmp, 4);

	return XDP_TX;
}
