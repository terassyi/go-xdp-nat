#include "bpf_helpers.h"
#include "packet.h"

int proxy_arp_handle(struct xdp_md *ctx, struct ethhdr *eth);
