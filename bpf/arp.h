#include "bpf_helpers.h"

int proxy_arp_handle(struct xdp_md *ctx, __u32 in_ifindex, __u8 *in_mac);
