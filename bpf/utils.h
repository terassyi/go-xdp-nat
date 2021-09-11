#include "bpf_helpers.h"

static inline __u16 ntohs(__u16 val);
static inline __u16 htons(__u16 val);
static inline __u32 htonl(__u32 val);
static inline __u16 checksum(__u16 *buf, __u32 bufsize);
