// SPDX-License-Identifier: GPL-2.0
// eBPF program for network policy enforcement
// Self-contained definitions to avoid architecture-specific header issues

// BPF type definitions (from linux/bpf.h, but without dependencies)
typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;

// BPF helper return types
#define BPF_MAP_TYPE_HASH 1

// BPF constants
#define ETH_P_IP 0x0800
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

// BPF helper function declarations
static void *(*bpf_map_lookup_elem)(void *map, void *key) = (void *)1;
static long (*bpf_map_update_elem)(void *map, void *key, void *value, unsigned long flags) = (void *)2;
static unsigned short (*bpf_htons)(unsigned short value) = (void *)9;
static unsigned short (*bpf_ntohs)(unsigned short value) = (void *)10;

// Compiler directives
#define __always_inline inline __attribute__((always_inline))
#define __attribute_const__ __attribute__((const))
#define SEC(name) __attribute__((section(name), used))

// Ethernet header
struct ethhdr
{
    unsigned char h_dest[6];
    unsigned char h_source[6];
    unsigned short h_proto;
};

// IP header (simplified for BPF)
struct iphdr
{
    unsigned char version_ihl;
    unsigned char tos;
    unsigned short tot_len;
    unsigned short id;
    unsigned short frag_off;
    unsigned char ttl;
    unsigned char protocol;
    unsigned short check;
    unsigned int saddr;
    unsigned int daddr;
};

// TCP header (simplified)
struct tcphdr
{
    unsigned short source;
    unsigned short dest;
    unsigned int seq;
    unsigned int ack_seq;
    unsigned short doff_flags;
    unsigned short window;
    unsigned short check;
    unsigned short urg_ptr;
};

// UDP header
struct udphdr
{
    unsigned short source;
    unsigned short dest;
    unsigned short len;
    unsigned short check;
};

// Socket buffer structure for skb context
struct __sk_buff
{
    __u32 data;
    __u32 data_end;
};

// Policy key structure (must match Go struct)
struct policy_key
{
    __u32 dest_ip;
    __u16 dest_port;
    __u8 protocol;
    __u8 _padding;
};

// Policy value structure (must match Go struct)
struct policy_value
{
    __u8 action; // 0 = block, 1 = allow
    __u8 _padding[3];
};

// BPF map definition using raw section (no kernel macros needed)
struct bpf_map_def
{
    unsigned int type;
    unsigned int key_size;
    unsigned int value_size;
    unsigned int max_entries;
};

__attribute__((section(".maps"))) struct bpf_map_def policy_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct policy_key),
    .value_size = sizeof(struct policy_value),
    .max_entries = 10000,
};

// Handle to policy_map for bpf_map_lookup_elem
#define policy_map_ptr (&policy_map)

// Helper to parse IPv4 packet
static __always_inline int parse_ipv4(struct __sk_buff *skb, __u32 *dest_ip,
                                      __u8 *protocol, __u16 *dest_port)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return -1;

    // Check if IPv4
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return -1;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return -1;

    *dest_ip = ip->daddr;
    *protocol = ip->protocol;

    // Parse port based on protocol
    if (ip->protocol == IPPROTO_TCP)
    {
        struct tcphdr *tcp = (void *)(ip + 1);
        if ((void *)(tcp + 1) > data_end)
            return -1;
        *dest_port = bpf_ntohs(tcp->dest);
    }
    else if (ip->protocol == IPPROTO_UDP)
    {
        struct udphdr *udp = (void *)(ip + 1);
        if ((void *)(udp + 1) > data_end)
            return -1;
        *dest_port = bpf_ntohs(udp->dest);
    }
    else
    {
        *dest_port = 0;
    }

    return 0;
}

// Main eBPF program for egress filtering
SEC("cgroup_skb/egress")
int filter_egress(struct __sk_buff *skb)
{
    __u32 dest_ip;
    __u8 protocol;
    __u16 dest_port;

    // Parse packet
    if (parse_ipv4(skb, &dest_ip, &protocol, &dest_port) < 0)
    {
        // If not IPv4 or parse error, allow by default
        return 1;
    }

    // Lookup policy in map
    struct policy_key key = {
        .dest_ip = dest_ip,
        .dest_port = dest_port,
        .protocol = protocol,
    };

    struct policy_value *value = bpf_map_lookup_elem(&policy_map, &key);
    if (value)
    {
        // Found matching policy
        if (value->action == 1)
        {
            // ALLOW
            return 1;
        }
        else
        {
            // BLOCK
            return 0;
        }
    }

    // Default deny: if no policy matches, block
    return 0;
}

// Alternative: Default allow mode (for testing)
SEC("cgroup_skb/egress_permissive")
int filter_egress_permissive(struct __sk_buff *skb)
{
    __u32 dest_ip;
    __u8 protocol;
    __u16 dest_port;

    if (parse_ipv4(skb, &dest_ip, &protocol, &dest_port) < 0)
    {
        return 1;
    }

    struct policy_key key = {
        .dest_ip = dest_ip,
        .dest_port = dest_port,
        .protocol = protocol,
    };

    struct policy_value *value = bpf_map_lookup_elem(&policy_map, &key);
    if (value && value->action == 0)
    {
        // Explicitly blocked
        return 0;
    }

    // Default allow: if no explicit block, allow
    return 1;
}

char _license[] SEC("license") = "GPL";
