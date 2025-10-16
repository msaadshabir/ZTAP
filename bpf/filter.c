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
static long (*bpf_skb_load_bytes)(const void *skb, __u32 offset, void *to, __u32 len) = (void *)26;

// Byte order conversion helpers (inline, not actual BPF helpers)
#define bpf_htons(x) __builtin_bswap16(x)
#define bpf_ntohs(x) __builtin_bswap16(x)

// Compiler directives
#define __always_inline inline __attribute__((always_inline))
#define __attribute_const__ __attribute__((const))
#define SEC(name) __attribute__((section(name), used))

// BTF map definition macros (for cilium/ebpf v0.19+)
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name

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

// BPF map definition using BTF-based approach (required by cilium/ebpf v0.19+)
// Modern cilium/ebpf expects map definitions in .maps section with BTF type info
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, struct policy_key);
    __type(value, struct policy_value);
} policy_map SEC(".maps");

// Helper to parse IPv4 packet
static __always_inline int parse_ipv4(struct __sk_buff *skb, __u32 *dest_ip,
                                      __u8 *protocol, __u16 *dest_port)
{
    struct ethhdr eth;
    struct iphdr ip;

    // Load ethernet header
    if (bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth)) < 0)
        return -1;

    // Check if IPv4
    if (eth.h_proto != bpf_htons(ETH_P_IP))
        return -1;

    // Load IP header
    if (bpf_skb_load_bytes(skb, sizeof(eth), &ip, sizeof(ip)) < 0)
        return -1;

    *dest_ip = ip.daddr;
    *protocol = ip.protocol;

    // Calculate IP header length (IHL is in 32-bit words)
    __u8 ihl = (ip.version_ihl & 0x0F) * 4;
    if (ihl < sizeof(struct iphdr))
        ihl = sizeof(struct iphdr);

    // Parse port based on protocol
    if (ip.protocol == IPPROTO_TCP)
    {
        struct tcphdr tcp;
        if (bpf_skb_load_bytes(skb, sizeof(eth) + ihl, &tcp, sizeof(tcp)) < 0)
            return -1;
        *dest_port = bpf_ntohs(tcp.dest);
    }
    else if (ip.protocol == IPPROTO_UDP)
    {
        struct udphdr udp;
        if (bpf_skb_load_bytes(skb, sizeof(eth) + ihl, &udp, sizeof(udp)) < 0)
            return -1;
        *dest_port = bpf_ntohs(udp.dest);
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
