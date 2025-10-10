// SPDX-License-Identifier: GPL-2.0
// eBPF program for network policy enforcement

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

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

// BPF map for storing policies
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
