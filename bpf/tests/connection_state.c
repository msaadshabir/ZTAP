#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#undef __always_inline
/* ELF sections do not exist on the macOS host; omit only that metadata. */
#define section(name) unused
#include "../engine.c"

/* Run the unmodified packet program with deterministic userspace helpers.
 * This validates decision logic, not Linux attachment or verifier behavior. */
static struct active_config_value config = { .active_slot = 1, .policy_epoch = 1 };
static struct subject_value subject = { .isolated = 3 };
static __u64 guards[2], counters[48], drops[2];
static struct event_limiter_value limiter;
static struct flow_event last_event;
static __u64 now = NS_PER_SECOND;
static unsigned char packet_bytes[64];
static int inner_map, rule_enabled = 1;
static struct { int present; struct connection_key key; struct connection_value value; } connections[8];

static void *lookup(void *map, const void *key) {
    if (map == &active_config) return &inner_map;
    if (map == &inner_map) return &config;
    if (map == &in_flight) return &guards[*(__u32 *)key];
    if (map == &subject_state) return &subject;
    if (map == &decision_counts) return &counters[*(__u32 *)key];
    if (map == &event_drops) return &drops[*(__u32 *)key];
    if (map == &event_limiter) return &limiter;
    if (map == &conn_state) {
        for (int i = 0; i < 8; i++)
            if (connections[i].present && !memcmp(key, &connections[i].key, sizeof(struct connection_key)))
                return &connections[i].value;
    }
    if (map == &policy_rules) {
        const struct policy_rule_key *k = key;
        if (rule_enabled && !(k->meta & (1U << 30)) && (k->meta & 65535) == 443)
            return &rule_enabled;
    }
    return NULL;
}
static long update(void *map, const void *key, const void *value, __u64 flags) {
    if (map != &conn_state) return 0;
    for (int i = 0; i < 8; i++) {
        if (connections[i].present && !memcmp(key, &connections[i].key, sizeof(struct connection_key))) {
            memcpy(&connections[i].value, value, sizeof(struct connection_value)); return 0;
        }
    }
    for (int i = 0; i < 8; i++) if (!connections[i].present) {
        connections[i].present = 1;
        memcpy(&connections[i].key, key, sizeof(struct connection_key));
        memcpy(&connections[i].value, value, sizeof(struct connection_value)); return 0;
    }
    return -1;
}
static long delete_key(void *map, const void *key) {
    if (map == &conn_state) for (int i = 0; i < 8; i++)
        if (connections[i].present && !memcmp(key, &connections[i].key, sizeof(struct connection_key)))
            connections[i].present = 0;
    return 0;
}
static __u64 clock_ns(void) { return now; }
static long load_bytes(const void *skb, __u32 offset, void *to, __u32 len) {
    if (offset + len > ((const struct __sk_buff *)skb)->len) return -1;
    memcpy(to, packet_bytes + offset, len); return 0;
}
static void *reserve(void *map, __u64 size, __u64 flags) { return &last_event; }
static void submit(void *data, __u64 flags) {}
static int tcp(int direction, __u16 flags) {
    struct ipv4_header ip = {
        .version_ihl = 0x45, .total_length = bpf_ntohs(40), .protocol = IPPROTO_TCP,
        .source = direction == DIR_EGRESS ? 0x0200000a : 0x0300000a,
        .destination = direction == DIR_EGRESS ? 0x0300000a : 0x0200000a,
    };
    struct tcp_header header = {
        .source = bpf_ntohs(direction == DIR_EGRESS ? 40000 : 443),
        .destination = bpf_ntohs(direction == DIR_EGRESS ? 443 : 40000),
        .offset_flags = bpf_ntohs(0x5000 | flags),
    };
    memcpy(packet_bytes, &ip, sizeof(ip));
    memcpy(packet_bytes + sizeof(ip), &header, sizeof(header));
    struct __sk_buff skb = {.len = 40};
    now += NS_PER_SECOND;
    return enforce_packet(&skb, direction, 42);
}
static void reset(void) {
    memset(connections, 0, sizeof(connections));
    config.policy_epoch = 1; config.active_slot = 1; rule_enabled = 1;
}

static void expect_tcp(int direction, __u16 flags, int allowed, const char *message) {
    int result = tcp(direction, flags);
    if (result != allowed) {
        fprintf(stderr, "%s: allowed=%d reason=%u\n", message, result, last_event.reason);
        exit(1);
    }
}
static void handshake(void) {
    expect_tcp(DIR_EGRESS, 0x02, 1, "outbound SYN");
    expect_tcp(DIR_INGRESS, 0x12, 1, "inbound SYN-ACK");
    expect_tcp(DIR_EGRESS, 0x10, 1, "outbound ACK");
}
int main(void) {
    bpf_map_lookup_elem = lookup; bpf_map_update_elem = update;
    bpf_map_delete_elem = delete_key; bpf_ktime_get_ns = clock_ns;
    bpf_skb_load_bytes = load_bytes; bpf_ringbuf_reserve = reserve; bpf_ringbuf_submit = submit;
    reset();
    expect_tcp(DIR_INGRESS, 0x02, 0, "unsolicited SYN without state");
    handshake();
    expect_tcp(DIR_INGRESS, 0x02, 0, "new reverse SYN during established connection");
    expect_tcp(DIR_INGRESS, 0x18, 1, "data after rejected SYN");
    expect_tcp(DIR_EGRESS, 0x11, 1, "first FIN");
    now += 300 * NS_PER_SECOND;
    expect_tcp(DIR_INGRESS, 0x18, 1, "half-closed stream remains usable");
    expect_tcp(DIR_INGRESS, 0x11, 1, "second FIN");
    expect_tcp(DIR_EGRESS, 0x10, 1, "final ACK");
    __u64 closed_at = now;
    now += 60 * NS_PER_SECOND;
    expect_tcp(DIR_INGRESS, 0x11, 1, "FIN retransmission during closing interval");
    now = closed_at + 121 * NS_PER_SECOND;
    expect_tcp(DIR_INGRESS, 0x18, 0, "closed state expires without retransmission extension");
    expect_tcp(DIR_INGRESS, 0x02, 0, "new reverse SYN after closure");
    handshake();
    expect_tcp(DIR_INGRESS, 0x18, 1, "allowed tuple reuse resets FIN state");
    expect_tcp(DIR_INGRESS, 0x14, 1, "reset closes connection");
    expect_tcp(DIR_INGRESS, 0x18, 0, "reset state cannot authorize replies");
    reset();
    handshake();
    config.policy_epoch++;
    expect_tcp(DIR_INGRESS, 0x18, 0, "changed policy epoch invalidates replies");
    reset();
    struct connection_key udp = { .policy_epoch = 1, .cgroup_id = 42,
        .source = 2, .destination = 3, .source_port = 40000, .destination_port = 443,
        .protocol = IPPROTO_UDP, .direction = DIR_EGRESS };
    remember_reverse_connection(udp, now, 0);
    struct connection_key reply = reverse_connection_key(udp);
    if (!allow_connection_state(reply, now + 2 * NS_PER_SECOND, 0)) return 1;
    if (!allow_connection_state(udp, now + 4 * NS_PER_SECOND, 0)) return 1;
    if (allow_connection_state(reply, now + 35 * NS_PER_SECOND, 0)) return 1;
    puts("TCP lifecycle, tuple reuse, epoch invalidation, and UDP expiry passed");
    return 0;
}
