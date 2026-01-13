# IPv6 Support Design Specification

## IMPORTANT: Internal Use only. Delete after implementation!!

## Overview

Status: Draft  
Owner: ZTAP Engineering  
Date: 2026-01-12

This document outlines the design for adding IPv6 enforcement capabilities to ZTAP. Currently, ZTAP only enforces policies on IPv4 traffic for both eBPF and iptables backends. This initiative will extend coverage to IPv6, ensuring zero-trust principles are applied across the full dual-stack networking environment.

## Goals

1.  **eBPF Enforcement**: Extend the eBPF datapath to filter IPv6 traffic.
2.  **Iptables Fallback**: Extend the iptables enforcer to manage `ip6tables` rules.
3.  **Policy Engine**: Ensure `ipBlock` and label resolution properly handle IPv6 addresses.
4.  **Observability**: Ensure flow logs capture and display IPv6 addresses correctly.

## Architecture

### 1. eBPF Datapath (`bpf/filter.c`)

The current BPF program only handles `ETH_P_IP` (IPv4). We will add a parallel path for `ETH_P_IPV6`.

#### New BPF Maps

Due to the different key sizes (IPv4 is 4 bytes, IPv6 is 16 bytes), we cannot easily use a single hash map without wasting significant space or complicating the key struct. We will introduce a dedicated map for IPv6 policies.

```c
struct policy_key_v6 {
    __u64 cgroup_id;
    __u32 ip[4];    // IPv6 Address (128 bits)
    __u16 port;
    __u8 protocol;
    __u8 direction; // 0=egress, 1=ingress
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct policy_key_v6));
    __uint(value_size, sizeof(struct policy_value));
    __uint(max_entries, 10000);
} policy_map_v6 SEC(".maps");
```

#### Filtering Logic

The `traffic_filter` function will:

1.  Check `h_proto`.
2.  If `ETH_P_IP` -> parse `struct iphdr` -> lookup `policy_map`.
3.  If `ETH_P_IPV6` -> parse `struct ipv6hdr` -> lookup `policy_map_v6`.

### 2. Linux Enforcer (`pkg/enforcer/ebpf_linux.go`)

The Go userspace code must populate the new map.

- Iterate over policies.
- Detect if an IP (cidr or resolved label) is IPv4 or IPv6.
- If IPv4 -> Add to `policy_map`.
- If IPv6 -> Add to `policy_map_v6`.
- The `policyKey` struct in Go will need a V6 counterpart.

### 3. Iptables Enforcer (`pkg/enforcer/iptables_linux.go`)

The `IptablesEnforcer` currently invokes `iptables` and `iptables-restore`.
It will be modified to:

- Separate rules into v4 and v6 buffers.
- Execute `iptables-restore` for v4 rules.
- Execute `ip6tables-restore` for v6 rules.
- Manage `ZTAP-INGRESS` and `ZTAP-EGRESS` chains in both `iptables` and `ip6tables`.

## Data Structures

### Go Structures

In `pkg/enforcer/ebpf_linux.go`:

```go
type policyKeyV6 struct {
    CgroupID  uint64
    IP        [4]uint32 // 16 bytes
    Port      uint16
    Protocol  uint8
    Direction uint8
}
```

### BPF Structures

In `bpf/filter.c`:

```c
// Standard IPv6 Header
struct ipv6hdr {
    __u32 priority:4;
    __u32 version:4;
    __u32 flow_lbl:24;
    __u16 payload_len;
    __u8  nexthdr;
    __u8  hop_limit;
    struct in6_addr saddr;
    struct in6_addr daddr;
};
```

## Implementation Plan

### Phase 1: eBPF Support

1.  Update `bpf/filter.c` with IPv6 structs and map.
2.  Recompile BPF objects (`go generate`).
3.  Update `ebpf_linux.go` to split policies by IP family and load into respective maps.
4.  Update flow event generation to support IPv6 addresses in ring buffer events.

### Phase 2: Iptables Support

1.  Refactor `iptables_linux.go` to support a `binary` parameter (iptables vs ip6tables).
2.  Implement `LoadPolicies` to split rulesets and apply both.

### Phase 3: Validation & Testing

1.  **Unit Tests**:
    - Test `LoadPolicies` with mixed v4/v6 CIDRs.
    - Verify correct serialization of `policyKeyV6`.
2.  **Integration Tests**:
    - Extend `tests/integration_test.go` to use `ping6` and `nc -6`.
    - Verify `ztap flows` shows IPv6 addresses.

## Operational Constraints

- **Kernel Version**: IPv6 BPF support is standard in target kernels (5.7+), no new constraints.
- **Performance**: IPv6 lookup adds minimal overhead (parsing header + hash calculation).
- **Memory**: New map consumes additional memory; default size 10,000 entries (approx 1MB).

## Future Work

- **NAT64/DNS64**: Explicit support for translation scenarios (out of scope for initial enforcement).
- **IPv6 Segment Routing**: Advanced policy matching on SRv6 headers (out of scope).
