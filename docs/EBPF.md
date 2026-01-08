# eBPF Enforcement Setup

ZTAP uses eBPF (Extended Berkeley Packet Filter) for high-performance, kernel-level network policy enforcement on Linux systems.

## Overview

ZTAP employs a **pre-compiled binary** strategy. The eBPF bytecode is compiled at build-time and embedded directly into the Go binary using `bpf2go`. This eliminates the need for `clang`, `llvm`, or kernel headers on the target production systems.

## Prerequisites

### Runtime Requirements

- **Operating System**: Linux kernel 5.7+ (for cgroup v2 support)
- **Root/CAP_BPF**: Root privileges or `CAP_BPF` and `CAP_NET_ADMIN` capabilities
- **cgroup v2**: Must be mounted at `/sys/fs/cgroup`

No compiler toolchain is required at runtime.

### Build/Development Dependencies

If you are building ZTAP from source or modifying the eBPF program, you will need:

- `clang` (LLVM compiler)
- `llvm`
- Go 1.24+

#### Install Build Dependencies (Ubuntu/Debian)

```bash
sudo apt-get update
sudo apt-get install -y clang llvm
```

## Compilation

### Standard Build (Go)

The eBPF bytecode is automatically generated and embedded during the build process if `go generate` is run:

```bash
# Generate the Go wrappers for eBPF bytecode
go generate ./pkg/enforcer/...

# Build the binary
go build -o ztap
```

### Manual C Compilation (Optional)

If you wish to manually compile the C source without using the Go generator:

```bash
cd bpf
make
```

After a manual build, the object file will be at `bpf/filter.o`. You can force ZTAP to use this local file instead of the embedded bytecode by setting an environment variable:

```bash
export ZTAP_BPF_OBJECT=$PWD/bpf/filter.o
sudo ./ztap enforce -f policy.yaml
```

## Loader Search Order

When `ZTAP_BPF_OBJECT` is not set, ZTAP uses the embedded bytecode. If `ZTAP_BPF_OBJECT` is provided, it takes precedence.

Historical search paths for `filter.o` (deprecated in favor of embedding):

- `<repo-root>/bpf/filter.o`
- `/usr/local/share/ztap/bpf/filter.o`

## eBPF Program Variants

ZTAP provides two eBPF program variants:

### 1. Strict Mode (Default: `filter_egress`)

- **Behavior**: Deny-by-default, allow only explicitly permitted traffic
- **Use Case**: High-security environments, zero-trust networks
- **Implementation**: Blocks all packets unless a matching policy exists

### 2. Permissive Mode (`filter_egress_permissive`)

- **Behavior**: Allow-by-default, block only explicitly denied traffic
- **Use Case**: Development, testing, gradual rollout
- **Implementation**: Allows all packets unless explicitly blocked

To switch variants, modify `ebpf_linux.go`:

```go
FilterProg *ebpf.Program `ebpf:"filter_egress_permissive"`
```

## Architecture

### eBPF Map Structure

```c
struct policy_key {
    __u64 cgroup_id;  // Source cgroup id (0 = global fallback)
    __u32 dest_ip;    // Destination IP address (network byte order)
    __u16 dest_port;  // Destination port
    __u8  protocol;   // Protocol (6=TCP, 17=UDP, 1=ICMP)
    __u8  _pad;       // Padding for alignment
};

struct policy_value {
    __u8 action;      // 0=block, 1=allow
    __u8 _pad[3];     // Padding for alignment
};
```

Lookup behavior:

- The dataplane looks up policies using the current process cgroup id.
- If there is no match for the current cgroup id, it falls back to `cgroup_id = 0` to preserve existing “global” enforcement.

### Flow Events Ring Buffer

Flow events are streamed to userspace via a ring buffer:

```c
struct flow_event {
    __u64 timestamp_ns;  // Kernel timestamp (nanoseconds since boot)
    __u32 src_ip;        // Source IP address
    __u32 dest_ip;       // Destination IP address
    __u16 src_port;      // Source port
    __u16 dest_port;     // Destination port
    __u8  protocol;      // Protocol (TCP=6, UDP=17, ICMP=1)
    __u8  direction;     // 0=egress, 1=ingress
    __u8  action;        // 0=blocked, 1=allowed
    __u8  pad;           // Padding
};
```

The ring buffer (256KB) is intended to enable real-time flow monitoring:

On Linux, `ztap enforce` pins the `flow_events` ring buffer map at:

`/sys/fs/bpf/ztap/flow_events`

`ztap flows --follow` opens this pinned map and streams events in real time. If enforcement isn't active (or the map isn't pinned), `ztap flows` falls back to simulated output.

### Attachment Points

eBPF programs attach to cgroups using `BPF_CGROUP_INET_EGRESS` (and ingress where supported):

- **Scope**: Applies to all processes in the cgroup
- **Direction**: Egress (outbound) traffic only
- **Performance**: Inline filtering with minimal latency

## Usage

### Basic Usage (with ZTAP)

ZTAP automatically loads and attaches eBPF programs when policies are enforced:

```bash
# Enforce a policy (requires root on Linux)
sudo ztap enforce -f policy.yaml

# Override cgroup path (Linux)
sudo ztap enforce -f policy.yaml --cgroup /sys/fs/cgroup

# Point directly at a compiled object file (Linux)
sudo ztap enforce -f policy.yaml --bpf-object /absolute/path/to/bpf/filter.o

# Enable debug logs for object load attempts (Linux)
sudo ztap enforce -f policy.yaml --debug-ebpf

# Check enforcement status
ztap status
```

Notes:

- `ztap enforce` keeps running while enforcement is active. Press Ctrl+C to detach and exit.
- The eBPF enforcer currently supports only IPv4 `ipBlock` rules with `/32` CIDRs, and TCP/UDP only.
  Policies that use non-/32 CIDRs will be rejected to avoid unsafe partial enforcement.
  Policies that use `podSelector` targets can be enforced on Linux by first resolving selectors into `/32` `ipBlock` rules:
  - In-cluster: run `ztap agent` (Kubernetes discovery is used automatically)
  - Local/CLI: run `ztap enforce --resolve-labels` with `discovery.backend: k8s` configured (kubeconfig-based)
    Cloud sync backends can also translate selectors (for example, `ztap gcp firewall-sync`).

### Manual Testing (Advanced)

For testing the eBPF program directly:

```bash
# Load the program
sudo bpftool prog load filter.o /sys/fs/bpf/ztap_filter type cgroup/skb

# Attach to cgroup
sudo bpftool cgroup attach /sys/fs/cgroup egress pinned /sys/fs/bpf/ztap_filter

# View loaded programs
sudo bpftool prog show

# Detach
sudo bpftool cgroup detach /sys/fs/cgroup egress pinned /sys/fs/bpf/ztap_filter
```

## Troubleshooting

### "missing BTF" / "load BTF maps: missing BTF"

If you see an error like:

```
load BTF maps: missing BTF
```

Ensure the object was compiled with debug info so it embeds BTF:

```bash
cd bpf
make clean && make
```

The Makefile includes `-g` by default. If you removed it, add it back to `CLANG_FLAGS`.

Additionally, you can point the loader directly to the object and enable debug logging:

```bash
export ZTAP_BPF_OBJECT=/absolute/path/to/bpf/filter.o
export ZTAP_DEBUG_EBPF=1
```

Then re-run your test or binary.

### "eBPF object file not found"

**Error**: `eBPF object file not found. Please compile with: cd bpf && make`

**Solution**: Compile the eBPF program:

```bash
cd bpf && make
```

### "failed to remove memlock"

**Error**: `failed to remove memlock: operation not permitted`

**Solution**: Run with root privileges or add `CAP_BPF` capability:

```bash
sudo ztap daemon
# OR
sudo setcap cap_bpf,cap_net_admin+ep ./ztap
```

### "failed to load eBPF objects"

**Possible Causes**:

1. Kernel version < 5.7
2. BPF not enabled in kernel
3. Invalid eBPF program

**Check Kernel Version**:

```bash
uname -r
```

**Verify BPF Support**:

```bash
zgrep BPF /proc/config.gz | grep -E 'BPF=|CGROUP'
```

Should show:

```
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_CGROUP_BPF=y
```

### "failed to attach to cgroup"

**Error**: `failed to attach to cgroup: no such file or directory`

**Solution**: Verify cgroup v2 is mounted:

```bash
mount | grep cgroup2
# Should show: cgroup2 on /sys/fs/cgroup type cgroup2 ...
```

If not mounted:

```bash
sudo mount -t cgroup2 none /sys/fs/cgroup
```

### Debugging eBPF Programs

#### View eBPF Logs

```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

#### List Loaded Maps

```bash
sudo bpftool map show
```

#### Dump Map Contents

```bash
# Find map ID
sudo bpftool map show | grep policy_map

# Dump map (replace <id> with actual map ID)
sudo bpftool map dump id <id>
```

## Performance Considerations

### Overhead

- **CPU**: < 5% overhead for typical workloads
- **Latency**: < 100ns per packet
- **Memory**: ~10MB for 10,000 policy entries

### Scalability

- **Map Capacity**: 10,000 policy entries (configurable)
- **Hash Lookup**: O(1) constant time
- **No Context Switch**: Runs entirely in kernel space

### Optimization Tips

1. **Aggregate Policies**: Combine similar rules to reduce map entries
2. **CIDR Ranges**: Use broader CIDR blocks where appropriate
3. **Protocol-Specific**: Apply policies at protocol level (TCP/UDP)

## Security Considerations

### Kernel Verifier

All eBPF programs are verified by the kernel before loading:

- **Memory Safety**: No out-of-bounds access
- **Termination**: Guaranteed to finish in bounded time
- **No Crashes**: Cannot crash the kernel

### Attack Surface

- **Minimal**: eBPF runs in sandboxed environment
- **Auditable**: Source code is visible and inspectable
- **Type-Safe**: C code compiled with strict checks

### Best Practices

1. **Principle of Least Privilege**: Use strict mode by default
2. **Regular Audits**: Review eBPF map contents periodically
3. **Logging**: Enable logging for blocked connections
4. **Updates**: Keep kernel and ZTAP up-to-date

## Development

### Testing Changes

After modifying `filter.c`:

```bash
cd bpf
make clean
make
make verify
```

### Adding Debug Output

Use `bpf_trace_printk()` for debugging:

```c
char fmt[] = "Blocked: IP=%x Port=%d\n";
bpf_trace_printk(fmt, sizeof(fmt), dest_ip, dest_port);
```

View output:

```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

### Running Tests (Linux Only)

```bash
# Run enforcer tests (requires Linux)
GOOS=linux go test ./pkg/enforcer -v

# Run full eBPF verification (requires root + build tags)
sudo GOOS=linux go test -tags integration ./pkg/enforcer -run TestEBPFIntegrationLoadAndAttach -v
```

The integration test recompiles `bpf/filter.o`, attaches the compiled program to a temporary
cgroup, and asserts that policy entries populate the eBPF map correctly. Ensure the kernel headers
match the running kernel before executing it.

## Platform Support

| Platform | eBPF Support | Fallback |
| -------- | ------------ | -------- |
| Linux    | Yes (Native) | N/A      |
| macOS    | No           | Firewall |
| Windows  | No           | Firewall |
| FreeBSD  | Limited      | Firewall |

Note: ZTAP supports Windows enforcement via WFP (Windows Filtering Platform), which is separate from eBPF.

## References

- [eBPF Documentation](https://ebpf.io/)
- [Cilium eBPF Library](https://github.com/cilium/ebpf)
- [Linux BPF Documentation](https://www.kernel.org/doc/html/latest/bpf/)
- [cgroup v2 Documentation](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html)
