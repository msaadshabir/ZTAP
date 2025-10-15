# eBPF Enforcement Setup

ZTAP uses eBPF (Extended Berkeley Packet Filter) for high-performance, kernel-level network policy enforcement on Linux systems.

## Prerequisites

### System Requirements

- **Operating System**: Linux kernel 5.7+ (for cgroup v2 support)
- **Root/CAP_BPF**: Root privileges or `CAP_BPF` and `CAP_NET_ADMIN` capabilities
- **cgroup v2**: Must be mounted at `/sys/fs/cgroup`

### Build Dependencies

- `clang` (LLVM compiler)
- Linux kernel headers
- `make`

#### Install on Ubuntu/Debian

```bash
sudo apt-get update
sudo apt-get install -y clang llvm make linux-headers-$(uname -r)
```

#### Install on Fedora/RHEL

```bash
sudo dnf install -y clang llvm make kernel-headers kernel-devel
```

#### Install on Arch Linux

```bash
sudo pacman -S clang llvm make linux-headers
```

## Compilation

### Build the eBPF Program

```bash
cd bpf
make
```

This compiles `filter.c` to `filter.o` (eBPF bytecode).

### Verify Compilation

```bash
make verify
```

This uses `llvm-objdump` to inspect the compiled eBPF program.

### Clean Build Artifacts

```bash
make clean
```

## Installation

### System-Wide Installation

Copy the compiled eBPF program to a system location:

```bash
sudo mkdir -p /usr/local/share/ztap/bpf
sudo cp filter.o /usr/local/share/ztap/bpf/
```

### User Installation

For non-root users (limited functionality):

```bash
mkdir -p ~/.ztap/bpf
cp filter.o ~/.ztap/bpf/
```

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

### Attachment Points

eBPF programs attach to cgroups using `BPF_CGROUP_INET_EGRESS`:

- **Scope**: Applies to all processes in the cgroup
- **Direction**: Egress (outbound) traffic only
- **Performance**: Inline filtering with minimal latency

## Usage

### Basic Usage (with ZTAP)

ZTAP automatically loads and attaches eBPF programs when policies are applied:

```bash
# Start ZTAP daemon (requires root)
sudo ztap daemon

# Apply policies
ztap policy apply examples/web-policy.yaml
```

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

## References

- [eBPF Documentation](https://ebpf.io/)
- [Cilium eBPF Library](https://github.com/cilium/ebpf)
- [Linux BPF Documentation](https://www.kernel.org/doc/html/latest/bpf/)
- [cgroup v2 Documentation](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html)

## Contributing

When contributing eBPF changes:

1. Test on multiple kernel versions (5.7+, 5.15+, 6.0+)
2. Verify with `make verify`
3. Check for verifier warnings
4. Document any new map structures
5. Update this documentation

For questions or issues, see [GitHub Issues](https://github.com/your-org/ztap/issues).
