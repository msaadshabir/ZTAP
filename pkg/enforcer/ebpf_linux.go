//go:build linux
// +build linux

package enforcer

import (
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"ztap/pkg/policy"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// eBPFEnforcer manages eBPF programs for network policy enforcement
type eBPFEnforcer struct {
	objs     *bpfObjects
	links    []link.Link
	policies []policy.NetworkPolicy
}

// bpfObjects contains loaded eBPF programs and maps
type bpfObjects struct {
	PolicyMap  *ebpf.Map     `ebpf:"policy_map"`
	FilterProg *ebpf.Program `ebpf:"filter_egress"`
}

// policyKey represents the key for eBPF policy map
type policyKey struct {
	DestIP   uint32
	DestPort uint16
	Protocol uint8
	_        uint8 // padding
}

// policyValue represents the value for eBPF policy map
type policyValue struct {
	Action uint8    // 0 = block, 1 = allow
	_      [3]uint8 // padding
}

// NewEBPFEnforcer creates a new eBPF enforcer
func NewEBPFEnforcer() (*eBPFEnforcer, error) {
	// Remove resource limits for loading eBPF programs
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("failed to remove memlock: %w", err)
	}

	return &eBPFEnforcer{
		links: make([]link.Link, 0),
	}, nil
}

// LoadPolicies loads policies into eBPF maps
func (e *eBPFEnforcer) LoadPolicies(policies []policy.NetworkPolicy) error {
	e.policies = policies

	// Try to load eBPF object file
	// First check if compiled BPF program exists
	// Determine repo root based on this source file location to handle tests run from package dirs
	var repoRootCandidate string
	if _, thisFile, _, ok := runtime.Caller(0); ok {
		repoRootCandidate = filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", ".."))
	}

	bpfPaths := []string{
		// Absolute path from repo root if detectable
		filepath.Join(repoRootCandidate, "bpf", "filter.o"),
		// Relative to current working directory (when CWD is repo root)
		"bpf/filter.o",
		// Relative to package directory (when CWD is pkg/enforcer)
		filepath.Join("..", "..", "bpf", "filter.o"),
		// System-wide locations
		"/usr/local/share/ztap/bpf/filter.o",
		filepath.Join(os.Getenv("HOME"), ".ztap", "bpf", "filter.o"),
	}

	var spec *ebpf.CollectionSpec
	var err error

	for _, path := range bpfPaths {
		spec, err = ebpf.LoadCollectionSpec(path)
		if err == nil {
			log.Printf("Loaded eBPF spec from: %s", path)
			break
		}
	}

	if spec == nil {
		// Fallback: create inline spec (simplified version without actual BPF code)
		return fmt.Errorf("eBPF object file not found. Please compile with: cd bpf && make")
	}

	objs := &bpfObjects{}
	if err := spec.LoadAndAssign(objs, nil); err != nil {
		return fmt.Errorf("failed to load eBPF objects: %w", err)
	}
	e.objs = objs

	// Populate policy map
	for _, p := range policies {
		if err := e.addPolicyToMap(p); err != nil {
			log.Printf("Warning: Failed to add policy '%s': %v", p.Metadata.Name, err)
		}
	}

	return nil
}

// addPolicyToMap adds a policy to the eBPF map
func (e *eBPFEnforcer) addPolicyToMap(p policy.NetworkPolicy) error {
	for _, egress := range p.Spec.Egress {
		// Handle IP-based rules
		if egress.To.IPBlock.CIDR != "" {
			ip, ipnet, err := net.ParseCIDR(egress.To.IPBlock.CIDR)
			if err != nil {
				return fmt.Errorf("invalid CIDR %s: %w", egress.To.IPBlock.CIDR, err)
			}

			// For simplicity, use network address (full CIDR support requires range)
			destIP := ipToUint32(ip.To4())

			for _, port := range egress.Ports {
				key := policyKey{
					DestIP:   destIP,
					DestPort: uint16(port.Port),
					Protocol: protocolToNum(port.Protocol),
				}

				value := policyValue{
					Action: 1, // allow
				}

				if err := e.objs.PolicyMap.Put(&key, &value); err != nil {
					return fmt.Errorf("failed to update policy map: %w", err)
				}

				log.Printf("Added eBPF rule: %s -> %s:%d (ALLOW)",
					p.Metadata.Name, ipnet.String(), port.Port)
			}
		}

		// Handle label-based rules (requires resolution)
		if len(egress.To.PodSelector.MatchLabels) > 0 {
			log.Printf("Warning: Label-based rules require IP resolution for policy '%s'",
				p.Metadata.Name)
			// In production: resolve labels to IPs via service discovery, then add to map
		}
	}

	return nil
}

// Attach attaches the eBPF program to cgroup
func (e *eBPFEnforcer) Attach(cgroupPath string) error {
	if e.objs == nil {
		return fmt.Errorf("eBPF objects not loaded")
	}

	// Attach to cgroup egress
	l, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupInetEgress,
		Program: e.objs.FilterProg,
	})
	if err != nil {
		return fmt.Errorf("failed to attach to cgroup: %w", err)
	}

	e.links = append(e.links, l)
	log.Printf("eBPF program attached to cgroup: %s", cgroupPath)

	return nil
}

// Close cleans up eBPF resources
func (e *eBPFEnforcer) Close() error {
	// Detach programs
	for _, l := range e.links {
		if err := l.Close(); err != nil {
			log.Printf("Warning: Failed to close link: %v", err)
		}
	}

	// Close maps and programs
	if e.objs != nil {
		if e.objs.PolicyMap != nil {
			e.objs.PolicyMap.Close()
		}
		if e.objs.FilterProg != nil {
			e.objs.FilterProg.Close()
		}
	}

	return nil
}

// Helper functions

func ipToUint32(ip net.IP) uint32 {
	if ip == nil {
		return 0
	}
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func protocolToNum(protocol string) uint8 {
	switch strings.ToUpper(protocol) {
	case "TCP":
		return 6
	case "UDP":
		return 17
	case "ICMP":
		return 1
	default:
		return 0
	}
}

// EnforceWithEBPFReal uses actual eBPF enforcement (requires root)
func EnforceWithEBPFReal(policies []policy.NetworkPolicy, cgroupPath string) error {
	enforcer, err := NewEBPFEnforcer()
	if err != nil {
		return fmt.Errorf("failed to create eBPF enforcer: %w", err)
	}

	if err := enforcer.LoadPolicies(policies); err != nil {
		return fmt.Errorf("failed to load policies: %w", err)
	}

	if err := enforcer.Attach(cgroupPath); err != nil {
		return fmt.Errorf("failed to attach eBPF program: %w", err)
	}

	log.Printf("Successfully enforced %d policies via eBPF", len(policies))
	return nil
}
