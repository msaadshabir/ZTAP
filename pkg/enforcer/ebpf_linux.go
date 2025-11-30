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
	PolicyMap     *ebpf.Map     `ebpf:"policy_map"`
	FlowEvents    *ebpf.Map     `ebpf:"flow_events"`
	FilterEgress  *ebpf.Program `ebpf:"filter_egress"`
	FilterIngress *ebpf.Program `ebpf:"filter_ingress"`
}

// Direction constants matching BPF program
const (
	DirectionEgress  uint8 = 0
	DirectionIngress uint8 = 1
)

// policyKey represents the key for eBPF policy map
// Must match struct policy_key in bpf/filter.c
type policyKey struct {
	IP        uint32 // dest_ip for egress, src_ip for ingress
	Port      uint16 // dest_port for egress, dest_port for ingress
	Protocol  uint8
	Direction uint8 // 0 = egress, 1 = ingress
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

	// Allow explicit override via environment variable
	if p := os.Getenv("ZTAP_BPF_OBJECT"); p != "" {
		log.Printf("ZTAP_BPF_OBJECT override set: %s", p)
	}

	bpfPaths := []string{
		// Explicit override (if set)
		os.Getenv("ZTAP_BPF_OBJECT"),
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
	var attempts []string

	for _, path := range bpfPaths {
		if path == "" {
			continue
		}
		// Log attempt in debug mode
		if os.Getenv("ZTAP_DEBUG_EBPF") == "1" {
			log.Printf("Attempting to load eBPF object: %s", path)
		}
		if _, statErr := os.Stat(path); statErr != nil {
			attempts = append(attempts, fmt.Sprintf("%s: %v", path, statErr))
			continue
		}
		spec, err = ebpf.LoadCollectionSpec(path)
		if err == nil {
			log.Printf("Loaded eBPF spec from: %s", path)
			break
		}
		attempts = append(attempts, fmt.Sprintf("%s: %v", path, err))
	}

	if spec == nil {
		// Provide detailed diagnostic information
		return fmt.Errorf("failed to load eBPF object. Please compile with: 'cd bpf && make'. Attempts: [%s]",
			strings.Join(attempts, "; "))
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
	// Handle egress rules
	for _, egress := range p.Spec.Egress {
		if err := e.addEgressRule(p.Metadata.Name, egress); err != nil {
			return err
		}
	}

	// Handle ingress rules
	for _, ingress := range p.Spec.Ingress {
		if err := e.addIngressRule(p.Metadata.Name, ingress); err != nil {
			return err
		}
	}

	return nil
}

// addEgressRule adds an egress rule to the eBPF map
func (e *eBPFEnforcer) addEgressRule(policyName string, egress policy.EgressRule) error {
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
				IP:        destIP,
				Port:      uint16(port.Port),
				Protocol:  protocolToNum(port.Protocol),
				Direction: DirectionEgress,
			}

			value := policyValue{
				Action: 1, // allow
			}

			if err := e.objs.PolicyMap.Put(&key, &value); err != nil {
				return fmt.Errorf("failed to update policy map: %w", err)
			}

			log.Printf("Added eBPF egress rule: %s -> %s:%d (ALLOW)",
				policyName, ipnet.String(), port.Port)
		}
	}

	// Handle label-based rules (requires resolution)
	if len(egress.To.PodSelector.MatchLabels) > 0 {
		log.Printf("Warning: Label-based egress rules require IP resolution for policy '%s'",
			policyName)
		// In production: resolve labels to IPs via service discovery, then add to map
	}

	return nil
}

// addIngressRule adds an ingress rule to the eBPF map
func (e *eBPFEnforcer) addIngressRule(policyName string, ingress policy.IngressRule) error {
	// Handle IP-based rules
	if ingress.From.IPBlock.CIDR != "" {
		ip, ipnet, err := net.ParseCIDR(ingress.From.IPBlock.CIDR)
		if err != nil {
			return fmt.Errorf("invalid CIDR %s: %w", ingress.From.IPBlock.CIDR, err)
		}

		// For simplicity, use network address (full CIDR support requires range)
		srcIP := ipToUint32(ip.To4())

		for _, port := range ingress.Ports {
			key := policyKey{
				IP:        srcIP,
				Port:      uint16(port.Port),
				Protocol:  protocolToNum(port.Protocol),
				Direction: DirectionIngress,
			}

			value := policyValue{
				Action: 1, // allow
			}

			if err := e.objs.PolicyMap.Put(&key, &value); err != nil {
				return fmt.Errorf("failed to update policy map: %w", err)
			}

			log.Printf("Added eBPF ingress rule: %s <- %s:%d (ALLOW)",
				policyName, ipnet.String(), port.Port)
		}
	}

	// Handle label-based rules (requires resolution)
	if len(ingress.From.PodSelector.MatchLabels) > 0 {
		log.Printf("Warning: Label-based ingress rules require IP resolution for policy '%s'",
			policyName)
		// In production: resolve labels to IPs via service discovery, then add to map
	}

	return nil
}

// Attach attaches the eBPF programs to cgroup for both egress and ingress
func (e *eBPFEnforcer) Attach(cgroupPath string) error {
	if e.objs == nil {
		return fmt.Errorf("eBPF objects not loaded")
	}

	// Attach egress filter to cgroup
	if e.objs.FilterEgress != nil {
		l, err := link.AttachCgroup(link.CgroupOptions{
			Path:    cgroupPath,
			Attach:  ebpf.AttachCGroupInetEgress,
			Program: e.objs.FilterEgress,
		})
		if err != nil {
			return fmt.Errorf("failed to attach egress filter to cgroup: %w", err)
		}
		e.links = append(e.links, l)
		log.Printf("eBPF egress filter attached to cgroup: %s", cgroupPath)
	}

	// Attach ingress filter to cgroup
	if e.objs.FilterIngress != nil {
		l, err := link.AttachCgroup(link.CgroupOptions{
			Path:    cgroupPath,
			Attach:  ebpf.AttachCGroupInetIngress,
			Program: e.objs.FilterIngress,
		})
		if err != nil {
			return fmt.Errorf("failed to attach ingress filter to cgroup: %w", err)
		}
		e.links = append(e.links, l)
		log.Printf("eBPF ingress filter attached to cgroup: %s", cgroupPath)
	}

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
		if e.objs.FlowEvents != nil {
			e.objs.FlowEvents.Close()
		}
		if e.objs.FilterEgress != nil {
			e.objs.FilterEgress.Close()
		}
		if e.objs.FilterIngress != nil {
			e.objs.FilterIngress.Close()
		}
	}

	return nil
}

// GetFlowEventsMap returns the flow_events ring buffer map for flow monitoring.
// Returns nil if the eBPF program is not loaded.
func (e *eBPFEnforcer) GetFlowEventsMap() *ebpf.Map {
	if e.objs == nil {
		return nil
	}
	return e.objs.FlowEvents
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
