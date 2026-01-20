//go:build linux
// +build linux

package enforcer

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -target bpfeb -cc clang bpf ../../bpf/filter.c -- -I../../bpf

import (
	"fmt"
	"math"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"ztap/pkg/logging"
	"ztap/pkg/policy"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

var (
	activeEBPFMu       sync.Mutex
	activeEBPFEnforcer *eBPFEnforcer
)

// eBPFEnforcer manages eBPF programs for network policy enforcement
type eBPFEnforcer struct {
	objs        *bpfObjects
	egressLink  link.Link
	ingressLink link.Link
	policies    []policy.NetworkPolicy
	// flowEventsPinPath is the bpffs pin path for the flow_events map (if pinned).
	flowEventsPinPath string
}

const DefaultFlowEventsPinPath = "/sys/fs/bpf/ztap/flow_events"

// Direction constants matching BPF program
const (
	DirectionEgress  uint8 = 0
	DirectionIngress uint8 = 1
)

// policyKey represents the key for eBPF policy map
// Must match struct policy_key in bpf/filter.c
type policyKey struct {
	CgroupID  uint64
	IP        uint32 // dest_ip for egress, src_ip for ingress
	Port      uint16 // dest_port for egress, dest_port for ingress
	Protocol  uint8
	Direction uint8 // 0 = egress, 1 = ingress
}

// policyKeyV6 represents the key for eBPF policy map (IPv6)
// Must match struct policy_key_v6 in bpf/filter.c
type policyKeyV6 struct {
	CgroupID  uint64
	IP        [4]uint32
	Port      uint16
	Protocol  uint8
	Direction uint8
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

	return &eBPFEnforcer{}, nil
}

// LoadPolicies loads policies into eBPF maps
func (e *eBPFEnforcer) LoadPolicies(policies []policy.NetworkPolicy) error {
	e.policies = policies

	var objs bpfObjects
	var err error

	// Allow explicit override via environment variable (useful for development)
	if p := os.Getenv("ZTAP_BPF_OBJECT"); p != "" {
		safeP := strings.ReplaceAll(p, "\n", "")
		safeP = strings.ReplaceAll(safeP, "\r", "")
		logging.Infof("Loading eBPF object from override: %s", safeP)
		spec, err := ebpf.LoadCollectionSpec(p)
		if err != nil {
			return fmt.Errorf("failed to load eBPF object from %s: %w", safeP, err)
		}
		if err := spec.LoadAndAssign(&objs, nil); err != nil {
			return fmt.Errorf("failed to load eBPF objects from %s: %w", safeP, err)
		}
	} else {
		// Load embedded eBPF objects
		if err = loadBpfObjects(&objs, nil); err != nil {
			return fmt.Errorf("failed to load embedded eBPF objects: %w", err)
		}
	}
	e.objs = &objs

	// Populate policy map
	for _, p := range policies {
		if err := e.addPolicyToMap(p); err != nil {
			safeName := strings.ReplaceAll(p.Metadata.Name, "\n", "")
			safeName = strings.ReplaceAll(safeName, "\r", "")
			safeErr := strings.ReplaceAll(err.Error(), "\n", "")
			safeErr = strings.ReplaceAll(safeErr, "\r", "")
			logging.Warnf("Failed to add policy '%s': %s", safeName, safeErr)
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
	safePolicyName := strings.ReplaceAll(policyName, "\n", "")
	safePolicyName = strings.ReplaceAll(safePolicyName, "\r", "")

	// Handle IP-based rules
	if egress.To.IPBlock.CIDR != "" {
		ip, ipnet, err := net.ParseCIDR(egress.To.IPBlock.CIDR)
		if err != nil {
			return fmt.Errorf("invalid CIDR %s: %w", egress.To.IPBlock.CIDR, err)
		}

		// Detect if it's IPv4 or IPv6
		isIPv6 := ip.To4() == nil

		for _, port := range egress.Ports {
			portValue, err := toUint16Port(port.Port)
			if err != nil {
				return err
			}
			protocol := protocolToNum(port.Protocol)

			if isIPv6 {
				// Remap ICMP (1) to ICMPv6 (58) for IPv6 rules
				if protocol == 1 {
					protocol = 58
				}

				key := policyKeyV6{
					IP:        ipToUint32Array(ip),
					Port:      portValue,
					Protocol:  protocol,
					Direction: DirectionEgress,
				}
				value := policyValue{Action: 1}
				if err := e.objs.PolicyMapV6.Put(&key, &value); err != nil {
					return fmt.Errorf("failed to update IPv6 policy map: %w", err)
				}
			} else {
				key := policyKey{
					IP:        ipToUint32(ip.To4()),
					Port:      portValue,
					Protocol:  protocol,
					Direction: DirectionEgress,
				}
				value := policyValue{Action: 1}
				if err := e.objs.PolicyMap.Put(&key, &value); err != nil {
					return fmt.Errorf("failed to update policy map: %w", err)
				}
			}

			safeDest := strings.ReplaceAll(ipnet.String(), "\n", "")
			safeDest = strings.ReplaceAll(safeDest, "\r", "")
			safePort := strings.ReplaceAll(fmt.Sprint(port.Port), "\n", "")
			safePort = strings.ReplaceAll(safePort, "\r", "")
			logging.Debugf("Added eBPF egress rule: %s -> %s:%s (ALLOW)",
				safePolicyName, safeDest, safePort)
		}
	}

	// Handle label-based rules (requires resolution)
	if len(egress.To.PodSelector.MatchLabels) > 0 {
		logging.Warnf("Label-based egress rules require IP resolution for policy '%s'",
			strings.ReplaceAll(strings.ReplaceAll(policyName, "\n", ""), "\r", ""))
		// In production: resolve labels to IPs via service discovery, then add to map
	}

	return nil
}

// addIngressRule adds an ingress rule to the eBPF map
func (e *eBPFEnforcer) addIngressRule(policyName string, ingress policy.IngressRule) error {
	safePolicyName := strings.ReplaceAll(policyName, "\n", "")
	safePolicyName = strings.ReplaceAll(safePolicyName, "\r", "")

	// Handle IP-based rules
	if ingress.From.IPBlock.CIDR != "" {
		ip, ipnet, err := net.ParseCIDR(ingress.From.IPBlock.CIDR)
		if err != nil {
			return fmt.Errorf("invalid CIDR %s: %w", ingress.From.IPBlock.CIDR, err)
		}

		// Detect if it's IPv4 or IPv6
		isIPv6 := ip.To4() == nil

		for _, port := range ingress.Ports {
			portValue, err := toUint16Port(port.Port)
			if err != nil {
				return err
			}
			protocol := protocolToNum(port.Protocol)

			if isIPv6 {
				// Remap ICMP (1) to ICMPv6 (58) for IPv6 rules
				if protocol == 1 {
					protocol = 58
				}

				key := policyKeyV6{
					IP:        ipToUint32Array(ip),
					Port:      portValue,
					Protocol:  protocol,
					Direction: DirectionIngress,
				}
				value := policyValue{Action: 1}
				if err := e.objs.PolicyMapV6.Put(&key, &value); err != nil {
					return fmt.Errorf("failed to update IPv6 policy map: %w", err)
				}
			} else {
				key := policyKey{
					IP:        ipToUint32(ip.To4()),
					Port:      portValue,
					Protocol:  protocol,
					Direction: DirectionIngress,
				}
				value := policyValue{Action: 1}
				if err := e.objs.PolicyMap.Put(&key, &value); err != nil {
					return fmt.Errorf("failed to update policy map: %w", err)
				}
			}

			safeSrc := strings.ReplaceAll(ipnet.String(), "\n", "")
			safeSrc = strings.ReplaceAll(safeSrc, "\r", "")
			// Normalize port before logging to avoid depending directly on user-controlled data.
			safePortStr := fmt.Sprintf("%d", port.Port)
			safePortStr = strings.ReplaceAll(safePortStr, "\n", "")
			safePortStr = strings.ReplaceAll(safePortStr, "\r", "")
			logging.Debugf("Added eBPF ingress rule: %s <- %s:%s (ALLOW)",
				safePolicyName, safeSrc, safePortStr)
		}
	}

	// Handle label-based rules (requires resolution)
	if len(ingress.From.PodSelector.MatchLabels) > 0 {
		logging.Warnf("Label-based ingress rules require IP resolution for policy '%s'",
			strings.ReplaceAll(strings.ReplaceAll(policyName, "\n", ""), "\r", ""))
		// In production: resolve labels to IPs via service discovery, then add to map
	}

	return nil
}

func toUint16Port(p int) (uint16, error) {
	if p < 0 || p > math.MaxUint16 {
		return 0, fmt.Errorf("invalid port %d: must be 0-%d", p, math.MaxUint16)
	}
	return uint16(p), nil //nolint:gosec // G115: conversion is safe after bounds check
}

// Attach attaches the eBPF programs to cgroup for both egress and ingress
func (e *eBPFEnforcer) Attach(cgroupPath string) error {
	if e.objs == nil {
		return fmt.Errorf("eBPF objects not loaded")
	}

	safeCgroupPath := strings.ReplaceAll(cgroupPath, "\n", "")
	safeCgroupPath = strings.ReplaceAll(safeCgroupPath, "\r", "")

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
		e.egressLink = l
		logging.Infof("eBPF egress filter attached to cgroup: %s", safeCgroupPath)
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
		e.ingressLink = l
		logging.Infof("eBPF ingress filter attached to cgroup: %s", safeCgroupPath)
	}

	return nil
}

// UpdateFrom transfers and updates eBPF links from an old enforcer.
// This implements graceful reload by updating existing links with new programs.
func (e *eBPFEnforcer) UpdateFrom(old *eBPFEnforcer) error {
	if old == nil {
		return nil
	}

	// Update Egress Link
	if old.egressLink != nil && e.objs.FilterEgress != nil {
		if err := old.egressLink.Update(e.objs.FilterEgress); err != nil {
			return fmt.Errorf("failed to update egress link: %w", err)
		}
		e.egressLink = old.egressLink
		old.egressLink = nil // Steal ownership
		logging.Info("eBPF egress link updated atomically", nil)
	}

	// Update Ingress Link
	if old.ingressLink != nil && e.objs.FilterIngress != nil {
		if err := old.ingressLink.Update(e.objs.FilterIngress); err != nil {
			return fmt.Errorf("failed to update ingress link: %w", err)
		}
		e.ingressLink = old.ingressLink
		old.ingressLink = nil // Steal ownership
		logging.Info("eBPF ingress link updated atomically", nil)
	}

	return nil
}

// Close cleans up eBPF resources
func (e *eBPFEnforcer) Close() error {
	// Detach programs
	if e.egressLink != nil {
		if err := e.egressLink.Close(); err != nil {
			logging.Warnf("Failed to close egress link: %v", err)
		}
		e.egressLink = nil
	}
	if e.ingressLink != nil {
		if err := e.ingressLink.Close(); err != nil {
			logging.Warnf("Failed to close ingress link: %v", err)
		}
		e.ingressLink = nil
	}

	// Close maps and programs
	if e.objs != nil {
		if e.objs.PolicyMap != nil {
			if err := e.objs.PolicyMap.Close(); err != nil {
				logging.Warnf("Failed to close policy map: %v", err)
			}
		}
		if e.objs.FlowEvents != nil {
			if err := e.objs.FlowEvents.Close(); err != nil {
				logging.Warnf("Failed to close flow_events map: %v", err)
			}
		}
		if e.objs.FilterEgress != nil {
			if err := e.objs.FilterEgress.Close(); err != nil {
				logging.Warnf("Failed to close egress program: %v", err)
			}
		}
		if e.objs.FilterIngress != nil {
			if err := e.objs.FilterIngress.Close(); err != nil {
				logging.Warnf("Failed to close ingress program: %v", err)
			}
		}
	}

	if e.flowEventsPinPath != "" {
		if err := os.Remove(e.flowEventsPinPath); err != nil && !os.IsNotExist(err) {
			logging.Warnf("Failed to remove pinned flow_events map: %v", err)
		}
		e.flowEventsPinPath = ""
	}

	return nil
}

// PinFlowEventsMap pins the flow_events ring buffer map to bpffs so other processes can open it.
func (e *eBPFEnforcer) PinFlowEventsMap(path string) error {
	if e.objs == nil || e.objs.FlowEvents == nil {
		return fmt.Errorf("flow_events map not available")
	}
	if path == "" {
		return fmt.Errorf("pin path is empty")
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("creating pin directory: %w", err)
	}
	_ = os.Remove(path)
	if err := e.objs.FlowEvents.Pin(path); err != nil {
		return fmt.Errorf("pinning flow_events map: %w", err)
	}
	e.flowEventsPinPath = path
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

func ipToUint32(ip net.IP) uint32 {
	if ip == nil {
		return 0
	}
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func ipToUint32Array(ip net.IP) [4]uint32 {
	if ip == nil {
		return [4]uint32{}
	}
	// For IPv6, net.IP is 16 bytes.
	v6 := ip.To16()
	if v6 == nil {
		return [4]uint32{}
	}
	return [4]uint32{
		uint32(v6[0]) | uint32(v6[1])<<8 | uint32(v6[2])<<16 | uint32(v6[3])<<24,
		uint32(v6[4]) | uint32(v6[5])<<8 | uint32(v6[6])<<16 | uint32(v6[7])<<24,
		uint32(v6[8]) | uint32(v6[9])<<8 | uint32(v6[10])<<16 | uint32(v6[11])<<24,
		uint32(v6[12]) | uint32(v6[13])<<8 | uint32(v6[14])<<16 | uint32(v6[15])<<24,
	}
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

// EnforceWithEBPFReal uses actual eBPF enforcement (requires root).
// It implements graceful reload by updating existing links if an enforcer
// is already active.
func EnforceWithEBPFReal(opts EnforcementOptions) error {
	newEnforcer, err := NewEBPFEnforcer()
	if err != nil {
		return fmt.Errorf("failed to create eBPF enforcer: %w", err)
	}

	if err := newEnforcer.LoadPolicies(opts.Policies); err != nil {
		_ = newEnforcer.Close()
		return fmt.Errorf("failed to load policies: %w", err)
	}

	if opts.DryRun {
		logging.Infof("[DRY-RUN] eBPF: Validated %d policies, skipping attachment and pinning", len(opts.Policies))
		_ = newEnforcer.Close()
		return nil
	}

	activeEBPFMu.Lock()
	defer activeEBPFMu.Unlock()

	if activeEBPFEnforcer != nil {
		// Graceful reload: update existing links
		if err := newEnforcer.UpdateFrom(activeEBPFEnforcer); err != nil {
			logging.Warnf("Atomic update failed, falling back to full re-attach: %v", err)
			// Fallback: stop old and start new (non-graceful)
			_ = activeEBPFEnforcer.Close()
			if err := newEnforcer.Attach(opts.CgroupPath); err != nil {
				_ = newEnforcer.Close()
				activeEBPFEnforcer = nil
				return fmt.Errorf("failed to attach eBPF program: %w", err)
			}
		} else {
			// Clean up old maps and programs from the previous enforcer instance.
			// Ownership of links was already transferred in UpdateFrom.
			_ = activeEBPFEnforcer.Close()
		}
	} else {
		// First run: just attach
		if err := newEnforcer.Attach(opts.CgroupPath); err != nil {
			_ = newEnforcer.Close()
			return fmt.Errorf("failed to attach eBPF program: %w", err)
		}
	}

	if err := newEnforcer.PinFlowEventsMap(DefaultFlowEventsPinPath); err != nil {
		logging.Warnf("Failed to pin flow_events map (ztap flows may not work): %v", err)
	}

	logging.Infof("Successfully enforced %d policies via eBPF", len(opts.Policies))
	activeEBPFEnforcer = newEnforcer
	return nil
}

// StopEBPFEnforcement detaches any active eBPF programs loaded by this process.
func StopEBPFEnforcement() error {
	activeEBPFMu.Lock()
	defer activeEBPFMu.Unlock()

	if activeEBPFEnforcer == nil {
		return nil
	}
	err := activeEBPFEnforcer.Close()
	activeEBPFEnforcer = nil
	return err
}
