//go:build linux
// +build linux

package enforcer

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
	"sync"

	"ztap/pkg/logging"
	"ztap/pkg/policy"
)

type iptablesRunner interface {
	Run(name string, arg ...string) error
	CombinedOutput(name string, arg ...string) ([]byte, error)
	RunWithStdin(stdin string, name string, arg ...string) error
}

type realIptablesRunner struct{}

func (r *realIptablesRunner) Run(name string, arg ...string) error {
	return exec.Command(name, arg...).Run() // #nosec G204
}

func (r *realIptablesRunner) CombinedOutput(name string, arg ...string) ([]byte, error) {
	return exec.Command(name, arg...).CombinedOutput() // #nosec G204
}

func (r *realIptablesRunner) RunWithStdin(stdin string, name string, arg ...string) error {
	cmd := exec.Command(name, arg...) // #nosec G204
	cmd.Stdin = strings.NewReader(stdin)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%v: %s", err, stderr.String())
	}
	return nil
}

// IptablesEnforcer implements network policy enforcement using iptables.
type IptablesEnforcer struct {
	mu     sync.Mutex
	runner iptablesRunner
	dryRun bool
}

// NewIptablesEnforcer creates a new iptables enforcer.
func NewIptablesEnforcer() *IptablesEnforcer {
	return &IptablesEnforcer{
		runner: &realIptablesRunner{},
	}
}

// Init sets up the ZTAP chains and hooks them into INPUT and OUTPUT.
func (e *IptablesEnforcer) Init() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.dryRun {
		logging.Infof("[DRY-RUN] iptables: would create chains ZTAP-INGRESS and ZTAP-EGRESS and hook them into INPUT/OUTPUT")
		return nil
	}

	for _, bin := range []string{"iptables", "ip6tables"} {
		// Create chains if they don't exist
		_ = e.runner.Run(bin, "-N", "ZTAP-INGRESS")
		_ = e.runner.Run(bin, "-N", "ZTAP-EGRESS")

		// Hook into INPUT and OUTPUT if not already hooked
		if !e.isHooked(bin, "INPUT", "ZTAP-INGRESS") {
			if err := e.runner.Run(bin, "-I", "INPUT", "1", "-j", "ZTAP-INGRESS"); err != nil {
				logging.Warnf("failed to hook %s ZTAP-INGRESS into INPUT: %v", bin, err)
			}
		}

		if !e.isHooked(bin, "OUTPUT", "ZTAP-EGRESS") {
			if err := e.runner.Run(bin, "-I", "OUTPUT", "1", "-j", "ZTAP-EGRESS"); err != nil {
				logging.Warnf("failed to hook %s ZTAP-EGRESS into OUTPUT: %v", bin, err)
			}
		}
	}

	return nil
}

// isHooked checks if a chain is hooked into another chain.
func (e *IptablesEnforcer) isHooked(bin, parent, child string) bool {
	out, err := e.runner.CombinedOutput(bin, "-C", parent, "-j", child)
	return err == nil && len(out) == 0
}

// Cleanup removes hooks and deletes the ZTAP chains.
func (e *IptablesEnforcer) Cleanup() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.dryRun {
		logging.Infof("[DRY-RUN] iptables: would cleanup ZTAP chains and hooks")
		return nil
	}

	for _, bin := range []string{"iptables", "ip6tables"} {
		// Flush and remove hooks
		_ = e.runner.Run(bin, "-D", "INPUT", "-j", "ZTAP-INGRESS")
		_ = e.runner.Run(bin, "-D", "OUTPUT", "-j", "ZTAP-EGRESS")

		_ = e.runner.Run(bin, "-F", "ZTAP-INGRESS")
		_ = e.runner.Run(bin, "-F", "ZTAP-EGRESS")

		_ = e.runner.Run(bin, "-X", "ZTAP-INGRESS")
		_ = e.runner.Run(bin, "-X", "ZTAP-EGRESS")
	}

	return nil
}

// LoadPolicies translates NetworkPolicies to iptables rules and applies them atomically.
func (e *IptablesEnforcer) LoadPolicies(policies []policy.NetworkPolicy) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	v4Rules, v6Rules, err := e.generateRestoreInput(policies)
	if err != nil {
		return err
	}

	if e.dryRun {
		logging.Infof("[DRY-RUN] iptables: would apply v4 and v6 rules via iptables-restore")
		return nil
	}

	if err := e.runner.RunWithStdin(v4Rules, "iptables-restore", "--noflush"); err != nil {
		return fmt.Errorf("iptables-restore failed: %w", err)
	}

	// Only apply v6 rules if ip6tables is available/enabled
	if v6Rules != "" {
		if err := e.runner.RunWithStdin(v6Rules, "ip6tables-restore", "--noflush"); err != nil {
			logging.Warnf("ip6tables-restore failed: %v", err)
		}
	}

	logging.Infof("Applied %d policies via iptables/ip6tables", len(policies))
	return nil
}

func (e *IptablesEnforcer) generateRestoreInput(policies []policy.NetworkPolicy) (string, string, error) {
	var v4, v6 strings.Builder

	setupChains := func(b *strings.Builder) {
		b.WriteString("*filter\n")
		b.WriteString(":ZTAP-INGRESS - [0:0]\n")
		b.WriteString(":ZTAP-EGRESS - [0:0]\n")
		b.WriteString("-A ZTAP-INGRESS -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n")
		b.WriteString("-A ZTAP-INGRESS -i lo -j ACCEPT\n")
		b.WriteString("-A ZTAP-EGRESS -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n")
		b.WriteString("-A ZTAP-EGRESS -o lo -j ACCEPT\n")
	}

	setupChains(&v4)
	setupChains(&v6)

	for _, p := range policies {
		// Ingress rules
		for _, ingress := range p.Spec.Ingress {
			cidr := ingress.From.IPBlock.CIDR
			if cidr == "" {
				continue
			}

			target := &v4
			if strings.Contains(cidr, ":") {
				target = &v6
			}

			if len(ingress.Ports) == 0 {
				_, _ = fmt.Fprintf(target, "-A ZTAP-INGRESS -s %s -j ACCEPT\n", cidr)
			} else {
				for _, port := range ingress.Ports {
					if port.PortName != "" {
						return "", "", fmt.Errorf("policy %s: named ports are not supported by iptables translator", p.Metadata.Name)
					}
					proto := strings.ToLower(port.Protocol)
					if proto == "" {
						proto = "tcp"
					}
					if proto == "icmp" {
						if target == &v6 {
							proto = "ipv6-icmp"
						}
						_, _ = fmt.Fprintf(target, "-A ZTAP-INGRESS -s %s -p %s -j ACCEPT\n", cidr, proto)
						continue
					}
					start := port.Port
					end := port.Port
					if port.EndPort != nil {
						end = *port.EndPort
					}
					if start <= 0 || end <= 0 {
						return "", "", fmt.Errorf("policy %s: invalid port in ingress rule", p.Metadata.Name)
					}
					if end != start {
						_, _ = fmt.Fprintf(target, "-A ZTAP-INGRESS -s %s -p %s --dport %d:%d -j ACCEPT\n", cidr, proto, start, end)
						continue
					}
					_, _ = fmt.Fprintf(target, "-A ZTAP-INGRESS -s %s -p %s --dport %d -j ACCEPT\n", cidr, proto, start)
				}
			}
		}

		// Egress rules
		for _, egress := range p.Spec.Egress {
			cidr := egress.To.IPBlock.CIDR
			if cidr == "" {
				continue
			}

			target := &v4
			if strings.Contains(cidr, ":") {
				target = &v6
			}

			if len(egress.Ports) == 0 {
				_, _ = fmt.Fprintf(target, "-A ZTAP-EGRESS -d %s -j ACCEPT\n", cidr)
			} else {
				for _, port := range egress.Ports {
					if port.PortName != "" {
						return "", "", fmt.Errorf("policy %s: named ports are not supported by iptables translator", p.Metadata.Name)
					}
					proto := strings.ToLower(port.Protocol)
					if proto == "" {
						proto = "tcp"
					}
					if proto == "icmp" {
						if target == &v6 {
							proto = "ipv6-icmp"
						}
						_, _ = fmt.Fprintf(target, "-A ZTAP-EGRESS -d %s -p %s -j ACCEPT\n", cidr, proto)
						continue
					}
					start := port.Port
					end := port.Port
					if port.EndPort != nil {
						end = *port.EndPort
					}
					if start <= 0 || end <= 0 {
						return "", "", fmt.Errorf("policy %s: invalid port in egress rule", p.Metadata.Name)
					}
					if end != start {
						_, _ = fmt.Fprintf(target, "-A ZTAP-EGRESS -d %s -p %s --dport %d:%d -j ACCEPT\n", cidr, proto, start, end)
						continue
					}
					_, _ = fmt.Fprintf(target, "-A ZTAP-EGRESS -d %s -p %s --dport %d -j ACCEPT\n", cidr, proto, start)
				}
			}
		}
	}

	// Default drop if we have policies
	if len(policies) > 0 {
		v4.WriteString("-A ZTAP-INGRESS -j DROP\n")
		v4.WriteString("-A ZTAP-EGRESS -j DROP\n")
		v6.WriteString("-A ZTAP-INGRESS -j DROP\n")
		v6.WriteString("-A ZTAP-EGRESS -j DROP\n")
	}

	v4.WriteString("COMMIT\n")
	v6.WriteString("COMMIT\n")
	return v4.String(), v6.String(), nil
}
