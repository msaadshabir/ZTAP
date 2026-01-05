//go:build linux
// +build linux

package enforcer

import (
	"bytes"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"sync"
	"ztap/pkg/policy"
)

type iptablesRunner interface {
	Run(name string, arg ...string) error
	CombinedOutput(name string, arg ...string) ([]byte, error)
	RunWithStdin(stdin string, name string, arg ...string) error
}

type realIptablesRunner struct{}

func (r *realIptablesRunner) Run(name string, arg ...string) error {
	return exec.Command(name, arg...).Run()
}

func (r *realIptablesRunner) CombinedOutput(name string, arg ...string) ([]byte, error) {
	return exec.Command(name, arg...).CombinedOutput()
}

func (r *realIptablesRunner) RunWithStdin(stdin string, name string, arg ...string) error {
	cmd := exec.Command(name, arg...)
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

	// Create chains if they don't exist
	_ = e.runner.Run("iptables", "-N", "ZTAP-INGRESS")
	_ = e.runner.Run("iptables", "-N", "ZTAP-EGRESS")

	// Hook into INPUT and OUTPUT if not already hooked
	if !e.isHooked("INPUT", "ZTAP-INGRESS") {
		if err := e.runner.Run("iptables", "-I", "INPUT", "1", "-j", "ZTAP-INGRESS"); err != nil {
			return fmt.Errorf("failed to hook ZTAP-INGRESS into INPUT: %w", err)
		}
	}

	if !e.isHooked("OUTPUT", "ZTAP-EGRESS") {
		if err := e.runner.Run("iptables", "-I", "OUTPUT", "1", "-j", "ZTAP-EGRESS"); err != nil {
			return fmt.Errorf("failed to hook ZTAP-EGRESS into OUTPUT: %w", err)
		}
	}

	return nil
}

// isHooked checks if a chain is hooked into another chain.
func (e *IptablesEnforcer) isHooked(parent, child string) bool {
	out, err := e.runner.CombinedOutput("iptables", "-C", parent, "-j", child)
	return err == nil && len(out) == 0
}

// Cleanup removes hooks and deletes the ZTAP chains.
func (e *IptablesEnforcer) Cleanup() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Flush and remove hooks
	_ = e.runner.Run("iptables", "-D", "INPUT", "-j", "ZTAP-INGRESS")
	_ = e.runner.Run("iptables", "-D", "OUTPUT", "-j", "ZTAP-EGRESS")

	_ = e.runner.Run("iptables", "-F", "ZTAP-INGRESS")
	_ = e.runner.Run("iptables", "-F", "ZTAP-EGRESS")

	_ = e.runner.Run("iptables", "-X", "ZTAP-INGRESS")
	_ = e.runner.Run("iptables", "-X", "ZTAP-EGRESS")

	return nil
}

// LoadPolicies translates NetworkPolicies to iptables rules and applies them atomically.
func (e *IptablesEnforcer) LoadPolicies(policies []policy.NetworkPolicy) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	restoreInput := e.generateRestoreInput(policies)

	if err := e.runner.RunWithStdin(restoreInput, "iptables-restore", "--noflush"); err != nil {
		return fmt.Errorf("iptables-restore failed: %w", err)
	}

	log.Printf("Applied %d policies via iptables", len(policies))
	return nil
}

func (e *IptablesEnforcer) generateRestoreInput(policies []policy.NetworkPolicy) string {
	var builder strings.Builder
	builder.WriteString("*filter\n")
	builder.WriteString(":ZTAP-INGRESS - [0:0]\n")
	builder.WriteString(":ZTAP-EGRESS - [0:0]\n")

	// Helper to add rules to chains
	// Always allow established connections
	builder.WriteString("-A ZTAP-INGRESS -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n")
	builder.WriteString("-A ZTAP-INGRESS -i lo -j ACCEPT\n")
	builder.WriteString("-A ZTAP-EGRESS -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n")
	builder.WriteString("-A ZTAP-EGRESS -o lo -j ACCEPT\n")

	for _, p := range policies {
		// Ingress rules
		for _, ingress := range p.Spec.Ingress {
			cidr := ingress.From.IPBlock.CIDR
			if cidr == "" {
				continue
			}

			if len(ingress.Ports) == 0 {
				builder.WriteString(fmt.Sprintf("-A ZTAP-INGRESS -s %s -j ACCEPT\n", cidr))
			} else {
				for _, port := range ingress.Ports {
					proto := strings.ToLower(port.Protocol)
					if proto == "" {
						proto = "tcp"
					}
					builder.WriteString(fmt.Sprintf("-A ZTAP-INGRESS -s %s -p %s --dport %d -j ACCEPT\n", cidr, proto, port.Port))
				}
			}
		}

		// Egress rules
		for _, egress := range p.Spec.Egress {
			cidr := egress.To.IPBlock.CIDR
			if cidr == "" {
				continue
			}

			if len(egress.Ports) == 0 {
				builder.WriteString(fmt.Sprintf("-A ZTAP-EGRESS -d %s -j ACCEPT\n", cidr))
			} else {
				for _, port := range egress.Ports {
					proto := strings.ToLower(port.Protocol)
					if proto == "" {
						proto = "tcp"
					}
					builder.WriteString(fmt.Sprintf("-A ZTAP-EGRESS -d %s -p %s --dport %d -j ACCEPT\n", cidr, proto, port.Port))
				}
			}
		}
	}

	// Default drop if we have policies
	if len(policies) > 0 {
		builder.WriteString("-A ZTAP-INGRESS -j DROP\n")
		builder.WriteString("-A ZTAP-EGRESS -j DROP\n")
	}

	builder.WriteString("COMMIT\n")
	return builder.String()
}
