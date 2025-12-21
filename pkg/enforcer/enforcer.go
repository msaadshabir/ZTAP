package enforcer

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"ztap/pkg/policy"
)

// IsLinux returns true if running on Linux
func IsLinux() bool {
	return runtime.GOOS == "linux"
}

// EnforceWithEBPF (Linux) - placeholder for real eBPF logic
func EnforceWithEBPF(policies []policy.NetworkPolicy) {
	fmt.Printf("Applying %d eBPF-based policies on Linux\n", len(policies))
	// In production: load eBPF programs, attach to cgroup/socket hooks
	// For demonstration: simulate with logs
	for _, p := range policies {
		fmt.Printf("  Policy '%s': %s\n", p.Metadata.Name, p.Spec.PodSelector.MatchLabels)
		if len(p.Spec.Egress) > 0 {
			fmt.Printf("    Egress rules: %d\n", len(p.Spec.Egress))
			for _, egress := range p.Spec.Egress {
				if egress.To.IPBlock.CIDR != "" {
					fmt.Printf("      -> %s (ports: %v)\n", egress.To.IPBlock.CIDR, egress.Ports)
				}
				if len(egress.To.PodSelector.MatchLabels) > 0 {
					fmt.Printf("      -> pods: %v (ports: %v)\n", egress.To.PodSelector.MatchLabels, egress.Ports)
				}
			}
		}
		if len(p.Spec.Ingress) > 0 {
			fmt.Printf("    Ingress rules: %d\n", len(p.Spec.Ingress))
			for _, ingress := range p.Spec.Ingress {
				if ingress.From.IPBlock.CIDR != "" {
					fmt.Printf("      <- %s (ports: %v)\n", ingress.From.IPBlock.CIDR, ingress.Ports)
				}
				if len(ingress.From.PodSelector.MatchLabels) > 0 {
					fmt.Printf("      <- pods: %v (ports: %v)\n", ingress.From.PodSelector.MatchLabels, ingress.Ports)
				}
			}
		}
	}
}

// EnforceWithPF (macOS) - uses pfctl to manage rules
func EnforceWithPF(policies []policy.NetworkPolicy) {
	fmt.Printf("Applying %d pf-based policies on macOS\n", len(policies))

	if os.Getenv("ZTAP_SKIP_PF") == "1" {
		log.Println("Skipping pf enforcement due to ZTAP_SKIP_PF environment override")
		return
	}

	if os.Geteuid() != 0 {
		log.Println("pf enforcement requires root privileges; skipping rule application")
		return
	}

	// Create anchor file content
	anchorContent := "# ZTAP Managed Rules\n"

	for _, p := range policies {
		anchorContent += fmt.Sprintf("# Policy: %s\n", p.Metadata.Name)

		// Process egress rules (outbound traffic)
		for _, egress := range p.Spec.Egress {
			if len(egress.To.PodSelector.MatchLabels) > 0 {
				// In real world: resolve labels to IPs (via DNS or inventory)
				anchorContent += "# Note: Label-based egress rules require inventory resolution\n"
				anchorContent += "block out quick from any to 192.168.0.0/16\n"
			}
			if egress.To.IPBlock.CIDR != "" {
				for _, port := range egress.Ports {
					anchorContent += fmt.Sprintf("pass out quick proto %s from any to %s port = %d\n",
						port.Protocol, egress.To.IPBlock.CIDR, port.Port)
				}
			}
		}

		// Process ingress rules (inbound traffic)
		for _, ingress := range p.Spec.Ingress {
			if len(ingress.From.PodSelector.MatchLabels) > 0 {
				// In real world: resolve labels to IPs (via DNS or inventory)
				anchorContent += "# Note: Label-based ingress rules require inventory resolution\n"
				anchorContent += "block in quick from 192.168.0.0/16 to any\n"
			}
			if ingress.From.IPBlock.CIDR != "" {
				for _, port := range ingress.Ports {
					anchorContent += fmt.Sprintf("pass in quick proto %s from %s to any port = %d\n",
						port.Protocol, ingress.From.IPBlock.CIDR, port.Port)
				}
			}
		}
	}

	anchorFile := "/etc/pf.anchors/ztap"
	if err := os.MkdirAll(filepath.Dir(anchorFile), 0o755); err != nil {
		log.Printf("Warning: failed to create pf anchors directory: %v", err)
		return
	}
	if err := os.WriteFile(anchorFile, []byte(anchorContent), 0o644); err != nil {
		log.Printf("Warning: failed to write pf anchor file: %v", err)
		return
	}

	// Ensure anchor is loaded in pf.conf
	pfConf := "/etc/pf.conf"
	pfContent := "anchor \"ztap\"\nload anchor \"ztap\" from \"/etc/pf.anchors/ztap\"\n"
	if existing, err := os.ReadFile(pfConf); err == nil {
		if !strings.Contains(string(existing), "anchor \"ztap\"") {
			if f, openErr := os.OpenFile(pfConf, os.O_APPEND|os.O_WRONLY, 0); openErr == nil {
				_, _ = f.WriteString("\n" + pfContent)
				_ = f.Close()
			}
		}
	}

	fmt.Println("Note: Full enforcement requires sudo. See docs for production setup.")
}
