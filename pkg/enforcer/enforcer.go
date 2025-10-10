package enforcer

import (
	"fmt"
	"log"
	"os/exec"
	"runtime"
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
	// For capstone: simulate with logs
	for _, p := range policies {
		fmt.Printf("  • Policy '%s': %s → %v\n",
			p.Metadata.Name,
			p.Spec.PodSelector.MatchLabels,
			p.Spec.Egress)
	}
}

// EnforceWithPF (macOS) - uses pfctl to manage rules
func EnforceWithPF(policies []policy.NetworkPolicy) {
	fmt.Printf("Applying %d pf-based policies on macOS\n", len(policies))

	// Create anchor file content
	anchorContent := "# ZTAP Managed Rules\n"

	for _, p := range policies {
		anchorContent += fmt.Sprintf("# Policy: %s\n", p.Metadata.Name)
		for _, egress := range p.Spec.Egress {
			if len(egress.To.PodSelector.MatchLabels) > 0 {
				// In real world: resolve labels to IPs (via DNS or inventory)
				anchorContent += "# Note: Label-based rules require inventory resolution\n"
				anchorContent += "block out quick from any to 192.168.0.0/16\n"
			}
			if egress.To.IPBlock.CIDR != "" {
				for _, port := range egress.Ports {
					anchorContent += fmt.Sprintf("block out quick proto %s from any to %s port = %d\n",
						port.Protocol, egress.To.IPBlock.CIDR, port.Port)
				}
			}
		}
	}

	// Write to anchor file (requires sudo in real use)
	anchorFile := "/etc/pf.anchors/ztap"
	cmd := exec.Command("sudo", "sh", "-c", fmt.Sprintf("mkdir -p /etc/pf.anchors && echo '%s' > %s", anchorContent, anchorFile))
	err := cmd.Run()
	if err != nil {
		log.Printf("Warning: pf rules require sudo. Demo mode only.")
	}

	// Ensure anchor is loaded in pf.conf
	pfConf := "/etc/pf.conf"
	pfContent := "anchor \"ztap\"\nload anchor \"ztap\" from \"/etc/pf.anchors/ztap\"\n"
	cmd2 := exec.Command("sudo", "sh", "-c", fmt.Sprintf("grep -q 'anchor \"ztap\"' %s || echo '%s' >> %s", pfConf, pfContent, pfConf))
	cmd2.Run() // Ignore errors (file may be read-only)

	fmt.Println("Note: Full enforcement requires sudo. See docs for production setup.")
}
