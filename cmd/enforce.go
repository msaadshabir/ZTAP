package cmd

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"ztap/pkg/enforcer"
	"ztap/pkg/policy"

	"github.com/spf13/cobra"
)

var enforceCmd = &cobra.Command{
	Use:   "enforce -f policy.yaml",
	Short: "Enforce zero-trust network policies",
	Run: func(cmd *cobra.Command, args []string) {
		policyFile, _ := cmd.Flags().GetString("file")
		cgroupPath, _ := cmd.Flags().GetString("cgroup")
		bpfObject, _ := cmd.Flags().GetString("bpf-object")
		debugEBPF, _ := cmd.Flags().GetBool("debug-ebpf")
		policies, err := policy.LoadFromFile(policyFile)
		if err != nil {
			log.Fatalf("Failed to load policy: %v", err)
		}

		policyName := filepath.Base(policyFile)
		named := make([]policy.NamedPolicy, 0, len(policies))
		for _, p := range policies {
			if err := p.Validate(); err != nil {
				log.Fatalf("Invalid policy: %v", err)
			}
			named = append(named, policy.NamedPolicy{PolicyName: policyName, Policy: p})
		}
		for i, np := range named {
			if err := policy.CheckConflicts(named[:i], np); err != nil {
				log.Fatalf("Policy conflict: %v", err)
			}
		}

		fmt.Printf("Loaded %d policy(ies) from %s\n", len(policies), policyFile)

		// Detect OS and choose enforcer
		if enforcer.IsLinux() {
			if os.Geteuid() != 0 {
				log.Fatalf("eBPF enforcement requires root privileges")
			}
			if cgroupPath == "" {
				cgroupPath = "/sys/fs/cgroup"
			}
			if _, err := os.Stat(cgroupPath); err != nil {
				log.Fatalf("Invalid cgroup path %s: %v", cgroupPath, err)
			}
			if bpfObject != "" {
				if _, err := os.Stat(bpfObject); err != nil {
					log.Fatalf("Invalid --bpf-object %s: %v", bpfObject, err)
				}
				_ = os.Setenv("ZTAP_BPF_OBJECT", bpfObject)
			}
			if debugEBPF {
				_ = os.Setenv("ZTAP_DEBUG_EBPF", "1")
			}
			if err := enforcer.ValidatePoliciesForEBPF(policies); err != nil {
				log.Fatalf("Policy is not supported by eBPF enforcer yet: %v", err)
			}

			fmt.Println("Enforcing via eBPF (Linux)...")
			if err := enforcer.EnforceWithEBPFIfAvailable(policies, cgroupPath); err != nil {
				log.Fatalf("Failed to enforce via eBPF: %v", err)
			}

			fmt.Println("Enforcement active. Press Ctrl+C to stop.")
			sigCh := make(chan os.Signal, 1)
			notifyStopSignals(sigCh)
			<-sigCh
			stopStopSignals(sigCh)
			if err := enforcer.StopEBPFEnforcement(); err != nil {
				log.Printf("Warning: failed to stop eBPF enforcement cleanly: %v", err)
			}
			fmt.Println("Enforcement stopped.")
			return
		} else {
			fmt.Println("Enforcing via pf (macOS)...")
			enforcer.EnforceWithPF(policies)
		}

		fmt.Println("Enforcement complete.")
	},
}

func init() {
	enforceCmd.Flags().StringP("file", "f", "policy.yaml", "Path to policy YAML file")
	enforceCmd.Flags().String("cgroup", "", "Cgroup v2 path for eBPF attachment (Linux only)")
	enforceCmd.Flags().String("bpf-object", "", "Path to compiled eBPF object file (overrides search paths; Linux only)")
	enforceCmd.Flags().Bool("debug-ebpf", false, "Enable debug logging for eBPF object loading (Linux only)")
	rootCmd.AddCommand(enforceCmd)
}
