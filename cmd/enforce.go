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
		resolveLabels, _ := cmd.Flags().GetBool("resolve-labels")
		dryRun, _ := cmd.Flags().GetBool("dry-run")

		policies, err := policy.LoadFromFile(policyFile)
		if err != nil {
			log.Fatalf("Failed to load policy: %v", err)
		}

		// Resolve labels if requested
		if resolveLabels {
			disc, err := getDiscoveryBackend()
			if err != nil {
				log.Fatalf("Failed to load discovery backend for label resolution: %v", err)
			}
			resolver := policy.NewPolicyResolver(disc)
			resolved, err := resolver.ResolvePodSelectorsToIPBlocks(policies)
			if err != nil {
				log.Fatalf("Failed to resolve pod selectors: %v", err)
			}
			policies = resolved
			fmt.Printf("Resolved label selectors to %d concrete rule(s)\n", len(policies))
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
			if err := enforcer.ValidatePoliciesForLinux(policies); err != nil {
				log.Fatalf("Policy is not supported by enforcer yet: %v", err)
			}

			opts := enforcer.EnforcementOptions{
				Policies:   policies,
				DryRun:     dryRun,
				CgroupPath: cgroupPath,
			}

			if err := enforcer.EnforceWithEBPFIfAvailable(opts); err != nil {
				log.Fatalf("Failed to enforce: %v", err)
			}

			if dryRun {
				fmt.Println("Dry-run complete. No changes were applied.")
				return
			}

			fmt.Println("Enforcement active. Press Ctrl+C to stop.")
			sigCh := make(chan os.Signal, 1)
			notifyStopSignals(sigCh)
			<-sigCh
			stopStopSignals(sigCh)
			if err := enforcer.StopLinuxEnforcement(); err != nil {
				log.Printf("Warning: failed to stop enforcement cleanly: %v", err)
			}
			fmt.Println("Enforcement stopped.")
			return
		} else if enforcer.IsWindows() {
			fmt.Println("Enforcing via WFP (Windows)...")
			opts := enforcer.EnforcementOptions{
				Policies: policies,
				DryRun:   dryRun,
			}
			if err := enforcer.EnforceWithWFP(opts); err != nil {
				log.Fatalf("Failed to enforce via WFP: %v", err)
			}

			if dryRun {
				fmt.Println("Dry-run complete. No changes were applied.")
				return
			}

			fmt.Println("Enforcement active. Press Ctrl+C to stop.")
			sigCh := make(chan os.Signal, 1)
			notifyStopSignals(sigCh)
			<-sigCh
			stopStopSignals(sigCh)
			if err := enforcer.StopWFPEnforcement(); err != nil {
				log.Printf("Warning: failed to stop WFP enforcement cleanly: %v", err)
			}
			fmt.Println("Enforcement stopped.")
			return
		} else {
			fmt.Println("Enforcing via pf (macOS)...")
			opts := enforcer.EnforcementOptions{
				Policies: policies,
				DryRun:   dryRun,
			}
			enforcer.EnforceWithPF(opts)
			if dryRun {
				fmt.Println("Dry-run complete. No rules were loaded into pf.")
			}
		}

		fmt.Println("Enforcement complete.")
	},
}

func init() {
	enforceCmd.Flags().StringP("file", "f", "policy.yaml", "Path to policy YAML file")
	enforceCmd.Flags().String("cgroup", "", "Cgroup v2 path for eBPF attachment (Linux only)")
	enforceCmd.Flags().String("bpf-object", "", "Optional path to compiled eBPF object file (overrides embedded bytecode; Linux only)")
	enforceCmd.Flags().Bool("debug-ebpf", false, "Enable debug logging for eBPF object loading (Linux only)")
	enforceCmd.Flags().Bool("resolve-labels", false, "Resolve pod selectors to IP blocks using configured discovery backend")
	enforceCmd.Flags().Bool("dry-run", false, "Simulate enforcement without making system changes")
	rootCmd.AddCommand(enforceCmd)
}
