package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"ztap/pkg/enforcer"
	"ztap/pkg/logging"
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
		resolveLabelsInterval, _ := cmd.Flags().GetDuration("resolve-labels-interval")
		dryRun, _ := cmd.Flags().GetBool("dry-run")

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		basePolicies, err := policy.LoadFromFile(policyFile)
		if err != nil {
			logging.Fatalf("Failed to load policy: %v", err)
		}

		needsResolution := policiesNeedTargetResolution(basePolicies)
		if needsResolution {
			resolveLabels = true
		}

		var disc policy.ServiceDiscovery
		if resolveLabels {
			disc, err = getDiscoveryBackend()
			if err != nil {
				logging.Fatalf("Failed to load discovery backend for label resolution: %v", err)
			}
			if starter, ok := disc.(interface{ Start(context.Context) error }); ok {
				if err := starter.Start(ctx); err != nil {
					logging.Fatalf("Failed to start discovery backend: %v", err)
				}
			}
			defer func() {
				if disc == nil {
					return
				}
				if err := disc.Stop(); err != nil {
					logging.Warnf("failed to stop discovery backend: %v", err)
				}
			}()
		}

		policies := basePolicies
		if resolveLabels {
			resolver := policy.NewPolicyResolver(disc)
			enforcer.WarnNoMatchPolicyTargets(disc, enforcer.SelectorRefreshOptions{}, basePolicies)
			resolved, err := resolver.ResolvePodSelectorsToIPBlocks(basePolicies)
			if err != nil {
				logging.Fatalf("Failed to resolve pod selectors: %v", err)
			}
			policies = resolved
			if needsResolution {
				if dryRun {
					fmt.Printf("Resolved label selectors (dry-run; no ongoing re-resolution)\n")
				} else if resolveLabelsInterval <= 0 {
					fmt.Printf("Resolved label selectors (refresh disabled; set --resolve-labels-interval to enable)\n")
				} else {
					fmt.Printf("Resolved label selectors and will keep them updated while enforcement is active\n")
				}
			}
		}
		normalized, err := policy.NormalizePolicies(policies)
		if err != nil {
			logging.Fatalf("Failed to normalize ipBlocks: %v", err)
		}
		policies = normalized

		policyName := filepath.Base(policyFile)
		named := make([]policy.NamedPolicy, 0, len(basePolicies))
		for _, p := range basePolicies {
			if err := p.Validate(); err != nil {
				logging.Fatalf("Invalid policy: %v", err)
			}
			named = append(named, policy.NamedPolicy{PolicyName: policyName, Policy: p})
		}
		for i, np := range named {
			if err := policy.CheckConflicts(named[:i], np); err != nil {
				logging.Fatalf("Policy conflict: %v", err)
			}
		}

		fmt.Printf("Loaded %d policy(ies) from %s\n", len(policies), policyFile)

		if enforcer.IsLinux() {
			if os.Geteuid() != 0 {
				logging.Fatalf("eBPF enforcement requires root privileges")
			}
			if cgroupPath == "" {
				cgroupPath = "/sys/fs/cgroup"
			}
			if _, err := os.Stat(cgroupPath); err != nil {
				logging.Fatalf("Invalid cgroup path %s: %v", cgroupPath, err)
			}
			if bpfObject != "" {
				if _, err := os.Stat(bpfObject); err != nil {
					logging.Fatalf("Invalid --bpf-object %s: %v", bpfObject, err)
				}
			}
			if err := enforcer.ValidatePoliciesForLinux(policies); err != nil {
				logging.Fatalf("Policy is not supported by enforcer yet: %v", err)
			}

			opts := enforcer.EnforcementOptions{
				Policies:      policies,
				DryRun:        dryRun,
				CgroupPath:    cgroupPath,
				BPFObjectPath: bpfObject,
				DebugEBPF:     debugEBPF,
				Context:       ctx,
			}

			if err := enforcer.EnforceWithEBPFIfAvailable(opts); err != nil {
				logging.Fatalf("Failed to enforce: %v", err)
			}

			if dryRun {
				fmt.Println("Dry-run complete. No changes were applied.")
				return
			}

			var wg sync.WaitGroup
			if needsResolution && resolveLabelsInterval > 0 {
				wg.Go(func() {
					enforcer.RunSelectorRefresh(ctx, disc, basePolicies, enforcer.SelectorRefreshOptions{PollInterval: resolveLabelsInterval}, func(next []policy.NetworkPolicy) error {
						if err := enforcer.ValidatePoliciesForLinux(next); err != nil {
							return err
						}
						nextOpts := opts
						nextOpts.Policies = next
						return enforcer.EnforceWithEBPFIfAvailable(nextOpts)
					})
				})
			}

			fmt.Println("Enforcement active. Press Ctrl+C to stop.")
			sigCh := make(chan os.Signal, 1)
			notifyStopSignals(sigCh)
			<-sigCh
			stopStopSignals(sigCh)
			cancel()
			wg.Wait()
			if err := enforcer.StopLinuxEnforcement(); err != nil {
				logging.Warnf("failed to stop enforcement cleanly: %v", err)
			}
			fmt.Println("Enforcement stopped.")
			return
		}

		if enforcer.IsWindows() {
			fmt.Println("Enforcing via WFP (Windows)...")
			opts := enforcer.EnforcementOptions{Policies: policies, DryRun: dryRun, Context: ctx}
			if err := enforcer.EnforceWithWFP(opts); err != nil {
				logging.Fatalf("Failed to enforce via WFP: %v", err)
			}

			if dryRun {
				fmt.Println("Dry-run complete. No changes were applied.")
				return
			}

			var wg sync.WaitGroup
			if needsResolution && resolveLabelsInterval > 0 {
				wg.Go(func() {
					enforcer.RunSelectorRefresh(ctx, disc, basePolicies, enforcer.SelectorRefreshOptions{PollInterval: resolveLabelsInterval}, func(next []policy.NetworkPolicy) error {
						nextOpts := opts
						nextOpts.Policies = next
						return enforcer.EnforceWithWFP(nextOpts)
					})
				})
			}

			fmt.Println("Enforcement active. Press Ctrl+C to stop.")
			sigCh := make(chan os.Signal, 1)
			notifyStopSignals(sigCh)
			<-sigCh
			stopStopSignals(sigCh)
			cancel()
			wg.Wait()
			if err := enforcer.StopWFPEnforcement(); err != nil {
				logging.Warnf("failed to stop WFP enforcement cleanly: %v", err)
			}
			fmt.Println("Enforcement stopped.")
			return
		}

		fmt.Println("Enforcing via pf (macOS)...")
		opts := enforcer.EnforcementOptions{Policies: policies, DryRun: dryRun, Context: ctx}
		if err := enforcer.EnforceWithPF(opts); err != nil {
			logging.Fatalf("Failed to enforce via pf: %v", err)
		}
		if dryRun {
			fmt.Println("Dry-run complete. No rules were loaded into pf.")
		}
		fmt.Println("Enforcement complete.")
	},
}

func init() {
	enforceCmd.Flags().StringP("file", "f", "policy.yaml", "Path to policy YAML file")
	enforceCmd.Flags().String("cgroup", "", "Cgroup v2 path for eBPF attachment (Linux only)")
	enforceCmd.Flags().String("bpf-object", "", "Optional path to compiled eBPF object file (overrides embedded bytecode; Linux only)")
	enforceCmd.Flags().Bool("debug-ebpf", false, "Enable debug logging for eBPF object loading (Linux only)")
	enforceCmd.Flags().Bool("resolve-labels", false, "Resolve pod selectors to IP blocks using configured discovery backend (auto-enabled when policies use podSelector targets)")
	enforceCmd.Flags().Duration("resolve-labels-interval", 5*time.Second, "Re-resolve label selectors at this interval while enforcement is active (0 disables refresh)")
	enforceCmd.Flags().Bool("dry-run", false, "Simulate enforcement without making system changes")
	rootCmd.AddCommand(enforceCmd)
}

func policiesNeedTargetResolution(policies []policy.NetworkPolicy) bool {
	return policy.NeedsTargetResolution(policies)
}
