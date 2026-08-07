package cli

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"ztap/internal/cloud"
	"ztap/internal/config"
	"ztap/internal/logging"
	"ztap/internal/policy"

	"github.com/spf13/cobra"
)

// gcpConfig holds GCP-specific settings from the central config.
type gcpConfig struct {
	ProjectID    string
	Network      string
	RulePrefix   string
	PriorityBase int32
}

func loadGCPConfig(cfg *config.Config) gcpConfig {
	return gcpConfig{
		ProjectID:    string(cfg.GCP.ProjectID),
		Network:      string(cfg.GCP.Network),
		RulePrefix:   string(cfg.GCP.RulePrefix),
		PriorityBase: cfg.GCP.PriorityBase,
	}
}

func newGcpCmd(app *App) *cobra.Command {
	c := &cobra.Command{
		Use:   "gcp",
		Short: "Manage GCP firewall synchronization",
		Long:  "Synchronize ZTAP network policies into GCP VPC firewall rules.",
	}
	c.AddCommand(newGcpFirewallSyncCmd(app))
	return c
}

func newGcpFirewallSyncCmd(app *App) *cobra.Command {
	c := &cobra.Command{
		Use:   "firewall-sync <policy-file>",
		Short: "Sync a policy into GCP VPC firewall rules",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			cfg := loadGCPConfig(app.Config())

			flagProject, _ := cmd.Flags().GetString("project-id")
			flagNetwork, _ := cmd.Flags().GetString("network")
			flagPrefix, _ := cmd.Flags().GetString("rule-prefix")
			flagPriority, _ := cmd.Flags().GetInt32("priority-base")
			dryRun, _ := cmd.Flags().GetBool("dry-run")
			watch, _ := cmd.Flags().GetBool("watch")
			watchInterval, _ := cmd.Flags().GetDuration("watch-interval")

			projectID := firstNonEmpty(strings.TrimSpace(flagProject), cfg.ProjectID)
			network := firstNonEmpty(strings.TrimSpace(flagNetwork), cfg.Network)
			rulePrefix := strings.TrimSpace(flagPrefix)
			priorityBase := flagPriority
			if priorityBase == 0 {
				priorityBase = cfg.PriorityBase
			}

			if projectID == "" || network == "" {
				logging.Fatalf("project-id and network are required")
			}

			cloudOpts := cloud.GCPOptions{}
			if rulePrefix != "" {
				cloudOpts.RulePrefix = rulePrefix
			}
			if priorityBase > 0 {
				cloudOpts.PriorityBase = priorityBase
			}

			ctx := context.Background()
			client, err := cloud.NewGCPClient(ctx, cloudOpts)
			if err != nil {
				logging.Fatalf("Failed to initialize GCP client: %v", err)
			}

			runOnce := func() {
				policies, err := policy.LoadFromFile(args[0])
				if err != nil {
					logging.Fatalf("Failed to read policy: %v", err)
				}
				if len(policies) == 0 {
					logging.Fatalf("Policy file contains no NetworkPolicy objects")
				}
				for _, p := range policies {
					if err := p.Validate(); err != nil {
						logging.Fatalf("Invalid policy: %v", err)
					}
				}

				for _, p := range policies {
					if err := client.SyncPolicyWithOptions(ctx, p, projectID, network, cloud.GCPPolicySyncOptions{DryRun: dryRun}); err != nil {
						logging.Fatalf("Failed to sync policy %s: %v", p.Metadata.Name, err)
					}
				}

				if dryRun {
					fmt.Printf("Dry-run complete for %d policy object(s) against GCP network %s/%s\n", len(policies), projectID, network)
					return
				}
				fmt.Printf("Synchronized %d policy object(s) to GCP network %s/%s\n", len(policies), projectID, network)
			}

			if !watch {
				runOnce()
				return
			}
			if watchInterval <= 0 {
				watchInterval = 30 * time.Second
			}

			var lastMod time.Time
			ticker := time.NewTicker(watchInterval)
			defer ticker.Stop()

			for {
				info, err := os.Stat(args[0])
				if err != nil {
					logging.Fatalf("stat policy file: %v", err)
				}
				mod := info.ModTime()
				if lastMod.IsZero() || mod.After(lastMod) {
					lastMod = mod
					runOnce()
				}
				<-ticker.C
			}
		},
	}
	c.Flags().String("project-id", "", "GCP project ID")
	c.Flags().String("network", "", "GCP VPC network name")
	c.Flags().String("rule-prefix", "", "Rule name prefix (optional, defaults to ztap-)")
	c.Flags().Int32("priority-base", 0, "Base priority for managed rules (optional)")
	c.Flags().Bool("dry-run", false, "Preview firewall rule changes without applying")
	c.Flags().Bool("watch", false, "Re-sync when the policy file changes")
	c.Flags().Duration("watch-interval", 30*time.Second, "Polling interval when --watch is enabled")
	return c
}
