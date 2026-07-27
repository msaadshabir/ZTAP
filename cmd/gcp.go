package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"ztap/pkg/cloud"
	"ztap/pkg/logging"
	"ztap/pkg/policy"

	"github.com/spf13/cobra"
	yaml "gopkg.in/yaml.v3"
)

// gcpConfig holds GCP-specific settings loaded from config.yaml.
type gcpConfig struct {
	ProjectID    string
	Network      string
	RulePrefix   string
	PriorityBase int32
}

type gcpConfigFile struct {
	GCP struct {
		Enabled      *bool  `yaml:"enabled"`
		ProjectID    string `yaml:"project_id"`
		Network      string `yaml:"network"`
		RulePrefix   string `yaml:"rule_prefix"`
		PriorityBase int32  `yaml:"priority_base"`
	} `yaml:"gcp"`
}

func loadGCPConfig() (gcpConfig, error) {
	path := os.Getenv("ZTAP_CONFIG")
	if path == "" {
		path = "config.yaml"
	}

	cfg := gcpConfig{}

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return applyGCPEnv(cfg), nil
		}
		return gcpConfig{}, fmt.Errorf("reading config file %s: %w", path, err)
	}

	var fileCfg gcpConfigFile
	if err := yaml.Unmarshal(data, &fileCfg); err != nil {
		return gcpConfig{}, fmt.Errorf("parsing config file %s: %w", path, err)
	}

	cfg.ProjectID = strings.TrimSpace(fileCfg.GCP.ProjectID)
	cfg.Network = strings.TrimSpace(fileCfg.GCP.Network)
	cfg.RulePrefix = strings.TrimSpace(fileCfg.GCP.RulePrefix)
	cfg.PriorityBase = fileCfg.GCP.PriorityBase

	return applyGCPEnv(cfg), nil
}

func applyGCPEnv(cfg gcpConfig) gcpConfig {
	if env := strings.TrimSpace(os.Getenv("ZTAP_GCP_PROJECT_ID")); env != "" {
		cfg.ProjectID = env
	}
	if env := strings.TrimSpace(os.Getenv("ZTAP_GCP_NETWORK")); env != "" {
		cfg.Network = env
	}
	if env := strings.TrimSpace(os.Getenv("ZTAP_GCP_RULE_PREFIX")); env != "" {
		cfg.RulePrefix = env
	}
	if env := strings.TrimSpace(os.Getenv("ZTAP_GCP_PRIORITY_BASE")); env != "" {
		if v, err := parseInt32(env); err == nil {
			cfg.PriorityBase = v
		}
	}
	return cfg
}

var gcpCmd = &cobra.Command{
	Use:   "gcp",
	Short: "Manage GCP firewall synchronization",
	Long:  "Synchronize ZTAP network policies into GCP VPC firewall rules.",
}

var gcpFirewallSyncCmd = &cobra.Command{
	Use:   "firewall-sync <policy-file>",
	Short: "Sync a policy into GCP VPC firewall rules",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		cfg, err := loadGCPConfig()
		if err != nil {
			logging.Fatalf("Failed to load config: %v", err)
		}

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

func init() {
	gcpFirewallSyncCmd.Flags().String("project-id", "", "GCP project ID")
	gcpFirewallSyncCmd.Flags().String("network", "", "GCP VPC network name")
	gcpFirewallSyncCmd.Flags().String("rule-prefix", "", "Rule name prefix (optional, defaults to ztap-)")
	gcpFirewallSyncCmd.Flags().Int32("priority-base", 0, "Base priority for managed rules (optional)")
	gcpFirewallSyncCmd.Flags().Bool("dry-run", false, "Preview firewall rule changes without applying")
	gcpFirewallSyncCmd.Flags().Bool("watch", false, "Re-sync when the policy file changes")
	gcpFirewallSyncCmd.Flags().Duration("watch-interval", 30*time.Second, "Polling interval when --watch is enabled")

	gcpCmd.AddCommand(gcpFirewallSyncCmd)
	rootCmd.AddCommand(gcpCmd)
}
