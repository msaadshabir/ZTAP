package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"ztap/pkg/cloud"
	"ztap/pkg/inventory"
	"ztap/pkg/logging"
	"ztap/pkg/policy"

	"github.com/spf13/cobra"
	yaml "gopkg.in/yaml.v2"
)

// awsConfig holds AWS-specific settings loaded from config.yaml.
type awsConfig struct {
	Region          string
	Profile         string
	SecurityGroupID string
}

type awsConfigFile struct {
	AWS struct {
		Enabled         *bool  `yaml:"enabled"`
		Region          string `yaml:"region"`
		Profile         string `yaml:"profile"`
		SecurityGroupID string `yaml:"security_group_id"`
	} `yaml:"aws"`
}

func loadAWSConfig() (awsConfig, error) {
	path := os.Getenv("ZTAP_CONFIG")
	if path == "" {
		path = "config.yaml"
	}

	cfg := awsConfig{}

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return applyAWSEnv(cfg), nil
		}
		return awsConfig{}, fmt.Errorf("reading config file %s: %w", path, err)
	}

	var fileCfg awsConfigFile
	if err := yaml.Unmarshal(data, &fileCfg); err != nil {
		return awsConfig{}, fmt.Errorf("parsing config file %s: %w", path, err)
	}

	cfg.Region = strings.TrimSpace(fileCfg.AWS.Region)
	cfg.Profile = strings.TrimSpace(fileCfg.AWS.Profile)
	cfg.SecurityGroupID = strings.TrimSpace(fileCfg.AWS.SecurityGroupID)

	return applyAWSEnv(cfg), nil
}

func applyAWSEnv(cfg awsConfig) awsConfig {
	if env := strings.TrimSpace(os.Getenv("ZTAP_AWS_REGION")); env != "" {
		cfg.Region = env
	}
	if env := strings.TrimSpace(os.Getenv("ZTAP_AWS_PROFILE")); env != "" {
		cfg.Profile = env
	}
	if env := strings.TrimSpace(os.Getenv("ZTAP_AWS_SECURITY_GROUP_ID")); env != "" {
		cfg.SecurityGroupID = env
	}
	return cfg
}

var awsCmd = &cobra.Command{
	Use:   "aws",
	Short: "Manage AWS Security Group synchronization",
	Long:  "Synchronize ZTAP network policies into AWS Security Groups.",
}

var awsSGSyncCmd = &cobra.Command{
	Use:   "sg-sync <policy-file>",
	Short: "Sync a policy into an AWS Security Group",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		cfg, err := loadAWSConfig()
		if err != nil {
			logging.Fatalf("Failed to load config: %v", err)
		}

		flagRegion, _ := cmd.Flags().GetString("region")
		flagProfile, _ := cmd.Flags().GetString("profile")
		flagSG, _ := cmd.Flags().GetString("security-group-id")
		dryRun, _ := cmd.Flags().GetBool("dry-run")
		watch, _ := cmd.Flags().GetBool("watch")
		watchInterval, _ := cmd.Flags().GetDuration("watch-interval")
		replaceEgress, _ := cmd.Flags().GetBool("replace-egress")
		force, _ := cmd.Flags().GetBool("force")
		yes, _ := cmd.Flags().GetBool("yes")
		inventoryFile, _ := cmd.Flags().GetString("inventory-file")
		outputFormat, _ := cmd.Flags().GetString("output")
		showResolved, _ := cmd.Flags().GetBool("show-resolved")

		region := firstNonEmpty(strings.TrimSpace(flagRegion), cfg.Region)
		if region == "" {
			region = "us-east-1"
		}
		profile := firstNonEmpty(strings.TrimSpace(flagProfile), cfg.Profile)
		sgID := firstNonEmpty(strings.TrimSpace(flagSG), cfg.SecurityGroupID)

		if sgID == "" {
			logging.Fatalf("security-group-id is required")
		}
		if yes {
			force = true
		}
		if replaceEgress && !force {
			logging.Fatalf("--force is required when using --replace-egress")
		}

		ctx := context.Background()
		client, err := cloud.NewAWSClientWithOptions(ctx, cloud.AWSOptions{Region: region, Profile: profile})
		if err != nil {
			logging.Fatalf("Failed to initialize AWS client: %v", err)
		}

		// Load inventory if provided
		var inventoryResources []cloud.Resource
		if inventoryFile != "" {
			inv, err := inventory.LoadFromFile(inventoryFile)
			if err != nil {
				logging.Fatalf("Failed to load inventory: %v", err)
			}
			for _, r := range inv.Resources {
				inventoryResources = append(inventoryResources, cloud.Resource{
					ID:        r.ID,
					Name:      r.Name,
					Type:      r.Type,
					PrivateIP: r.PrivateIP,
					PublicIP:  r.PublicIP,
					Labels:    r.Labels,
				})
			}
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

			normalized, err := policy.NormalizePolicies(policies)
			if err != nil {
				logging.Fatalf("Failed to normalize policies: %v", err)
			}

			opts := cloud.AWSPolicySyncOptions{DryRun: dryRun, ReplaceEgress: replaceEgress}
			if inventoryFile != "" {
				opts.Inventory = inventoryResources
			}

			total := cloud.AWSSyncResult{}
			for idx, p := range normalized {
				callOpts := opts
				if replaceEgress && idx > 0 {
					callOpts.ReplaceEgress = false
				}
				result, err := client.SyncPolicyWithOptions(ctx, p, sgID, callOpts)
				if err != nil {
					logging.Fatalf("Failed to sync policy %s: %v", p.Metadata.Name, err)
				}
				if result != nil {
					total.Desired += result.Desired
					total.ResolvedTargets += result.ResolvedTargets
					total.ToAuthorize += result.ToAuthorize
					if !replaceEgress || idx == 0 {
						total.ToRevoke += result.ToRevoke
					}
				}
			}

			if strings.ToLower(outputFormat) == "json" {
				output := map[string]interface{}{
					"sync_type":        "aws_security_group",
					"target":           sgID,
					"policies_synced":  len(normalized),
					"resolved_targets": total.ResolvedTargets,
					"dry_run":          dryRun,
					"rules": map[string]int{
						"desired":      total.Desired,
						"to_authorize": total.ToAuthorize,
						"to_revoke":    total.ToRevoke,
						"to_update":    total.ToUpdate,
					},
				}
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				enc.Encode(output)
			} else {
				fmt.Printf("Resolved selector targets: %d\n", total.ResolvedTargets)
				fmt.Printf("Desired rules: %d\n", total.Desired)
				fmt.Printf("Planned changes: create %d, update %d, delete %d\n", total.ToAuthorize, total.ToUpdate, total.ToRevoke)

				if showResolved {
					fmt.Println("\nResolved targets by policy:")
					for _, p := range normalized {
						fmt.Printf("\nPolicy: %s\n", p.Metadata.Name)
						for _, egress := range p.Spec.Egress {
							// Check if selector is not empty (has matchLabels or matchExpressions)
							hasSelector := len(egress.To.PodSelector.MatchLabels) > 0 || len(egress.To.PodSelector.MatchExpressions) > 0
							if hasSelector {
								var resources []cloud.Resource
								if inventoryFile != "" {
									resources = inventoryResources
								} else {
									var err error
									resources, err = client.DiscoverResources(ctx)
									if err != nil {
										logging.Warnf("Failed to discover AWS resources for resolved output: %v", err)
										continue
									}
								}

								matched := make([]cloud.Resource, 0)
								for _, r := range resources {
									if policy.MatchesSelector(r.Labels, egress.To.PodSelector) {
										matched = append(matched, r)
									}
								}

								fmt.Printf("  Selector %v -> %d match(es)\n", egress.To.PodSelector, len(matched))
								for _, r := range matched {
									fmt.Printf("    - %s (%s): %s\n", r.ID, r.Name, r.PrivateIP)
								}
							}
						}
					}
				}
			}

			if dryRun {
				fmt.Printf("Dry-run complete for %d policy object(s) against Security Group %s\n", len(normalized), sgID)
				return
			}
			fmt.Printf("Synchronized %d policy object(s) to Security Group %s\n", len(normalized), sgID)
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
	awsSGSyncCmd.Flags().String("region", "", "AWS region")
	awsSGSyncCmd.Flags().String("profile", "", "AWS CLI profile")
	awsSGSyncCmd.Flags().String("security-group-id", "", "Target AWS Security Group ID")
	awsSGSyncCmd.Flags().Bool("dry-run", false, "Preview security group changes without applying")
	awsSGSyncCmd.Flags().Bool("watch", false, "Re-sync when the policy file changes")
	awsSGSyncCmd.Flags().Duration("watch-interval", 30*time.Second, "Polling interval when --watch is enabled")
	awsSGSyncCmd.Flags().Bool("replace-egress", false, "Clear existing egress rules before applying desired rules")
	awsSGSyncCmd.Flags().Bool("force", false, "Required when using --replace-egress")
	awsSGSyncCmd.Flags().Bool("yes", false, "Alias for --force")
	awsSGSyncCmd.Flags().String("inventory-file", "", "Use pre-exported inventory file instead of live API calls")
	awsSGSyncCmd.Flags().String("output", "text", "Output format (text or json)")
	awsSGSyncCmd.Flags().Bool("show-resolved", false, "Print matched instances/IPs for each selector (text mode)")

	awsCmd.AddCommand(awsSGSyncCmd)
	rootCmd.AddCommand(awsCmd)
}
