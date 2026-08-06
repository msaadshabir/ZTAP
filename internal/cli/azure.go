package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"ztap/internal/cloud"
	"ztap/internal/logging"
	"ztap/internal/policy"

	"github.com/spf13/cobra"
	yaml "gopkg.in/yaml.v3"
)

// azureConfig holds Azure-specific settings loaded from config.yaml.
type azureConfig struct {
	SubscriptionID string
	ResourceGroup  string
	NSG            string
	RulePrefix     string
	PriorityBase   int32
}

type azureConfigFile struct {
	Azure struct {
		Enabled        *bool  `yaml:"enabled"`
		SubscriptionID string `yaml:"subscription_id"`
		ResourceGroup  string `yaml:"resource_group"`
		NSG            string `yaml:"nsg"`
		RulePrefix     string `yaml:"rule_prefix"`
		PriorityBase   int32  `yaml:"priority_base"`
	} `yaml:"azure"`
}

func loadAzureConfig() (azureConfig, error) {
	path := os.Getenv("ZTAP_CONFIG")
	if path == "" {
		path = "config.yaml"
	}

	cfg := azureConfig{}

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return applyAzureEnv(cfg), nil
		}
		return azureConfig{}, fmt.Errorf("reading config file %s: %w", path, err)
	}

	var fileCfg azureConfigFile
	if err := yaml.Unmarshal(data, &fileCfg); err != nil {
		return azureConfig{}, fmt.Errorf("parsing config file %s: %w", path, err)
	}

	cfg.SubscriptionID = strings.TrimSpace(fileCfg.Azure.SubscriptionID)
	cfg.ResourceGroup = strings.TrimSpace(fileCfg.Azure.ResourceGroup)
	cfg.NSG = strings.TrimSpace(fileCfg.Azure.NSG)
	cfg.RulePrefix = strings.TrimSpace(fileCfg.Azure.RulePrefix)
	cfg.PriorityBase = fileCfg.Azure.PriorityBase

	return applyAzureEnv(cfg), nil
}

func applyAzureEnv(cfg azureConfig) azureConfig {
	if env := strings.TrimSpace(os.Getenv("ZTAP_AZURE_SUBSCRIPTION_ID")); env != "" {
		cfg.SubscriptionID = env
	}
	if env := strings.TrimSpace(os.Getenv("ZTAP_AZURE_RESOURCE_GROUP")); env != "" {
		cfg.ResourceGroup = env
	}
	if env := strings.TrimSpace(os.Getenv("ZTAP_AZURE_NSG")); env != "" {
		cfg.NSG = env
	}
	if env := strings.TrimSpace(os.Getenv("ZTAP_AZURE_RULE_PREFIX")); env != "" {
		cfg.RulePrefix = env
	}
	if env := strings.TrimSpace(os.Getenv("ZTAP_AZURE_PRIORITY_BASE")); env != "" {
		if v, err := parseInt32(env); err == nil {
			cfg.PriorityBase = v
		}
	}
	return cfg
}

func parseInt32(s string) (int32, error) {
	v, err := strconv.ParseInt(s, 10, 32)
	if err != nil {
		return 0, err
	}
	return int32(v), nil
}

func newAzureCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "azure",
		Short: "Manage Azure NSG synchronization",
		Long:  "Synchronize ZTAP network policies into Azure Network Security Groups.",
	}
	c.AddCommand(newAzureNSGSyncCmd())
	return c
}

func newAzureNSGSyncCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "nsg-sync <policy-file>",
		Short: "Sync a policy into an Azure NSG",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			cfg, err := loadAzureConfig()
			if err != nil {
				logging.Fatalf("Failed to load config: %v", err)
			}

			flagSub, _ := cmd.Flags().GetString("subscription-id")
			flagRG, _ := cmd.Flags().GetString("resource-group")
			flagNSG, _ := cmd.Flags().GetString("nsg")
			flagPrefix, _ := cmd.Flags().GetString("rule-prefix")
			flagPriority, _ := cmd.Flags().GetInt32("priority-base")

			subscriptionID := firstNonEmpty(strings.TrimSpace(flagSub), cfg.SubscriptionID)
			resourceGroup := firstNonEmpty(strings.TrimSpace(flagRG), cfg.ResourceGroup)
			nsgName := firstNonEmpty(strings.TrimSpace(flagNSG), cfg.NSG)
			rulePrefix := strings.TrimSpace(flagPrefix)
			priorityBase := flagPriority
			if priorityBase == 0 {
				priorityBase = cfg.PriorityBase
			}

			if subscriptionID == "" || resourceGroup == "" || nsgName == "" {
				logging.Fatalf("subscription-id, resource-group, and nsg are required")
			}

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

			opts := cloud.AzureOptions{}
			if rulePrefix != "" {
				opts.RulePrefix = rulePrefix
			}
			if priorityBase > 0 {
				opts.PriorityBase = priorityBase
			}

			ctx := context.Background()
			client, err := cloud.NewAzureClientWithOptions(ctx, subscriptionID, opts)
			if err != nil {
				logging.Fatalf("Failed to initialize Azure client: %v", err)
			}

			for _, p := range policies {
				if err := client.SyncPolicy(ctx, p, resourceGroup, nsgName); err != nil {
					logging.Fatalf("Failed to sync policy %s: %v", p.Metadata.Name, err)
				}
			}

			fmt.Printf("Synchronized %d policy object(s) to NSG %s/%s\n", len(policies), resourceGroup, nsgName)
		},
	}
	c.Flags().String("subscription-id", "", "Azure subscription ID")
	c.Flags().String("resource-group", "", "Azure resource group containing the NSG")
	c.Flags().String("nsg", "", "Target Azure NSG name")
	c.Flags().String("rule-prefix", "", "Rule name prefix (optional, defaults to ztap-)")
	c.Flags().Int32("priority-base", 0, "Base priority for managed rules (optional)")
	return c
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
