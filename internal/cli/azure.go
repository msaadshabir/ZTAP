package cli

import (
	"context"
	"fmt"
	"strings"

	"ztap/internal/cloud"
	"ztap/internal/config"
	"ztap/internal/logging"
	"ztap/internal/policy"

	"github.com/spf13/cobra"
)

// azureConfig holds Azure-specific settings from the central config.
type azureConfig struct {
	SubscriptionID string
	ResourceGroup  string
	NSG            string
	RulePrefix     string
	PriorityBase   int32
}

func loadAzureConfig(cfg *config.Config) azureConfig {
	return azureConfig{
		SubscriptionID: string(cfg.Azure.SubscriptionID),
		ResourceGroup:  string(cfg.Azure.ResourceGroup),
		NSG:            string(cfg.Azure.NSG),
		RulePrefix:     string(cfg.Azure.RulePrefix),
		PriorityBase:   cfg.Azure.PriorityBase,
	}
}

func newAzureCmd(app *App) *cobra.Command {
	c := &cobra.Command{
		Use:   "azure",
		Short: "Manage Azure NSG synchronization",
		Long:  "Synchronize ZTAP network policies into Azure Network Security Groups.",
	}
	c.AddCommand(newAzureNSGSyncCmd(app))
	return c
}

func newAzureNSGSyncCmd(app *App) *cobra.Command {
	c := &cobra.Command{
		Use:   "nsg-sync <policy-file>",
		Short: "Sync a policy into an Azure NSG",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			cfg := loadAzureConfig(app.Config())

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
