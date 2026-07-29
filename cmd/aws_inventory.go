package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"ztap/pkg/cloud"
	"ztap/pkg/inventory"
	"ztap/pkg/policy"

	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
)

var awsInventoryCmd = &cobra.Command{
	Use:   "inventory",
	Short: "Manage AWS EC2 inventory for label-based operations",
	Long:  `Export inventory and resolve label selectors to resource IPs using AWS EC2 instance metadata.`,
}

var awsInventoryExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export AWS EC2 inventory to JSON",
	Long:  `Discover EC2 instances and export as structured inventory JSON for offline analysis or label resolution.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		region, _ := cmd.Flags().GetString("region")
		profile, _ := cmd.Flags().GetString("profile")
		outPath, _ := cmd.Flags().GetString("out")

		ctx := context.Background()
		client, err := cloud.NewAWSClientWithOptions(ctx, cloud.AWSOptions{Region: region, Profile: profile})
		if err != nil {
			return fmt.Errorf("failed to create AWS client: %w", err)
		}

		resources, err := client.DiscoverResources(ctx)
		if err != nil {
			return fmt.Errorf("failed to discover resources: %w", err)
		}

		inv := &inventory.Inventory{
			Version:   "1.0",
			Provider:  inventory.ProviderAWS,
			Scope:     region,
			Generated: time.Now(),
			Resources: make([]inventory.Resource, 0, len(resources)),
		}

		for _, r := range resources {
			inv.Resources = append(inv.Resources, inventory.Resource{
				ID:        r.ID,
				Name:      r.Name,
				Type:      r.Type,
				PrivateIP: r.PrivateIP,
				PublicIP:  r.PublicIP,
				Labels:    r.Labels,
				Provider:  inventory.ProviderAWS,
				Scope:     region,
			})
		}

		sort.Slice(inv.Resources, func(i, j int) bool {
			return inv.Resources[i].ID < inv.Resources[j].ID
		})

		if outPath == "" || outPath == "-" {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(inv)
		}

		return inv.SaveToFile(outPath)
	},
}

var awsInventoryResolveCmd = &cobra.Command{
	Use:   "resolve",
	Short: "Resolve IPs for label selectors using AWS inventory",
	Long:  `Resolve cloud resource IPs matching label selectors. Uses live AWS API by default, or a pre-exported inventory file.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		labelsRaw, _ := cmd.Flags().GetStringToString("labels")
		selectorRaw, _ := cmd.Flags().GetString("selector")
		inventoryFile, _ := cmd.Flags().GetString("inventory-file")
		ipModeStr, _ := cmd.Flags().GetString("ip-mode")
		region, _ := cmd.Flags().GetString("region")
		profile, _ := cmd.Flags().GetString("profile")

		var ipMode inventory.IPMode
		switch strings.ToLower(ipModeStr) {
		case "", "private":
			ipMode = inventory.IPModePrivate
		case "public":
			ipMode = inventory.IPModePublic
		case "both":
			ipMode = inventory.IPModeBoth
		default:
			return fmt.Errorf("invalid ip-mode: %s (expected private, public, or both)", ipModeStr)
		}

		var inv *inventory.Inventory
		var err error

		if inventoryFile != "" {
			inv, err = inventory.LoadFromFile(inventoryFile)
			if err != nil {
				return fmt.Errorf("failed to load inventory: %w", err)
			}
		} else {
			ctx := context.Background()
			client, err := cloud.NewAWSClientWithOptions(ctx, cloud.AWSOptions{Region: region, Profile: profile})
			if err != nil {
				return fmt.Errorf("failed to create AWS client: %w", err)
			}

			resources, err := client.DiscoverResources(ctx)
			if err != nil {
				return fmt.Errorf("failed to discover resources: %w", err)
			}

			inv = &inventory.Inventory{
				Version:   "1.0",
				Provider:  inventory.ProviderAWS,
				Scope:     region,
				Generated: time.Now(),
			}
			for _, r := range resources {
				inv.Resources = append(inv.Resources, inventory.Resource{
					ID:        r.ID,
					Name:      r.Name,
					Type:      r.Type,
					PrivateIP: r.PrivateIP,
					PublicIP:  r.PublicIP,
					Labels:    r.Labels,
					Provider:  inventory.ProviderAWS,
					Scope:     region,
				})
			}
		}

		var selector policy.PodSelectorSpec
		if selectorRaw != "" {
			selector, err = parseSelectorString(selectorRaw)
			if err != nil {
				return fmt.Errorf("failed to parse selector: %w", err)
			}
		} else if len(labelsRaw) > 0 {
			selector = policy.PodSelectorSpec{
				MatchLabels: labelsRaw,
			}
		} else {
			return errors.New("either --labels or --selector is required")
		}

		matched := inv.Match(selector)
		if len(matched) == 0 {
			fmt.Println("No resources match the given selector")
			return nil
		}

		ips, _ := inv.ResolveIPs(selector, ipMode)

		fmt.Printf("Matched %d resource(s):\n", len(matched))
		for _, r := range matched {
			fmt.Printf("  %s (%s)\n", r.ID, r.Name)
		}

		fmt.Printf("\nResolved %d IP(s):\n", len(ips))
		for _, ip := range ips {
			fmt.Printf("  %s\n", ip)
		}

		return nil
	},
}

// parseSelectorString parses a Kubernetes-style label selector string
// e.g., "app in (web,api),tier!=dev"
func parseSelectorString(selectorStr string) (policy.PodSelectorSpec, error) {
	sel, err := labels.Parse(selectorStr)
	if err != nil {
		return policy.PodSelectorSpec{}, fmt.Errorf("parsing selector: %w", err)
	}

	// Convert labels.Selector to PodSelectorSpec
	// We need to extract the requirements from the selector
	requirements, selectable := sel.Requirements()
	if !selectable {
		return policy.PodSelectorSpec{}, errors.New("selector is not selectable")
	}

	spec := policy.PodSelectorSpec{
		MatchLabels:      make(map[string]string),
		MatchExpressions: make([]policy.LabelSelectorRequirement, 0, len(requirements)),
	}

	for _, req := range requirements {
		key := req.Key()
		op := req.Operator()
		values := req.Values().List()

		switch op {
		case selection.In, selection.NotIn, selection.Exists, selection.DoesNotExist:
			spec.MatchExpressions = append(spec.MatchExpressions, policy.LabelSelectorRequirement{
				Key:      key,
				Operator: string(op),
				Values:   values,
			})
		case selection.Equals, selection.DoubleEquals:
			// For equals operators, we can use MatchLabels
			if len(values) == 1 {
				spec.MatchLabels[key] = values[0]
			}
		default:
			// Other operators go to matchExpressions
			spec.MatchExpressions = append(spec.MatchExpressions, policy.LabelSelectorRequirement{
				Key:      key,
				Operator: string(op),
				Values:   values,
			})
		}
	}

	return spec, nil
}

func init() {
	awsInventoryCmd.AddCommand(awsInventoryExportCmd)
	awsInventoryCmd.AddCommand(awsInventoryResolveCmd)

	awsCmd.AddCommand(awsInventoryCmd)

	awsInventoryExportCmd.Flags().String("region", "us-east-1", "AWS region")
	awsInventoryExportCmd.Flags().String("profile", "", "AWS CLI profile")
	awsInventoryExportCmd.Flags().String("out", "", "Output file (stdout if empty or '-')")

	awsInventoryResolveCmd.Flags().StringToString("labels", nil, "Label selectors (key=value)")
	awsInventoryResolveCmd.Flags().String("selector", "", "K8s-style selector string (e.g., 'app in (web,api),tier!=dev')")
	awsInventoryResolveCmd.Flags().String("inventory-file", "", "Path to pre-exported inventory JSON")
	awsInventoryResolveCmd.Flags().String("ip-mode", "private", "Which IPs to resolve (private, public, both)")
	awsInventoryResolveCmd.Flags().String("region", "us-east-1", "AWS region (used when --inventory-file not provided)")
	awsInventoryResolveCmd.Flags().String("profile", "", "AWS CLI profile (used when --inventory-file not provided)")
}
