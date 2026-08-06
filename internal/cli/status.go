package cli

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strings"
	"text/tabwriter"

	"ztap/internal/cloud"
	"ztap/internal/logging"

	"github.com/spf13/cobra"
)

func newStatusCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "status",
		Short: "Show status of on-premises and cloud resources",
		Long:  `Display discovered resources from local system and cloud providers (AWS, Azure, GCP)`,
		Run: func(cmd *cobra.Command, args []string) {
			region, _ := cmd.Flags().GetString("region")
			showAWS, _ := cmd.Flags().GetBool("aws")
			showAzure, _ := cmd.Flags().GetBool("azure")
			showGCP, _ := cmd.Flags().GetBool("gcp")
			verbose, _ := cmd.Flags().GetBool("verbose")

			fmt.Println("ZTAP Status Report")
			fmt.Println("==================")
			fmt.Println()

			// Show local system info
			fmt.Println("Local System:")
			fmt.Printf("  OS: %s\n", runtime.GOOS)
			fmt.Printf("  Arch: %s\n", runtime.GOARCH)
			fmt.Printf("  CPUs: %d\n", runtime.NumCPU())
			hostname, _ := os.Hostname()
			fmt.Printf("  Hostname: %s\n", hostname)
			fmt.Println()

			// Show AWS resources if requested
			if showAWS {
				cfg, err := loadAWSConfig()
				if err != nil {
					logging.Warnf("Failed to load AWS config: %v", err)
				} else if cfg.Region != "" && !cmd.Flags().Changed("region") {
					region = cfg.Region
				}
				if region == "" {
					region = "us-east-1"
				}

				flagProfile, _ := cmd.Flags().GetString("profile")
				profile := firstNonEmpty(strings.TrimSpace(flagProfile), cfg.Profile)

				fmt.Printf("AWS Resources (Region: %s", region)
				if profile != "" {
					fmt.Printf(", Profile: %s", profile)
				}
				fmt.Println("):")

				ctx := context.Background()
				client, err := cloud.NewAWSClientWithOptions(ctx, cloud.AWSOptions{Region: region, Profile: profile})
				if err != nil {
					logging.Warnf("Failed to initialize AWS client: %v", err)
					logging.Warnf("Make sure AWS credentials are configured (aws configure)")
				} else {
					resources, err := client.DiscoverResources(ctx)
					if err != nil {
						logging.Warnf("Failed to discover AWS resources: %v", err)
					} else {
						fmt.Printf("  Discovered: %d EC2 instance(s)\n", len(resources))

						if verbose && len(resources) > 0 {
							fmt.Println("\n  Sample Instances:")
							printCloudResources(resources)
						}
					}
				}
			}

			if showAzure {
				fmt.Println()
				cfg, err := loadAzureConfig()
				if err != nil {
					logging.Warnf("Failed to load Azure config: %v", err)
				}

				flagSubID, _ := cmd.Flags().GetString("azure-subscription-id")
				subscriptionID := firstNonEmpty(strings.TrimSpace(flagSubID), cfg.SubscriptionID)

				flagRG, _ := cmd.Flags().GetString("azure-resource-group")
				resourceGroup := firstNonEmpty(strings.TrimSpace(flagRG), cfg.ResourceGroup)

				flagNSG, _ := cmd.Flags().GetString("azure-nsg")
				nsgName := firstNonEmpty(strings.TrimSpace(flagNSG), cfg.NSG)

				fmt.Printf("Azure Resources:\n")
				if subscriptionID != "" {
					fmt.Printf("  Subscription: %s\n", subscriptionID)
				}
				if resourceGroup != "" {
					fmt.Printf("  Resource Group: %s\n", resourceGroup)
				}

				if subscriptionID == "" {
					logging.Warnf("Azure subscription_id is required to discover resources")
				} else {
					ctx := context.Background()
					client, err := cloud.NewAzureClient(ctx, subscriptionID)
					if err != nil {
						logging.Warnf("Failed to initialize Azure client: %v", err)
					} else {
						resources, err := client.DiscoverResources(ctx, resourceGroup)
						if err != nil {
							logging.Warnf("Failed to discover Azure resources: %v", err)
						} else {
							fmt.Printf("  Discovered: %d NIC(s)\n", len(resources))
							if len(resources) > 0 {
								printCloudResources(resources)
							}

							// Show NSG rule counts if NSG is specified
							if nsgName != "" && resourceGroup != "" {
								total, managed, err := client.CountManagedRules(ctx, resourceGroup, nsgName)
								if err != nil {
									logging.Warnf("Failed to count managed rules: %v", err)
								} else {
									fmt.Printf("\n  NSG: %s\n", nsgName)
									fmt.Printf("    Total Rules: %d\n", total)
									fmt.Printf("    Managed Rules: %d (ztap-*)\n", managed)

									if verbose && managed > 0 {
										rules, err := client.ListManagedRules(ctx, resourceGroup, nsgName)
										if err == nil && len(rules) > 0 {
											fmt.Println("\n    Managed Rule Names:")
											for _, rule := range rules {
												fmt.Printf("      - %s\n", rule)
											}
										}
									}
								}
							}
						}
					}
				}
			}

			if showGCP {
				fmt.Println()
				cfg, err := loadGCPConfig()
				if err != nil {
					logging.Warnf("Failed to load GCP config: %v", err)
				}

				flagProject, _ := cmd.Flags().GetString("project-id")
				flagNetwork, _ := cmd.Flags().GetString("network")

				// Also check legacy flag names
				if flagProject == "" {
					flagProject, _ = cmd.Flags().GetString("gcp-project-id")
				}
				if flagNetwork == "" {
					flagNetwork, _ = cmd.Flags().GetString("gcp-network")
				}

				projectID := firstNonEmpty(strings.TrimSpace(flagProject), cfg.ProjectID)
				network := firstNonEmpty(strings.TrimSpace(flagNetwork), cfg.Network)

				fmt.Printf("GCP Resources:\n")
				if projectID != "" {
					fmt.Printf("  Project: %s\n", projectID)
				}
				if network != "" {
					fmt.Printf("  Network: %s\n", network)
				}

				if projectID == "" || network == "" {
					logging.Warnf("GCP project_id and network are required to discover resources")
				} else {
					ctx := context.Background()
					client, err := cloud.NewGCPClient(ctx, cloud.GCPOptions{})
					if err != nil {
						logging.Warnf("Failed to initialize GCP client: %v", err)
					} else {
						resources, err := client.DiscoverResources(ctx, projectID, network)
						if err != nil {
							logging.Warnf("Failed to discover GCP resources: %v", err)
						} else {
							fmt.Printf("  Discovered: %d GCE instance(s)\n", len(resources))
							if len(resources) > 0 {
								printCloudResources(resources)
							}

							// Show firewall rule counts
							total, managed, err := client.CountManagedFirewalls(ctx, projectID, network)
							if err != nil {
								logging.Warnf("Failed to count managed firewalls: %v", err)
							} else {
								fmt.Printf("\n  Managed Firewall Rules: %d/%d (ztap-*)\n", managed, total)

								if verbose && managed > 0 {
									rules, err := client.ListManagedFirewalls(ctx, projectID, network)
									if err == nil && len(rules) > 0 {
										fmt.Println("\n    Managed Rule Names:")
										for _, rule := range rules {
											fmt.Printf("      - %s\n", rule)
										}
									}
								}
							}
						}
					}
				}
			}

			if !showAWS && !showAzure && !showGCP {
				fmt.Println("Cloud Resources: (use --aws, --azure, or --gcp)")
			}
		},
	}
	c.Flags().BoolP("aws", "a", false, "Discover AWS resources")
	c.Flags().StringP("region", "r", "us-east-1", "AWS region")
	c.Flags().String("profile", "", "AWS CLI profile")
	c.Flags().Bool("azure", false, "Discover Azure resources")
	c.Flags().Bool("gcp", false, "Discover GCP resources")
	c.Flags().String("azure-resource-group", "", "Azure resource group for discovery (optional)")
	c.Flags().String("azure-subscription-id", "", "Azure subscription ID (overrides config)")
	c.Flags().String("azure-nsg", "", "Azure NSG name for rule summary (optional)")
	c.Flags().String("gcp-project-id", "", "GCP project ID for discovery (optional)")
	c.Flags().String("gcp-network", "", "GCP network name for discovery (optional)")
	c.Flags().String("project-id", "", "GCP project ID (alias for --gcp-project-id)")
	c.Flags().String("network", "", "GCP network name (alias for --gcp-network)")
	c.Flags().BoolP("verbose", "v", false, "Show detailed output including managed rule names")
	return c
}

func printCloudResources(resources []cloud.Resource) {
	if len(resources) == 0 {
		fmt.Println("  No resources found")
		return
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "  ID\tName\tType\tPrivate IP\tPublic IP\tLabels")
	_, _ = fmt.Fprintln(w, "  --\t----\t----\t----------\t---------\t------")

	for _, r := range resources {
		var labels strings.Builder
		for k, v := range r.Labels {
			if k == "Name" {
				continue
			}
			_, _ = fmt.Fprintf(&labels, "%s=%s ", k, v)
		}
		_, _ = fmt.Fprintf(w, "  %s\t%s\t%s\t%s\t%s\t%s\n",
			r.ID, r.Name, r.Type, r.PrivateIP, r.PublicIP, labels.String())
	}
	_ = w.Flush()
	fmt.Printf("\nTotal: %d resource(s)\n", len(resources))
}
