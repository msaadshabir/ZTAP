package cmd

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strings"
	"text/tabwriter"

	"ztap/pkg/cloud"
	"ztap/pkg/logging"

	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show status of on-premises and cloud resources",
	Long:  `Display discovered resources from local system and cloud providers (AWS, Azure, etc.)`,
	Run: func(cmd *cobra.Command, args []string) {
		region, _ := cmd.Flags().GetString("region")
		showAWS, _ := cmd.Flags().GetBool("aws")
		showAzure, _ := cmd.Flags().GetBool("azure")
		showGCP, _ := cmd.Flags().GetBool("gcp")

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
			} else {
				if cfg.Region != "" && !cmd.Flags().Changed("region") {
					region = cfg.Region
				}
			}
			if region == "" {
				region = "us-east-1"
			}

			fmt.Printf("AWS Resources (Region: %s):\n", region)

			ctx := context.Background()
			profile := ""
			if cfg.Profile != "" {
				profile = cfg.Profile
			}
			client, err := cloud.NewAWSClientWithOptions(ctx, cloud.AWSOptions{Region: region, Profile: profile})
			if err != nil {
				logging.Warnf("Failed to initialize AWS client: %v", err)
				logging.Warnf("Make sure AWS credentials are configured (aws configure)")
			} else {
				resources, err := client.DiscoverResources(ctx)
				if err != nil {
					logging.Warnf("Failed to discover AWS resources: %v", err)
				} else {
					printCloudResources(resources)
				}
			}
		}

		if showAzure {
			fmt.Println()
			fmt.Println("Azure Resources:")
			cfg, err := loadAzureConfig()
			if err != nil {
				logging.Warnf("Failed to load Azure config: %v", err)
			} else if cfg.SubscriptionID == "" {
				logging.Warnf("Azure subscription_id is required to discover resources")
			} else {
				flagRG, _ := cmd.Flags().GetString("azure-resource-group")
				resourceGroup := firstNonEmpty(strings.TrimSpace(flagRG), cfg.ResourceGroup)
				ctx := context.Background()
				client, err := cloud.NewAzureClient(ctx, cfg.SubscriptionID)
				if err != nil {
					logging.Warnf("Failed to initialize Azure client: %v", err)
				} else {
					resources, err := client.DiscoverResources(ctx, resourceGroup)
					if err != nil {
						logging.Warnf("Failed to discover Azure resources: %v", err)
					} else {
						printCloudResources(resources)
					}
				}
			}
		}

		if showGCP {
			fmt.Println()
			fmt.Println("GCP Resources:")
			cfg, err := loadGCPConfig()
			if err != nil {
				logging.Warnf("Failed to load GCP config: %v", err)
			} else {
				flagProject, _ := cmd.Flags().GetString("gcp-project-id")
				flagNetwork, _ := cmd.Flags().GetString("gcp-network")
				projectID := firstNonEmpty(strings.TrimSpace(flagProject), cfg.ProjectID)
				network := firstNonEmpty(strings.TrimSpace(flagNetwork), cfg.Network)
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
							printCloudResources(resources)
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

func init() {
	statusCmd.Flags().BoolP("aws", "a", false, "Discover AWS resources")
	statusCmd.Flags().StringP("region", "r", "us-east-1", "AWS region")
	statusCmd.Flags().Bool("azure", false, "Discover Azure resources")
	statusCmd.Flags().Bool("gcp", false, "Discover GCP resources")
	statusCmd.Flags().String("azure-resource-group", "", "Azure resource group for discovery (optional)")
	statusCmd.Flags().String("gcp-project-id", "", "GCP project ID for discovery (optional)")
	statusCmd.Flags().String("gcp-network", "", "GCP network name for discovery (optional)")
	rootCmd.AddCommand(statusCmd)
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
		labels := ""
		for k, v := range r.Labels {
			if k == "Name" {
				continue
			}
			labels += fmt.Sprintf("%s=%s ", k, v)
		}
		_, _ = fmt.Fprintf(w, "  %s\t%s\t%s\t%s\t%s\t%s\n",
			r.ID, r.Name, r.Type, r.PrivateIP, r.PublicIP, labels)
	}
	_ = w.Flush()
	fmt.Printf("\nTotal: %d resource(s)\n", len(resources))
}
