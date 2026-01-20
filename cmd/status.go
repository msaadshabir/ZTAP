package cmd

import (
	"context"
	"fmt"
	"os"
	"runtime"
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
			fmt.Printf("AWS Resources (Region: %s):\n", region)

			ctx := context.Background()
			client, err := cloud.NewAWSClient(ctx, region)
			if err != nil {
				logging.Warnf("Failed to initialize AWS client: %v", err)
				logging.Warnf("Make sure AWS credentials are configured (aws configure)")
				return
			}

			resources, err := client.DiscoverResources(ctx)
			if err != nil {
				logging.Warnf("Failed to discover AWS resources: %v", err)
				return
			}

			if len(resources) == 0 {
				fmt.Println("  No resources found")
			} else {
				w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
				fmt.Fprintln(w, "  ID\tName\tType\tPrivate IP\tPublic IP\tLabels")
				fmt.Fprintln(w, "  --\t----\t----\t----------\t---------\t------")

				for _, r := range resources {
					labels := ""
					for k, v := range r.Labels {
						if k == "Name" {
							continue
						}
						labels += fmt.Sprintf("%s=%s ", k, v)
					}
					fmt.Fprintf(w, "  %s\t%s\t%s\t%s\t%s\t%s\n",
						r.ID, r.Name, r.Type, r.PrivateIP, r.PublicIP, labels)
				}
				_ = w.Flush()
				fmt.Printf("\nTotal: %d resource(s)\n", len(resources))
			}
		}

		if showAzure {
			fmt.Println("Azure discovery is not implemented yet. Use 'ztap azure nsg-sync' to manage NSGs.")
		}

		if !showAWS && !showAzure {
			fmt.Println("Cloud Resources: (use --aws or --azure)")
		}
	},
}

func init() {
	statusCmd.Flags().BoolP("aws", "a", false, "Discover AWS resources")
	statusCmd.Flags().StringP("region", "r", "us-east-1", "AWS region")
	statusCmd.Flags().Bool("azure", false, "Show Azure integration guidance")
	rootCmd.AddCommand(statusCmd)
}
