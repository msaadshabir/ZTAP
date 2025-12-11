package cmd

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"text/tabwriter"
	"time"

	"ztap/pkg/cluster"
	"ztap/pkg/policy"

	"github.com/spf13/cobra"
)

// Global policy sync instance (initialized when cluster is initialized)
var policySync cluster.PolicySync

var policyCmd = &cobra.Command{
	Use:   "policy",
	Short: "Manage distributed policy synchronization",
	Long:  `Sync policies across the cluster, view policy versions, and monitor policy changes.`,
}

var policySyncCmd = &cobra.Command{
	Use:   "sync <policy-file>",
	Short: "Sync a policy to the cluster",
	Long: `Broadcast a policy update to all nodes in the cluster. 
Only the leader can initiate policy synchronization.`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if policySync == nil {
			fmt.Println("Policy sync not initialized. Cluster must be running.")
			os.Exit(1)
		}

		if !clusterElection.IsLeader() {
			leader := clusterElection.GetLeader()
			if leader == nil {
				fmt.Println("Error: No leader elected. Cannot sync policies.")
			} else {
				fmt.Printf("Error: Only the leader can sync policies. Current leader: %s\n", leader.ID)
			}
			os.Exit(1)
		}

		policyFile := args[0]

		// Read policy YAML from file
		policyYAML, err := os.ReadFile(policyFile)
		if err != nil {
			log.Fatalf("Failed to read policy file: %v", err)
		}

		policies, err := policy.LoadFromBytes(policyYAML)
		if err != nil {
			log.Fatalf("Failed to parse policy file: %v", err)
		}
		if len(policies) == 0 {
			log.Fatalf("Policy file contains no NetworkPolicy objects")
		}
		for _, p := range policies {
			if err := p.Validate(); err != nil {
				log.Fatalf("Invalid policy: %v", err)
			}
		}

		// Extract policy name from the file (simple: use filename without extension)
		// In production, we'd parse the YAML to get metadata.name
		policyName, err := cmd.Flags().GetString("name")
		if err != nil || policyName == "" {
			if len(policies) == 1 && policies[0].Metadata.Name != "" {
				policyName = policies[0].Metadata.Name
			} else {
				policyName = filepath.Base(policyFile)
			}
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// Sync policy to cluster
		if err := policySync.SyncPolicy(ctx, policyName, policyYAML); err != nil {
			log.Fatalf("Failed to sync policy: %v", err)
		}

		version, _ := policySync.GetPolicyVersion(policyName)
		fmt.Printf("Policy %s synced to cluster (version %d)\n", policyName, version)
	},
}

var policyListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all policies in the cluster",
	Long:  `Display all policies currently synchronized across the cluster with their versions.`,
	Run: func(cmd *cobra.Command, args []string) {
		if policySync == nil {
			fmt.Println("Policy sync not initialized. Cluster must be running.")
			os.Exit(1)
		}

		// Type assertion to access ListPolicies method
		inMemorySync, ok := policySync.(*cluster.InMemoryPolicySync)
		if !ok {
			fmt.Println("Error: Current policy sync backend doesn't support listing")
			os.Exit(1)
		}

		policies := inMemorySync.ListPolicies()

		fmt.Println("Cluster Policies")
		fmt.Println("================")
		fmt.Println()

		if len(policies) == 0 {
			fmt.Println("No policies synchronized in cluster")
			return
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "Name\tVersion\tSource Node\tLast Updated")
		fmt.Fprintln(w, "----\t-------\t-----------\t------------")

		for _, policy := range policies {
			lastUpdated := time.Since(policy.Timestamp).Round(time.Second)
			fmt.Fprintf(w, "%s\t%d\t%s\t%s ago\n",
				policy.Name, policy.Version, policy.Source, lastUpdated)
		}
		w.Flush()
		fmt.Printf("\nTotal: %d polic%s\n", len(policies), pluralize(len(policies), "y", "ies"))
	},
}

var policyWatchCmd = &cobra.Command{
	Use:   "watch",
	Short: "Watch for policy changes in the cluster",
	Long:  `Monitor and display policy updates as they are synchronized across the cluster.`,
	Run: func(cmd *cobra.Command, args []string) {
		if policySync == nil {
			fmt.Println("Policy sync not initialized. Cluster must be running.")
			os.Exit(1)
		}

		fmt.Println("Watching for policy updates... (Ctrl+C to stop)")
		fmt.Println()

		ctx := context.Background()
		updates := policySync.SubscribePolicies(ctx)

		for update := range updates {
			fmt.Printf("[%s] Policy: %s | Version: %d | Source: %s\n",
				update.Timestamp.Format("15:04:05"),
				update.PolicyName,
				update.Version,
				update.Source)
		}
	},
}

var policyShowCmd = &cobra.Command{
	Use:   "show <policy-name>",
	Short: "Show detailed information about a policy",
	Long:  `Display the full YAML content and metadata for a specific policy.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if policySync == nil {
			fmt.Println("Policy sync not initialized. Cluster must be running.")
			os.Exit(1)
		}

		policyName := args[0]

		// Type assertion to access GetPolicy method
		inMemorySync, ok := policySync.(*cluster.InMemoryPolicySync)
		if !ok {
			fmt.Println("Error: Current policy sync backend doesn't support policy retrieval")
			os.Exit(1)
		}

		policy, err := inMemorySync.GetPolicy(policyName)
		if err != nil {
			log.Fatalf("Failed to get policy: %v", err)
		}
		if policy == nil {
			fmt.Printf("Policy '%s' not found in cluster\n", policyName)
			os.Exit(1)
		}

		fmt.Printf("Policy: %s\n", policy.Name)
		fmt.Printf("Version: %d\n", policy.Version)
		fmt.Printf("Source Node: %s\n", policy.Source)
		fmt.Printf("Last Updated: %s\n", policy.Timestamp.Format(time.RFC3339))
		fmt.Println()
		fmt.Println("YAML Content:")
		fmt.Println("-------------")
		fmt.Println(string(policy.YAML))
	},
}

// pluralize is a simple helper for singular/plural forms
func pluralize(count int, singular, plural string) string {
	if count == 1 {
		return singular
	}
	return plural
}

func init() {
	// Add flags
	policySyncCmd.Flags().StringP("name", "n", "", "Policy name (defaults to filename)")

	// Add subcommands
	policyCmd.AddCommand(policySyncCmd)
	policyCmd.AddCommand(policyListCmd)
	policyCmd.AddCommand(policyWatchCmd)
	policyCmd.AddCommand(policyShowCmd)

	// Register with root command
	rootCmd.AddCommand(policyCmd)
}
