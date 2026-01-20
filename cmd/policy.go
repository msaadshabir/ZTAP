package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"text/tabwriter"
	"time"

	"ztap/pkg/cluster"
	"ztap/pkg/logging"
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
				fmt.Println("error: no leader elected, cannot sync policies")
			} else {
				fmt.Printf("error: only the leader can sync policies, current leader: %s\n", leader.ID)
			}
			os.Exit(1)
		}

		policyFile := args[0]

		// Read policy YAML from file
		policyYAML, err := os.ReadFile(policyFile)
		if err != nil {
			logging.Fatalf("failed to read policy file: %v", err)
		}

		policies, err := policy.LoadFromBytes(policyYAML)
		if err != nil {
			logging.Fatalf("failed to parse policy file: %v", err)
		}
		if len(policies) == 0 {
			logging.Fatalf("policy file contains no NetworkPolicy objects")
		}
		for _, p := range policies {
			if err := p.Validate(); err != nil {
				logging.Fatalf("invalid policy: %v", err)
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
			logging.Fatalf("failed to sync policy: %v", err)
		}

		version, _ := policySync.GetPolicyVersion(policyName)
		fmt.Printf("policy %s synced to cluster (version %d)\n", policyName, version)
	},
}

var policyListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all policies in the cluster",
	Long:  `Display all policies currently synchronized across the cluster with their versions.`,
	Run: func(cmd *cobra.Command, args []string) {
		if policySync == nil {
			fmt.Println("policy sync not initialized, cluster must be running")
			os.Exit(1)
		}

		listable, ok := policySync.(interface{ ListPolicies() []*cluster.PolicyState })
		if !ok {
			fmt.Println("error: current policy sync backend doesn't support listing")
			os.Exit(1)
		}

		policies := listable.ListPolicies()

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
		_ = w.Flush()
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

		getter, ok := policySync.(interface {
			GetPolicy(string) (*cluster.PolicyState, error)
		})
		if !ok {
			fmt.Println("error: current policy sync backend doesn't support policy retrieval")
			os.Exit(1)
		}

		policy, err := getter.GetPolicy(policyName)
		if err != nil {
			logging.Fatalf("failed to get policy: %v", err)
		}
		if policy == nil {
			fmt.Printf("policy '%s' not found in cluster\n", policyName)
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

var policyHistoryCmd = &cobra.Command{
	Use:   "history <policy-name>",
	Short: "Show policy revision history",
	Long:  `Display stored policy revisions in descending version order.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if policySync == nil {
			fmt.Println("Policy sync not initialized. Cluster must be running.")
			os.Exit(1)
		}

		store, ok := policySync.(cluster.PolicyRevisionStore)
		if !ok {
			fmt.Println("Error: Current policy sync backend doesn't support revision history")
			os.Exit(1)
		}

		policyName := args[0]
		limit, _ := cmd.Flags().GetInt("limit")

		revisions, err := store.ListPolicyRevisions(policyName, limit)
		if err != nil {
			logging.Fatalf("failed to list policy revisions: %v", err)
		}

		if len(revisions) == 0 {
			fmt.Printf("no revisions found for policy '%s'\n", policyName)
			return
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "Version\tSource\tRollback From\tReason\tAge")
		fmt.Fprintln(w, "-------\t------\t-------------\t------\t---")

		for _, rev := range revisions {
			rollbackFrom := "-"
			if rev.RollbackFromVersion != nil {
				rollbackFrom = fmt.Sprintf("%d", *rev.RollbackFromVersion)
			}
			reason := rev.Reason
			if reason == "" {
				reason = "-"
			}
			age := time.Since(rev.Timestamp).Round(time.Second)
			fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s ago\n",
				rev.Version,
				rev.Source,
				rollbackFrom,
				reason,
				age,
			)
		}

		_ = w.Flush()
	},
}

var policyRollbackCmd = &cobra.Command{
	Use:   "rollback <policy-name>",
	Short: "Rollback a policy to a previous version",
	Long:  `Create a new revision using the YAML from a previous version and broadcast it as the latest policy revision.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if policySync == nil {
			fmt.Println("Policy sync not initialized. Cluster must be running.")
			os.Exit(1)
		}

		store, ok := policySync.(cluster.PolicyRevisionStore)
		if !ok {
			fmt.Println("Error: Current policy sync backend doesn't support rollback")
			os.Exit(1)
		}

		policyName := args[0]
		targetVersion, _ := cmd.Flags().GetInt64("to")
		if targetVersion <= 0 {
			fmt.Println("Error: --to must be provided and greater than zero")
			os.Exit(1)
		}
		reason, _ := cmd.Flags().GetString("reason")

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		rev, err := store.RollbackPolicy(ctx, policyName, targetVersion, reason)
		if err != nil {
			logging.Fatalf("rollback failed: %v", err)
		}

		rolledBackFrom := targetVersion
		fmt.Printf("rollback created policy %s version %d (from version %d)\n", rev.PolicyName, rev.Version, rolledBackFrom)
	},
}

var policyValidateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate a policy file locally",
	Long:  `Performs static validation of a policy file against the ZTAP specification options.`,
	Run:   runPolicyValidate,
}

func runPolicyValidate(cmd *cobra.Command, args []string) {
	policyFile, _ := cmd.Flags().GetString("file")

	// Read policy YAML from file
	policyYAML, err := os.ReadFile(policyFile)
	if err != nil {
		logging.Fatalf("failed to read policy file: %v", err)
	}

	policies, err := policy.LoadFromBytes(policyYAML)
	if err != nil {
		logging.Fatalf("failed to parse policy file: %v", err)
	}

	if len(policies) == 0 {
		logging.Fatalf("policy file contains no NetworkPolicy objects")
	}

	hasError := false
	for _, p := range policies {
		if err := p.Validate(); err != nil {
			fmt.Printf("✗ %v\n", err)
			hasError = true
		} else {
			fmt.Printf("✓ policy '%s' is valid\n", p.Metadata.Name)
		}
	}

	if hasError {
		os.Exit(1)
	}
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
	policyHistoryCmd.Flags().Int("limit", 10, "Number of revisions to display (0 for all)")
	policyRollbackCmd.Flags().Int64("to", 0, "Target version to rollback to")
	policyRollbackCmd.Flags().String("reason", "", "Optional reason for rollback")
	policyValidateCmd.Flags().StringP("file", "f", "", "Path to policy file")
	_ = policyValidateCmd.MarkFlagRequired("file")

	// Add subcommands
	policyCmd.AddCommand(policySyncCmd)
	policyCmd.AddCommand(policyListCmd)
	policyCmd.AddCommand(policyWatchCmd)
	policyCmd.AddCommand(policyShowCmd)
	policyCmd.AddCommand(policyHistoryCmd)
	policyCmd.AddCommand(policyRollbackCmd)
	policyCmd.AddCommand(policyValidateCmd)

	// Register with root command
	rootCmd.AddCommand(policyCmd)
}
