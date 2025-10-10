package cmd

import (
	"fmt"
	"log"

	"ztap/pkg/enforcer"
	"ztap/pkg/policy"

	"github.com/spf13/cobra"
)

var enforceCmd = &cobra.Command{
	Use:   "enforce -f policy.yaml",
	Short: "Enforce zero-trust network policies",
	Run: func(cmd *cobra.Command, args []string) {
		policyFile, _ := cmd.Flags().GetString("file")
		policies, err := policy.LoadFromFile(policyFile)
		if err != nil {
			log.Fatalf("Failed to load policy: %v", err)
		}

		fmt.Printf("Loaded %d policy(ies) from %s\n", len(policies), policyFile)

		// Detect OS and choose enforcer
		if enforcer.IsLinux() {
			fmt.Println("Enforcing via eBPF (Linux)...")
			enforcer.EnforceWithEBPF(policies)
		} else {
			fmt.Println("Enforcing via pf (macOS)...")
			enforcer.EnforceWithPF(policies)
		}

		fmt.Println("Enforcement complete.")
	},
}

func init() {
	enforceCmd.Flags().StringP("file", "f", "policy.yaml", "Path to policy YAML file")
	rootCmd.AddCommand(enforceCmd)
}
