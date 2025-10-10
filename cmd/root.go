package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "ztap",
	Short: "Zero Trust Access Platform - Microsegmentation for hybrid environments",
	Long: `ZTAP enforces zero-trust network policies across on-premises and cloud workloads.
It uses eBPF on Linux and pf on macOS to enforce fine-grained traffic rules.`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
