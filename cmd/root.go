package cmd

import (
	"fmt"
	"os"

	"ztap/pkg/logging"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "ztap",
	Short: "Zero Trust Access Platform - Microsegmentation for hybrid environments",
	Long: `ZTAP enforces zero-trust network policies across on-premises and cloud workloads.
It uses eBPF on Linux and pf on macOS to enforce fine-grained traffic rules.`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		cfgPath := os.Getenv("ZTAP_CONFIG")
		if cfgPath == "" {
			cfgPath = "config.yaml"
		}
		cfg, err := logging.LoadConfig(cfgPath)
		if err != nil {
			return err
		}

		level, _ := cmd.Flags().GetString("log-level")
		if level != "" {
			cfg.Level = level
		}
		format, _ := cmd.Flags().GetString("log-format")
		if format != "" {
			cfg.Format = format
		}
		file, _ := cmd.Flags().GetString("log-file")
		if file != "" {
			cfg.File = file
		}

		if _, err := logging.Configure(cfg); err != nil {
			return fmt.Errorf("configure logging: %w", err)
		}
		return nil
	},
}

func init() {
	rootCmd.PersistentFlags().String("log-level", "", "Log level (debug, info, warn, error)")
	rootCmd.PersistentFlags().String("log-format", "", "Log format (json, text)")
	rootCmd.PersistentFlags().String("log-file", "", "Log output file")
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
