package cli

import (
	"fmt"
	"os"

	"ztap/internal/logging"

	"github.com/spf13/cobra"
)

// NewRootCmd builds the ztap root command with every subcommand registered.
// Command construction is explicit (no init() side effects); main calls this
// once and executes the returned command.
func NewRootCmd(version string) *cobra.Command {
	Version = version

	root := &cobra.Command{
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

	root.PersistentFlags().String("log-level", "", "Log level (debug, info, warn, error)")
	root.PersistentFlags().String("log-format", "", "Log format (json, text)")
	root.PersistentFlags().String("log-file", "", "Log output file")

	root.AddCommand(
		newAgentCmd(),
		newAlertCmd(),
		newApiCmd(),
		newAuditCmd(),
		newAwsCmd(),
		newAzureCmd(),
		newClusterCmd(),
		newComplianceCmd(),
		newDiscoveryCmd(),
		newEnforceCmd(),
		newFlowsCmd(),
		newGcpCmd(),
		newGrpcCmd(),
		newLogsCmd(),
		newMetricsCmd(),
		newPolicyCmd(),
		newStatusCmd(),
		newUserCmd(),
		newVersionCmd(),
	)

	initClusterBackend(root)

	return root
}
