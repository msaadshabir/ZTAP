package cli

import (
	"fmt"

	"ztap/internal/config"
	"ztap/internal/logging"

	"github.com/spf13/cobra"
)

// App carries per-invocation state (currently the single parsed config).
// NewRootCmd owns one App; PersistentPreRunE parses the config once and the
// subcommands read it via app.Config(). Precedence is flag > env > file > default.
type App struct {
	cfg *config.Config
}

// Config returns the parsed configuration. When commands are invoked directly
// (e.g. in unit tests) without going through the root PersistentPreRunE, the
// config is loaded on first use.
func (a *App) Config() *config.Config {
	if a.cfg == nil {
		cfg, err := config.Load("")
		if err != nil {
			logging.Fatalf("Failed to load config: %v", err)
		}
		a.cfg = cfg
	}
	return a.cfg
}

// NewRootCmd builds the ztap root command with every subcommand registered.
// Command construction is explicit (no init() side effects); main calls this
// once and executes the returned command.
func NewRootCmd(version string) *cobra.Command {
	app := &App{}
	Version = version

	root := &cobra.Command{
		Use:   "ztap",
		Short: "Zero Trust Access Platform - Microsegmentation for hybrid environments",
		Long: `ZTAP enforces zero-trust network policies across on-premises and cloud workloads.
It uses eBPF on Linux and pf on macOS to enforce fine-grained traffic rules.`,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load("")
			if err != nil {
				return err
			}
			app.cfg = cfg

			lcfg := logging.Config{
				Level:  string(cfg.Logging.Level),
				File:   cfg.Logging.File,
				Format: string(cfg.Logging.Format),
			}
			if level, _ := cmd.Flags().GetString("log-level"); level != "" {
				lcfg.Level = level
			}
			if format, _ := cmd.Flags().GetString("log-format"); format != "" {
				lcfg.Format = format
			}
			if file, _ := cmd.Flags().GetString("log-file"); file != "" {
				lcfg.File = file
			}

			if _, err := logging.Configure(lcfg); err != nil {
				return fmt.Errorf("configure logging: %w", err)
			}
			return nil
		},
	}

	root.PersistentFlags().String("log-level", "", "Log level (debug, info, warn, error)")
	root.PersistentFlags().String("log-format", "", "Log format (json, text)")
	root.PersistentFlags().String("log-file", "", "Log output file")

	root.AddCommand(
		newAgentCmd(app),
		newAlertCmd(app),
		newApiCmd(app),
		newAuditCmd(app),
		newAwsCmd(app),
		newAzureCmd(app),
		newClusterCmd(),
		newComplianceCmd(),
		newDiscoveryCmd(app),
		newEnforceCmd(app),
		newFlowsCmd(),
		newGcpCmd(app),
		newGrpcCmd(app),
		newLogsCmd(app),
		newMetricsCmd(app),
		newPolicyCmd(app),
		newStatusCmd(app),
		newUserCmd(app),
		newVersionCmd(),
	)

	initClusterBackend(root)

	return root
}
