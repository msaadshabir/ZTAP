package cli

import "github.com/spf13/cobra"

func newCleanupCmd() *cobra.Command {
	command := &cobra.Command{
		Use: "cleanup", Short: "Intentionally remove this node's pinned ZTAP enforcement",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			bpffsRoot, err := cmd.Flags().GetString("bpffs-root")
			if err != nil {
				return err
			}
			runDir, err := cmd.Flags().GetString("run-dir")
			if err != nil {
				return err
			}
			return cleanupNativeEnforcement(cmd.Context(), bpffsRoot, runDir)
		},
	}
	command.Flags().String("bpffs-root", "/sys/fs/bpf", "Mounted bpffs root containing the enforcement pins")
	command.Flags().String("run-dir", "/run/ztap", "Directory containing the node-agent lock")
	return command
}
