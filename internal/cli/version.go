package cli

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

// Version is the human-readable build version.
//
// It is set when the root command is constructed.
var Version = "dev"

func newVersionCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "version",
		Short: "Print ZTAP version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			v := Version
			if v == "" {
				v = "dev"
			}
			_, err := fmt.Fprintf(cmd.OutOrStdout(), "version=%s go=%s os=%s arch=%s\n", v, runtime.Version(), runtime.GOOS, runtime.GOARCH)
			return err
		},
	}
	return c
}
