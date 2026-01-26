package cmd

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

// Version is the human-readable build version.
//
// It is set by main at startup. Release builds also inject main.Version via ldflags.
var Version = "dev"

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print ZTAP version",
	Run: func(cmd *cobra.Command, args []string) {
		v := Version
		if v == "" {
			v = "dev"
		}
		fmt.Printf("ztap %s (%s/%s)\n", v, runtime.GOOS, runtime.GOARCH)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
