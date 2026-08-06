//go:build windows

package cmd

import (
	"ztap/internal/flow"
)

func createFlowReader() flow.FlowReader {
	return flow.NewWindowsReader()
}
