//go:build windows

package cmd

import (
	"ztap/pkg/flow"
)

func createFlowReader() flow.FlowReader {
	return flow.NewWindowsReader()
}
