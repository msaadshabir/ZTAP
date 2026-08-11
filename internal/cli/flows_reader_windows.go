//go:build windows

package cli

import (
	"ztap/internal/flow"
)

func createFlowReader() flow.FlowReader {
	return flow.NewWindowsReader()
}

func createAnomalyFlowReader() (flow.FlowReader, error) {
	return flow.NewWindowsReader(), nil
}
