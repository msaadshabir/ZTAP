//go:build windows

package apigrpc

import "ztap/internal/flow"

func createFlowReader() flow.FlowReader {
	return flow.NewWindowsReader()
}
