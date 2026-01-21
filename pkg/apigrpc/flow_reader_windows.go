//go:build windows

package apigrpc

import "ztap/pkg/flow"

func createFlowReader() flow.FlowReader {
	return flow.NewWindowsReader()
}
