//go:build windows

package apihttp

import "ztap/internal/flow"

func createFlowReader() flow.FlowReader {
	return flow.NewWindowsReader()
}
