//go:build windows

package apihttp

import "ztap/pkg/flow"

func createFlowReader() flow.FlowReader {
	return flow.NewWindowsReader()
}
