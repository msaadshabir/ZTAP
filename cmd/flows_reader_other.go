//go:build !linux && !windows
// +build !linux,!windows

package cmd

import (
	"time"

	"ztap/pkg/flow"
)

func createFlowReader() flow.FlowReader {
	return flow.NewSimulatedReader(generateRawDemoFlows(), 500*time.Millisecond)
}
