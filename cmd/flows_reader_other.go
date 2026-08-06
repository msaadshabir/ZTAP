//go:build !linux && !windows

package cmd

import (
	"time"

	"ztap/internal/flow"
)

func createFlowReader() flow.FlowReader {
	return flow.NewSimulatedReader(generateRawDemoFlows(), 500*time.Millisecond)
}
