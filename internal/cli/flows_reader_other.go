//go:build !linux && !windows

package cli

import (
	"time"

	"ztap/internal/flow"
)

func createFlowReader() flow.FlowReader {
	return flow.NewSimulatedReader(generateRawDemoFlows(), 500*time.Millisecond)
}
