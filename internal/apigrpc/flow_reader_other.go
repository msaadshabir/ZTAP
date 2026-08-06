//go:build !linux && !windows

package apigrpc

import (
	"time"

	"ztap/internal/flow"
)

func createFlowReader() flow.FlowReader {
	return flow.NewSimulatedReader(demoRawFlows(), 500*time.Millisecond)
}
