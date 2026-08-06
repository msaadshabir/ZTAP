//go:build !linux && !windows

package apihttp

import (
	"time"

	"ztap/internal/flow"
)

func createFlowReader() flow.FlowReader {
	return flow.NewSimulatedReader(demoRawFlows(), 500*time.Millisecond)
}
