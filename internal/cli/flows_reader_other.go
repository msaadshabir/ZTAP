//go:build !linux && !windows

package cli

import (
	"fmt"
	"time"

	"ztap/internal/flow"
)

func createFlowReader() flow.FlowReader {
	return flow.NewSimulatedReader(generateRawDemoFlows(), 500*time.Millisecond)
}

func createAnomalyFlowReader() (flow.FlowReader, error) {
	return nil, fmt.Errorf("real flow monitoring is unavailable on this platform")
}
