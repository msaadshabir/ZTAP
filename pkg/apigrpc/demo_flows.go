package apigrpc

import (
	"time"

	"ztap/pkg/flow"
)

func demoRawFlows() []flow.RawFlowEvent {
	now := uint64(time.Now().UnixNano())
	return []flow.RawFlowEvent{
		{
			TimestampNs: now,
			SrcIP:       0x0A000101, // 10.0.1.1
			DestIP:      0x0A000201, // 10.0.2.1
			SrcPort:     45678,
			DestPort:    5432,
			Protocol:    6,
			Direction:   0,
			Action:      1,
		},
	}
}
