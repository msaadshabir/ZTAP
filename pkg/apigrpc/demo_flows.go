package apigrpc

import (
	"time"

	"ztap/pkg/flow"
)

func demoRawFlows() []flow.RawFlowEvent {
	nowNs := time.Now().UnixNano()
	if nowNs < 0 {
		nowNs = 0
	}
	now := uint64(nowNs) // #nosec G115 -- nowNs is clamped to >=0 above
	return []flow.RawFlowEvent{
		{
			TimestampNs: now,
			SrcIP:       [4]uint32{0x0A000101}, // 10.0.1.1
			DestIP:      [4]uint32{0x0A000201}, // 10.0.2.1
			SrcPort:     45678,
			DestPort:    5432,
			Protocol:    6,
			Direction:   0,
			Action:      1,
			Family:      4,
		},
	}
}
