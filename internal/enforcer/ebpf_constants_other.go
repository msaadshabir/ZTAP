//go:build !linux

package enforcer

// DefaultFlowEventsPinPath is the expected bpffs pin path for the flow_events map.
// On non-Linux platforms, it is informational only.
const DefaultFlowEventsPinPath = "/sys/fs/bpf/ztap/flow_events"
