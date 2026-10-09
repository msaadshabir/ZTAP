package enforcer

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"

	"github.com/saadshabir/ZTAP/internal/policy"
)

// ErrIdentityUncertain defers a complete candidate while a committed, live
// workload cannot yet be matched to authoritative runtime and Kubernetes facts.
// It is retryable and never authorizes removal of the committed generation.
var ErrIdentityUncertain = errors.New("committed workload identity is uncertain")

// Agent status ABI constants are shared by the engine and readers of its
// stable status pin. Keep the wire values explicit because they are persisted
// in bpffs while the agent is running.
const (
	AgentStatusSchemaVersion  uint32 = 1
	AgentLifecycleStarting    uint32 = 1
	AgentLifecycleEnforcing   uint32 = 2
	AgentLifecycleStopping    uint32 = 3
	DefaultFlowEventsPinPath         = "/sys/fs/bpf/ztap/flow_events"
	DefaultAgentStatusPinPath        = "/sys/fs/bpf/ztap/agent_status"
)

// Engine applies complete, kernel-neutral policy snapshots to one node.
// Implementations own their programs, maps, links, and cleanup lifecycle.
type Engine interface {
	Apply(context.Context, policy.PolicySet) error
	Close() error
}

// EngineMetricsSnapshot is the bounded, process-owned observability surface
// exposed by engines that can read their persistent kernel counters. Decision
// and drop counters are cumulative for the engine lifetime; callers may
// publish them directly as Prometheus counters.
type EngineMetricsSnapshot struct {
	ActivePolicyEpoch   uint64
	ProgramGeneration   string
	Decisions           []EngineDecisionMetric
	EventDrops          []EngineEventDropMetric
	SlotCleanupFailures uint64
}

type EngineDecisionMetric struct {
	Action    string
	Direction string
	Reason    string
	Count     uint64
}

type EngineEventDropMetric struct {
	Reason string
	Count  uint64
}

// MetricsProvider is optional so dry-run and non-Linux engines can implement
// the Engine contract without pretending to have kernel counters.
type MetricsProvider interface {
	MetricsSnapshot(context.Context) (EngineMetricsSnapshot, error)
}

// CgroupPathResolver resolves the filesystem path corresponding to a kernel
// cgroup ID. The caller owns the resolver and may back it with a cache.
type CgroupPathResolver func(context.Context, uint64) (string, error)

// LinuxEngineOptions contains the operating-system resources required by the
// Linux eBPF engine. The caller must hold the node's agent lock before recovery
// and for the entire controller lifetime.
type LinuxEngineOptions struct {
	CgroupRoot        string
	BPFFSRoot         string
	ResolveCgroupPath CgroupPathResolver
	AgentEpoch        uint64
	Logger            *slog.Logger
	// ResolveIdentity and ValidateIdentity bind committed subjects to complete
	// runtime identities. Validation must also account for unisolated workloads.
	ResolveIdentity  func(context.Context, uint64) (WorkloadIdentity, error)
	ValidateIdentity func(context.Context, WorkloadIdentity) error
	// ObserveCheckpoint supports deterministic Linux fault injection. The
	// production agent leaves it nil; it must not change policy semantics.
	ObserveCheckpoint func(string)
	// Guard installs inherited protection on verified Kubernetes parents.
	Guard *WorkloadGuardOptions
}

// WorkloadGuardOptions is prepared from a protected node bootstrap record and
// the current process's exact runtime identity before contacting informers.
type WorkloadGuardOptions struct {
	Parents           []string
	HostNetnsCookie   uint64
	HostNetwork       []WorkloadIdentity
	BootstrapIdentity WorkloadIdentity
	APIPeers          []netip.AddrPort
}

// WorkloadIdentity is persisted before a policy commit. Path is relative to
// the configured cgroup root, so host and DaemonSet mount paths may differ.
type WorkloadIdentity struct {
	CgroupID    uint64
	Device      uint64
	PodUID      string
	ContainerID string
	Path        string
}
