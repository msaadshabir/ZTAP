package enforcer

import (
	"context"

	"ztap/internal/policy"
)

// SubjectResolver resolves policy subjects (pods/workloads) to Linux cgroup IDs.
//
// The cgroup IDs returned must match the value produced by bpf_get_current_cgroup_id().
//
// In Kubernetes mode, tenant is the namespace.
type SubjectResolver interface {
	ResolveCgroupIDs(ctx context.Context, tenant string, podSelector policy.PodSelectorSpec) ([]uint64, error)
}

// SubjectPortInfo describes a resolved subject cgroup with named ports.
type SubjectPortInfo struct {
	CgroupID uint64
	Ports    []policy.PodPort
	PodName  string
}

// SubjectPortResolver resolves subjects with named port metadata.
type SubjectPortResolver interface {
	ResolveSubjectPorts(ctx context.Context, tenant string, podSelector policy.PodSelectorSpec) ([]SubjectPortInfo, error)
}
