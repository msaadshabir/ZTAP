package enforcer

import "context"

// SubjectResolver resolves policy subjects (pods/workloads) to Linux cgroup IDs.
//
// The cgroup IDs returned must match the value produced by bpf_get_current_cgroup_id().
//
// In Kubernetes mode, tenant is the namespace.
type SubjectResolver interface {
	ResolveCgroupIDs(ctx context.Context, tenant string, podSelector map[string]string) ([]uint64, error)
}
