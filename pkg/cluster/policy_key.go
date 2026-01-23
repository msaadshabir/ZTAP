package cluster

import (
	"fmt"
	"strings"
)

const DefaultTenant = "default"

// PolicyKey uniquely identifies a policy within a tenant.
//
// In Kubernetes deployments, Tenant maps to the namespace that owns the policy.
type PolicyKey struct {
	Tenant string
	Name   string
}

func (k PolicyKey) Normalized() PolicyKey {
	k.Tenant = NormalizeTenant(k.Tenant)
	k.Name = strings.TrimSpace(k.Name)
	return k
}

func (k PolicyKey) String() string {
	n := k.Normalized()
	if n.Name == "" {
		return NormalizeTenant(n.Tenant)
	}
	return fmt.Sprintf("%s/%s", n.Tenant, n.Name)
}

func NormalizeTenant(tenant string) string {
	tenant = strings.TrimSpace(tenant)
	if tenant == "" {
		return DefaultTenant
	}
	return tenant
}

// ParsePolicyKey parses `tenant/name` into a PolicyKey.
//
// Backward compatibility: if no `/` is present, the key is treated as
// `default/<input>`.
func ParsePolicyKey(s string) (PolicyKey, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return PolicyKey{}, fmt.Errorf("policy key is empty")
	}

	parts := strings.SplitN(s, "/", 2)
	if len(parts) == 1 {
		return NewPolicyKey(DefaultTenant, parts[0])
	}
	return NewPolicyKey(parts[0], parts[1])
}

func NewPolicyKey(tenant, name string) (PolicyKey, error) {
	tenant = strings.TrimSpace(tenant)
	name = strings.TrimSpace(name)
	if tenant == "" {
		tenant = DefaultTenant
	}
	if name == "" {
		return PolicyKey{}, fmt.Errorf("policy name is empty")
	}
	if strings.Contains(name, "/") {
		return PolicyKey{}, fmt.Errorf("policy name must not contain '/'")
	}
	if strings.Contains(tenant, "/") {
		return PolicyKey{}, fmt.Errorf("tenant must not contain '/'")
	}
	return PolicyKey{Tenant: tenant, Name: name}, nil
}
