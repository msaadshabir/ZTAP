package enforcer

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/saadshabir/ZTAP/internal/policy"
)

// ReconcileNativePolicySnapshot compiles one caller-provided Kubernetes
// snapshot and applies its complete policy set through the instance-owned
// engine. The caller owns snapshot freshness and engine lifecycle.
func ReconcileNativePolicySnapshot(ctx context.Context, engine Engine, policies []policy.NativeNetworkPolicy, input policy.ResolutionInput) (policy.CompileResult, error) {
	if ctx == nil {
		return policy.CompileResult{}, errors.New("policy reconciliation context is nil")
	}
	if engine == nil {
		return policy.CompileResult{}, errors.New("policy reconciliation engine is nil")
	}
	if err := ctx.Err(); err != nil {
		return policy.CompileResult{}, err
	}

	result, err := policy.CompileNativePolicies(policies, input)
	if err != nil {
		return policy.CompileResult{}, fmt.Errorf("compile native policy snapshot: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	for _, pod := range input.Pods {
		if pod.Local && !pod.HostNetwork {
			result.PolicySet.ClassifiedCgroups = append(result.PolicySet.ClassifiedCgroups, pod.CgroupIDs...)
		}
	}
	slices.Sort(result.PolicySet.ClassifiedCgroups)
	result.PolicySet.ClassifiedCgroups = slices.Compact(result.PolicySet.ClassifiedCgroups)
	if err := engine.Apply(ctx, result.PolicySet); err != nil {
		return result, fmt.Errorf("apply native policy snapshot: %w", err)
	}
	return result, nil
}
