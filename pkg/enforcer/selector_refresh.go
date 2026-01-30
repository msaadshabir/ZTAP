package enforcer

import (
	"context"
	"errors"
	"reflect"
	"sort"
	"strings"
	"time"

	"ztap/pkg/logging"
	"ztap/pkg/policy"
)

type SelectorRefreshOptions struct {
	// Scope is an optional tenant/namespace scope. When non-empty and the
	// discovery backend supports ScopedServiceDiscovery, scoped watch/resolve
	// operations are used.
	Scope string

	// PollInterval triggers periodic refreshes. If <= 0, it defaults to 5s.
	PollInterval time.Duration

	// Debounce coalesces bursts of discovery events. If <= 0, it defaults to 300ms.
	Debounce time.Duration

	// Ready, when non-nil, receives a signal after initial setup.
	Ready chan<- struct{}
}

// WarnNoMatchPolicyTargets logs a warning for any podSelector targets that
// currently resolve to zero addresses.
func WarnNoMatchPolicyTargets(disc policy.ServiceDiscovery, opts SelectorRefreshOptions, policies []policy.NetworkPolicy) {
	if disc == nil {
		return
	}
	selectors := uniqueTargetSelectors(policies)
	if len(selectors) == 0 {
		return
	}

	resolver := policy.NewPolicyResolver(disc)
	for _, sel := range selectors {
		ips, err := resolver.ResolveLabelsScoped(opts.Scope, sel.labels)
		if err != nil {
			if isNoMatches(err) {
				logging.Warnf("podSelector %s resolved to no targets (rules will be inactive until targets exist)", sel.key)
			}
			continue
		}
		if len(ips) == 0 {
			logging.Warnf("podSelector %s resolved to no targets (rules will be inactive until targets exist)", sel.key)
		}
	}
}

// RunSelectorRefresh watches podSelector targets in basePolicies, re-resolves
// them over time, and calls apply whenever the resolved policy set changes.
//
// Callers should run this in a goroutine and cancel ctx to stop it.
func RunSelectorRefresh(
	ctx context.Context,
	disc policy.ServiceDiscovery,
	basePolicies []policy.NetworkPolicy,
	opts SelectorRefreshOptions,
	apply func([]policy.NetworkPolicy) error,
) {
	if disc == nil {
		return
	}
	selectors := uniqueTargetSelectors(basePolicies)
	if len(selectors) == 0 {
		return
	}

	if opts.PollInterval <= 0 {
		opts.PollInterval = 5 * time.Second
	}
	if opts.Debounce <= 0 {
		opts.Debounce = 300 * time.Millisecond
	}

	trigger := make(chan struct{}, 1)
	sendTrigger := func() {
		select {
		case trigger <- struct{}{}:
		default:
		}
	}

	// Start watches.
	for _, sel := range selectors {
		ch, err := watchSelector(ctx, disc, opts.Scope, sel.labels)
		if err != nil {
			continue
		}
		go func(ch <-chan []string) {
			for {
				select {
				case <-ctx.Done():
					return
				case _, ok := <-ch:
					if !ok {
						return
					}
					sendTrigger()
				}
			}
		}(ch)
	}

	ticker := time.NewTicker(opts.PollInterval)
	defer ticker.Stop()

	resolver := policy.NewPolicyResolver(disc)
	current, _ := resolvePoliciesWithScope(resolver, opts.Scope, basePolicies)

	if opts.Ready != nil {
		select {
		case opts.Ready <- struct{}{}:
		default:
		}
	}

	timer := time.NewTimer(time.Hour)
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	defer timer.Stop()

	pending := false
	reset := func() {
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(opts.Debounce)
		pending = true
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sendTrigger()
		case <-trigger:
			reset()
		case <-timer.C:
			pending = false
			next, err := resolvePoliciesWithScope(resolver, opts.Scope, basePolicies)
			if err != nil {
				logging.Warnf("Failed to re-resolve pod selectors: %v", err)
				continue
			}
			if reflect.DeepEqual(next, current) {
				continue
			}
			WarnNoMatchPolicyTargets(disc, opts, basePolicies)
			if err := apply(next); err != nil {
				logging.Warnf("Failed to re-apply policies after selector update: %v", err)
				continue
			}
			current = next
			logging.Info("Re-applied policies due to selector resolution change", nil)
			if pending {
				sendTrigger()
			}
		}
	}
}

type selectorSpec struct {
	key    string
	labels map[string]string
}

func uniqueTargetSelectors(policies []policy.NetworkPolicy) []selectorSpec {
	seen := make(map[string]map[string]string)
	add := func(labels map[string]string) {
		if len(labels) == 0 {
			return
		}
		k := policy.SelectorKey(labels)
		if k == "" {
			return
		}
		if _, ok := seen[k]; ok {
			return
		}
		cpy := make(map[string]string, len(labels))
		for kk, vv := range labels {
			cpy[kk] = vv
		}
		seen[k] = cpy
	}

	for _, p := range policies {
		for _, e := range p.Spec.Egress {
			add(e.To.PodSelector.MatchLabels)
		}
		for _, in := range p.Spec.Ingress {
			add(in.From.PodSelector.MatchLabels)
		}
	}

	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	out := make([]selectorSpec, 0, len(keys))
	for _, k := range keys {
		out = append(out, selectorSpec{key: k, labels: seen[k]})
	}
	return out
}

func resolvePoliciesWithScope(resolver *policy.PolicyResolver, scope string, policies []policy.NetworkPolicy) ([]policy.NetworkPolicy, error) {
	scope = policyTenantScope(scope)
	if scope != "" {
		return resolver.ResolvePodSelectorsToIPBlocksScoped(scope, policies)
	}
	return resolver.ResolvePodSelectorsToIPBlocks(policies)
}

func watchSelector(ctx context.Context, disc policy.ServiceDiscovery, scope string, selector map[string]string) (<-chan []string, error) {
	scope = policyTenantScope(scope)
	if scope != "" {
		if scoped, ok := disc.(policy.ScopedServiceDiscovery); ok {
			return scoped.WatchScoped(ctx, scope, selector)
		}
	}
	return disc.Watch(ctx, selector)
}

func policyTenantScope(scope string) string {
	// Normalize empty/whitespace-only scope to empty.
	// The policy resolver treats empty scope as unscoped.
	scope = strings.TrimSpace(scope)
	if scope == "" {
		return ""
	}
	return scope
}

func isNoMatches(err error) bool {
	type noMatches interface {
		NoMatches() bool
	}
	var nm noMatches
	if errors.As(err, &nm) {
		return nm.NoMatches()
	}
	return false
}
