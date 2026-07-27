package enforcer

import (
	"context"
	"testing"
	"time"

	"ztap/pkg/discovery"
	"ztap/pkg/policy"
)

func TestRunSelectorRefresh_RemovesRuleOnNoMatch(t *testing.T) {
	disc := discovery.NewInMemoryDiscovery()
	if err := disc.RegisterService("db-1", "10.0.0.1", map[string]string{"app": "db"}); err != nil {
		t.Fatalf("register: %v", err)
	}

	base := []policy.NetworkPolicy{
		{
			Metadata: policy.NetworkPolicyMetadata{Name: "p"},
			Spec: policy.NetworkPolicySpec{
				PodSelector: policy.PodSelectorSpec{MatchLabels: map[string]string{"app": "web"}},
				Egress: []policy.EgressRule{
					{
						To:    policy.EgressTarget{PodSelector: policy.PodSelectorSpec{MatchLabels: map[string]string{"app": "db"}}},
						Ports: []policy.PortSpec{{Protocol: "TCP", Port: 5432}},
					},
				},
			},
		},
	}

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	ready := make(chan struct{}, 1)
	appliedCh := make(chan []policy.NetworkPolicy, 10)
	go RunSelectorRefresh(ctx, disc, base, SelectorRefreshOptions{PollInterval: 1 * time.Second, Ready: ready}, func(p []policy.NetworkPolicy) error {
		appliedCh <- p
		return nil
	})

	select {
	case <-ready:
	case <-ctx.Done():
		t.Fatal("timed out waiting for refresher setup")
	}

	// Remove the only matching service; selector should resolve to empty and rules should be removed.
	if err := disc.DeregisterService("db-1"); err != nil {
		t.Fatalf("deregister: %v", err)
	}

	select {
	case applied := <-appliedCh:
		if len(applied) != 1 {
			t.Fatalf("expected 1 policy, got %d", len(applied))
		}
		if len(applied[0].Spec.Egress) != 0 {
			t.Fatalf("expected 0 egress rules after no-match, got %d", len(applied[0].Spec.Egress))
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for re-apply")
	}
}

func TestRunSelectorRefresh_AddsRuleOnMatch(t *testing.T) {
	disc := discovery.NewInMemoryDiscovery()

	base := []policy.NetworkPolicy{
		{
			Metadata: policy.NetworkPolicyMetadata{Name: "p"},
			Spec: policy.NetworkPolicySpec{
				PodSelector: policy.PodSelectorSpec{MatchLabels: map[string]string{"app": "web"}},
				Egress: []policy.EgressRule{
					{
						To:    policy.EgressTarget{PodSelector: policy.PodSelectorSpec{MatchLabels: map[string]string{"app": "db"}}},
						Ports: []policy.PortSpec{{Protocol: "TCP", Port: 5432}},
					},
				},
			},
		},
	}

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	ready := make(chan struct{}, 1)
	appliedCh := make(chan []policy.NetworkPolicy, 10)
	go RunSelectorRefresh(ctx, disc, base, SelectorRefreshOptions{PollInterval: 1 * time.Second, Ready: ready}, func(p []policy.NetworkPolicy) error {
		appliedCh <- p
		return nil
	})

	select {
	case <-ready:
	case <-ctx.Done():
		t.Fatal("timed out waiting for refresher setup")
	}

	// Add a matching service; selector should resolve and rules should be added.
	if err := disc.RegisterService("db-1", "10.0.0.1", map[string]string{"app": "db"}); err != nil {
		t.Fatalf("register: %v", err)
	}

	select {
	case applied := <-appliedCh:
		if len(applied) != 1 {
			t.Fatalf("expected 1 policy, got %d", len(applied))
		}
		if len(applied[0].Spec.Egress) != 1 {
			t.Fatalf("expected 1 egress rule after match, got %d", len(applied[0].Spec.Egress))
		}
		if applied[0].Spec.Egress[0].To.IPBlock.CIDR != "10.0.0.1/32" {
			t.Fatalf("expected resolved CIDR 10.0.0.1/32, got %s", applied[0].Spec.Egress[0].To.IPBlock.CIDR)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for re-apply")
	}
}
