package cluster

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func TestK8sPolicySyncSyncExistingAllNamespaces(t *testing.T) {
	//nolint:staticcheck // NewClientset requires applyconfigs not generated in this repo.
	client := fake.NewSimpleClientset(
		&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "p1",
				Namespace: "ns-a",
				Labels:    map[string]string{"app": "ztap", "component": "policy-store"},
			},
			Data: map[string]string{"policy.yaml": "apiVersion: ztap/v1\nkind: NetworkPolicy\nmetadata:\n  name: p1\nspec:\n  podSelector:\n    matchLabels:\n      app: p1\n  egress:\n  - to:\n      ipBlock:\n        cidr: 10.0.0.0/8\n    ports:\n    - protocol: TCP\n      port: 80\n"},
		},
		&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "p2",
				Namespace: "ns-b",
				Labels:    map[string]string{"app": "ztap", "component": "policy-store"},
			},
			Data: map[string]string{"policy.yaml": "apiVersion: ztap/v1\nkind: NetworkPolicy\nmetadata:\n  name: p2\nspec:\n  podSelector:\n    matchLabels:\n      app: p2\n  egress:\n  - to:\n      ipBlock:\n        cidr: 10.0.0.0/8\n    ports:\n    - protocol: TCP\n      port: 80\n"},
		},
	)

	ps := NewK8sPolicySyncAllNamespaces(client)

	subCtx, subCancel := context.WithCancel(context.Background())
	defer subCancel()
	updates := ps.SubscribePolicies(subCtx)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := ps.Start(ctx); err != nil {
		t.Fatalf("Start() failed: %v", err)
	}
	t.Cleanup(func() { _ = ps.Stop() })

	got := make(map[string]PolicyUpdate)
	deadline := time.After(2 * time.Second)
	for len(got) < 2 {
		select {
		case u := <-updates:
			got[u.PolicyKeyString()] = u
		case <-deadline:
			t.Fatalf("timeout waiting for updates; got %d", len(got))
		}
	}

	if _, ok := got["ns-a/p1"]; !ok {
		t.Fatalf("expected ns-a/p1 update, got keys=%v", keys(got))
	}
	if _, ok := got["ns-b/p2"]; !ok {
		t.Fatalf("expected ns-b/p2 update, got keys=%v", keys(got))
	}
}

func TestK8sPolicySyncNamespaceAllowList(t *testing.T) {
	//nolint:staticcheck // NewClientset requires applyconfigs not generated in this repo.
	client := fake.NewSimpleClientset(
		&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "p1",
				Namespace: "ns-a",
				Labels:    map[string]string{"app": "ztap", "component": "policy-store"},
			},
			Data: map[string]string{"policy.yaml": "apiVersion: ztap/v1\nkind: NetworkPolicy\nmetadata:\n  name: p1\nspec:\n  podSelector:\n    matchLabels:\n      app: p1\n  egress:\n  - to:\n      ipBlock:\n        cidr: 10.0.0.0/8\n    ports:\n    - protocol: TCP\n      port: 80\n"},
		},
		&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "p2",
				Namespace: "ns-b",
				Labels:    map[string]string{"app": "ztap", "component": "policy-store"},
			},
			Data: map[string]string{"policy.yaml": "apiVersion: ztap/v1\nkind: NetworkPolicy\nmetadata:\n  name: p2\nspec:\n  podSelector:\n    matchLabels:\n      app: p2\n  egress:\n  - to:\n      ipBlock:\n        cidr: 10.0.0.0/8\n    ports:\n    - protocol: TCP\n      port: 80\n"},
		},
	)

	ps := NewK8sPolicySyncNamespaces(client, []string{"ns-a"})

	subCtx, subCancel := context.WithCancel(context.Background())
	defer subCancel()
	updates := ps.SubscribePolicies(subCtx)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := ps.Start(ctx); err != nil {
		t.Fatalf("Start() failed: %v", err)
	}
	t.Cleanup(func() { _ = ps.Stop() })

	select {
	case u := <-updates:
		if u.PolicyKeyString() != "ns-a/p1" {
			t.Fatalf("expected ns-a/p1, got %s", u.PolicyKeyString())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for first update")
	}

	select {
	case u := <-updates:
		t.Fatalf("unexpected extra update: %s", u.PolicyKeyString())
	case <-time.After(150 * time.Millisecond):
		// ok
	}
}

func TestK8sPolicySyncMultiNamespaceWatch(t *testing.T) {
	//nolint:staticcheck // NewClientset requires applyconfigs not generated in this repo.
	client := fake.NewSimpleClientset()

	// The fake clientset's built-in watch behavior isn't reliable for this usage.
	// Use explicit watch reactors so we can deterministically feed events.
	fwA := watch.NewFake()
	fwB := watch.NewFake()
	client.PrependWatchReactor("configmaps", func(action k8stesting.Action) (bool, watch.Interface, error) {
		wa, ok := action.(k8stesting.WatchAction)
		if !ok {
			return false, nil, nil
		}
		switch wa.GetNamespace() {
		case "ns-a":
			return true, fwA, nil
		case "ns-b":
			return true, fwB, nil
		default:
			return true, watch.NewFake(), nil
		}
	})

	ps := NewK8sPolicySyncNamespaces(client, []string{"ns-a", "ns-b"})

	subCtx, subCancel := context.WithCancel(context.Background())
	defer subCancel()
	updates := ps.SubscribePolicies(subCtx)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := ps.Start(ctx); err != nil {
		t.Fatalf("Start() failed: %v", err)
	}
	t.Cleanup(func() { _ = ps.Stop() })

	// Give the watch goroutines a moment to register watches.
	time.Sleep(25 * time.Millisecond)

	fwA.Add(&corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "p1", Namespace: "ns-a", Labels: map[string]string{"app": "ztap", "component": "policy-store"}},
		Data:       map[string]string{"policy.yaml": "apiVersion: ztap/v1\nkind: NetworkPolicy\nmetadata:\n  name: p1\nspec:\n  podSelector:\n    matchLabels:\n      app: p1\n  egress:\n  - to:\n      ipBlock:\n        cidr: 10.0.0.0/8\n    ports:\n    - protocol: TCP\n      port: 80\n"},
	})
	fwB.Add(&corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "p2", Namespace: "ns-b", Labels: map[string]string{"app": "ztap", "component": "policy-store"}},
		Data:       map[string]string{"policy.yaml": "apiVersion: ztap/v1\nkind: NetworkPolicy\nmetadata:\n  name: p2\nspec:\n  podSelector:\n    matchLabels:\n      app: p2\n  egress:\n  - to:\n      ipBlock:\n        cidr: 10.0.0.0/8\n    ports:\n    - protocol: TCP\n      port: 80\n"},
	})

	got := map[string]bool{}
	deadline := time.After(2 * time.Second)
	for len(got) < 2 {
		select {
		case u := <-updates:
			got[u.PolicyKeyString()] = true
		case <-deadline:
			t.Fatalf("timeout waiting for watch updates, got=%v", got)
		}
	}
	if !got["ns-a/p1"] || !got["ns-b/p2"] {
		t.Fatalf("expected updates for ns-a/p1 and ns-b/p2, got=%v", got)
	}
}

func keys(m map[string]PolicyUpdate) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
