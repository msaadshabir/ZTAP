package discovery

import (
	"context"
	"testing"
	"testing/synctest"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"ztap/internal/policy"
)

func TestK8sDiscoveryAllNamespaces_ResolveLabelsScoped(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		//nolint:staticcheck // NewClientset requires applyconfigs not generated in this repo.
		client := fake.NewSimpleClientset()
		disc, err := NewK8sDiscoveryAllNamespaces(client)
		if err != nil {
			t.Fatalf("Failed to create discovery: %v", err)
		}

		ctx := t.Context()
		if err := disc.Start(ctx); err != nil {
			t.Fatalf("Failed to start discovery: %v", err)
		}

		_, _ = client.CoreV1().Pods("ns-a").Create(ctx, &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "web-a", Namespace: "ns-a", Labels: map[string]string{"app": "web"}},
			Status:     corev1.PodStatus{PodIP: "10.0.0.1"},
		}, metav1.CreateOptions{})
		_, _ = client.CoreV1().Pods("ns-b").Create(ctx, &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "web-b", Namespace: "ns-b", Labels: map[string]string{"app": "web"}},
			Status:     corev1.PodStatus{PodIP: "10.0.0.2"},
		}, metav1.CreateOptions{})

		time.Sleep(100 * time.Millisecond)

		ips, err := disc.ResolveLabelsScoped("ns-a", map[string]string{"app": "web"})
		if err != nil {
			t.Fatalf("ResolveLabelsScoped failed: %v", err)
		}
		if len(ips) != 1 || ips[0] != "10.0.0.1" {
			t.Fatalf("expected [10.0.0.1], got %v", ips)
		}
	})
}

func TestK8sDiscoveryAllNamespaces_WatchScopedIsNamespaceScoped(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		//nolint:staticcheck // NewClientset requires applyconfigs not generated in this repo.
		client := fake.NewSimpleClientset()
		disc, err := NewK8sDiscoveryAllNamespaces(client)
		if err != nil {
			t.Fatalf("Failed to create discovery: %v", err)
		}

		ctx := t.Context()
		if err := disc.Start(ctx); err != nil {
			t.Fatalf("Failed to start discovery: %v", err)
		}

		// Seed one matching pod in ns-a.
		_, _ = client.CoreV1().Pods("ns-a").Create(ctx, &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "web-a", Namespace: "ns-a", Labels: map[string]string{"app": "web"}},
			Status:     corev1.PodStatus{PodIP: "10.0.0.1"},
		}, metav1.CreateOptions{})
		time.Sleep(100 * time.Millisecond)

		watchCtx, watchCancel := context.WithCancel(ctx)
		ch, err := disc.WatchScoped(watchCtx, "ns-a", map[string]string{"app": "web"})
		if err != nil {
			t.Fatalf("WatchScoped failed: %v", err)
		}

		// Initial.
		select {
		case ips := <-ch:
			if len(ips) != 1 || ips[0] != "10.0.0.1" {
				t.Fatalf("expected initial [10.0.0.1], got %v", ips)
			}
		case <-time.After(1 * time.Second):
			t.Fatal("timed out waiting for initial state")
		}

		// Change in ns-b should NOT trigger ns-a watch.
		_, _ = client.CoreV1().Pods("ns-b").Create(ctx, &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "web-b", Namespace: "ns-b", Labels: map[string]string{"app": "web"}},
			Status:     corev1.PodStatus{PodIP: "10.0.0.2"},
		}, metav1.CreateOptions{})
		select {
		case ips := <-ch:
			t.Fatalf("unexpected update from other namespace: %v", ips)
		case <-time.After(150 * time.Millisecond):
			// ok
		}

		// Change in ns-a should trigger.
		_, _ = client.CoreV1().Pods("ns-a").Create(ctx, &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "web-a-2", Namespace: "ns-a", Labels: map[string]string{"app": "web"}},
			Status:     corev1.PodStatus{PodIP: "10.0.0.3"},
		}, metav1.CreateOptions{})
		select {
		case ips := <-ch:
			if len(ips) != 2 {
				t.Fatalf("expected 2 IPs, got %v", ips)
			}
		case <-time.After(1 * time.Second):
			t.Fatal("timed out waiting for namespace-scoped update")
		}

		watchCancel()
		select {
		case _, ok := <-ch:
			if ok {
				t.Fatal("expected watch channel to close")
			}
		case <-time.After(1 * time.Second):
			t.Fatal("timed out waiting for watch close")
		}
	})
}

func TestK8sDiscoveryAllNamespaces_ResolveNamespaces(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		//nolint:staticcheck // NewClientset requires applyconfigs not generated in this repo.
		client := fake.NewSimpleClientset()
		disc, err := NewK8sDiscoveryAllNamespaces(client)
		if err != nil {
			t.Fatalf("Failed to create discovery: %v", err)
		}

		ctx := t.Context()
		if err := disc.Start(ctx); err != nil {
			t.Fatalf("Failed to start discovery: %v", err)
		}

		_, _ = client.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: "payments", Labels: map[string]string{"team": "payments"}},
		}, metav1.CreateOptions{})
		_, _ = client.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: "core", Labels: map[string]string{"team": "core"}},
		}, metav1.CreateOptions{})

		time.Sleep(100 * time.Millisecond)

		namespaces, err := disc.ResolveNamespaces(policy.PodSelectorSpec{MatchLabels: map[string]string{"team": "payments"}})
		if err != nil {
			t.Fatalf("ResolveNamespaces failed: %v", err)
		}
		if len(namespaces) != 1 || namespaces[0] != "payments" {
			t.Fatalf("expected [payments], got %v", namespaces)
		}
	})
}
