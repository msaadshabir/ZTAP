package discovery

import (
	"context"
	"slices"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestK8sDiscovery(t *testing.T) {
	//nolint:staticcheck // NewClientset requires applyconfigs not generated in this repo.
	client := fake.NewSimpleClientset()
	namespace := "default"
	disc, err := NewK8sDiscovery(client, namespace)
	if err != nil {
		t.Fatalf("Failed to create discovery: %v", err)
	}

	ctx := t.Context()

	if err := disc.Start(ctx); err != nil {
		t.Fatalf("Failed to start discovery: %v", err)
	}

	// Test ResolveLabels with no pods
	_, err = disc.ResolveLabels(map[string]string{"app": "web"})
	if err == nil {
		t.Error("Expected error for no matching pods, got nil")
	}

	// Add a pod
	pod1 := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "web-1",
			Namespace: namespace,
			Labels:    map[string]string{"app": "web"},
		},
		Status: corev1.PodStatus{
			PodIP: "10.0.0.1",
		},
	}
	_, _ = client.CoreV1().Pods(namespace).Create(ctx, pod1, metav1.CreateOptions{})

	// Wait for informer to sync (fake client informers are usually fast but need a small yield)
	time.Sleep(100 * time.Millisecond)

	// Test ResolveLabels
	ips, err := disc.ResolveLabels(map[string]string{"app": "web"})
	if err != nil {
		t.Fatalf("ResolveLabels failed: %v", err)
	}
	if len(ips) != 1 || ips[0] != "10.0.0.1" {
		t.Errorf("Expected [10.0.0.1], got %v", ips)
	}

	// Test Watch
	watchCtx, watchCancel := context.WithCancel(ctx)
	ch, err := disc.Watch(watchCtx, map[string]string{"app": "web"})
	if err != nil {
		t.Fatalf("Watch failed: %v", err)
	}

	// Initial state
	select {
	case initialIPs := <-ch:
		if len(initialIPs) != 1 || initialIPs[0] != "10.0.0.1" {
			t.Errorf("Expected initial [10.0.0.1], got %v", initialIPs)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Timed out waiting for initial watch state")
	}

	// Add another pod
	pod2 := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "web-2",
			Namespace: namespace,
			Labels:    map[string]string{"app": "web"},
		},
		Status: corev1.PodStatus{
			PodIP: "10.0.0.2",
		},
	}
	_, _ = client.CoreV1().Pods(namespace).Create(ctx, pod2, metav1.CreateOptions{})

	select {
	case updatedIPs := <-ch:
		slices.Sort(updatedIPs)
		if len(updatedIPs) != 2 || updatedIPs[0] != "10.0.0.1" || updatedIPs[1] != "10.0.0.2" {
			t.Errorf("Expected updated [10.0.0.1 10.0.0.2], got %v", updatedIPs)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Timed out waiting for watch update")
	}

	// Update pod labels (remove from selector)
	pod2.Labels = map[string]string{"app": "db"}
	_, _ = client.CoreV1().Pods(namespace).Update(ctx, pod2, metav1.UpdateOptions{})

	select {
	case updatedIPs := <-ch:
		if len(updatedIPs) != 1 || updatedIPs[0] != "10.0.0.1" {
			t.Errorf("Expected updated [10.0.0.1] after label change, got %v", updatedIPs)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Timed out waiting for watch update after label change")
	}

	// Cancel watch
	watchCancel()
	select {
	case _, ok := <-ch:
		if ok {
			t.Error("Expected channel to be closed after watch cancel")
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Timed out waiting for channel close")
	}
}

func TestK8sDiscovery_WatchNoMatchInitialState(t *testing.T) {
	// Test that Watch returns nil IPs (not error) when no pods match the selector.
	// This verifies the NoMatchesError is handled gracefully.
	//nolint:staticcheck
	client := fake.NewSimpleClientset()
	namespace := "default"
	disc, err := NewK8sDiscovery(client, namespace)
	if err != nil {
		t.Fatalf("Failed to create discovery: %v", err)
	}

	ctx := t.Context()

	if err := disc.Start(ctx); err != nil {
		t.Fatalf("Failed to start discovery: %v", err)
	}

	// Watch for a label that has no matching pods
	watchCtx, watchCancel := context.WithCancel(ctx)
	defer watchCancel()
	ch, err := disc.Watch(watchCtx, map[string]string{"app": "nonexistent"})
	if err != nil {
		t.Fatalf("Watch should not fail for no-match scenario, got: %v", err)
	}

	// Should receive nil/empty initial state (not error)
	select {
	case initialIPs := <-ch:
		// nil or empty is acceptable
		if len(initialIPs) > 0 {
			t.Errorf("Expected nil/empty initial IPs, got %v", initialIPs)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Timed out waiting for initial watch state")
	}

	watchCancel()
	select {
	case _, ok := <-ch:
		if ok {
			t.Error("Expected channel to be closed after watch cancel")
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Timed out waiting for channel close")
	}
}
