//go:build linux

package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func TestCommittedIdentityRequiresCompleteCurrentContainerStatus(t *testing.T) {
	root := t.TempDir()
	uid := "2b6a3c84-291d-4c16-9ca1-709384c3a4b2"
	container := strings.Repeat("a", 64)
	path := filepath.Join(root, "kubepods.slice", "kubepods-burstable.slice", "kubepods-burstable-pod"+strings.ReplaceAll(uid, "-", "_")+".slice", "cri-containerd-"+container+".scope")
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatal(err)
	}
	id, err := cgroupIDFromPath(path)
	if err != nil {
		t.Fatal(err)
	}
	pod := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "local", Name: "protected", UID: types.UID(uid)}, Spec: corev1.PodSpec{NodeName: "node-a"}, Status: corev1.PodStatus{QOSClass: corev1.PodQOSBurstable, Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{{ContainerID: "containerd://" + container, State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}}}}}
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-a"}, Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: "192.0.2.1"}}}}
	resolver := newK8sSubjectResolver(root)
	if _, err := resolver.BuildResolutionSnapshot("node-a", node, nil, []corev1.Pod{pod}); err != nil {
		t.Fatal(err)
	}
	committed, err := resolver.ResolveWorkloadIdentity(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if committed.PodUID != uid || committed.ContainerID != container || filepath.Join(root, committed.Path) != path {
		t.Fatalf("incomplete persisted identity: %+v", committed)
	}
	for _, state := range []string{"id-missing", "pending", "pod-missing", "inconsistent"} {
		t.Run(state, func(t *testing.T) {
			candidate := pod.DeepCopy()
			pods := []corev1.Pod{*candidate}
			switch state {
			case "id-missing":
				pods[0].Status.ContainerStatuses[0].ContainerID = ""
			case "pending":
				pods[0].Status.ContainerStatuses[0].State = corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{}}
			case "pod-missing":
				pods = nil
			case "inconsistent":
				pods[0].Status.ContainerStatuses[0].ContainerID = "containerd://" + strings.Repeat("b", 64)
			}
			if _, err := resolver.BuildResolutionSnapshot("node-a", node, nil, pods); err != nil {
				t.Fatal(err)
			}
			if err := resolver.ValidateWorkloadIdentity(context.Background(), committed); err == nil {
				t.Fatal("uncertain live identity authorized policy removal")
			}
			if _, err := resolver.BuildResolutionSnapshot("node-a", node, nil, []corev1.Pod{pod}); err != nil {
				t.Fatal(err)
			}
			if err := resolver.ValidateWorkloadIdentity(context.Background(), committed); err != nil {
				t.Fatalf("resolved identity remained degraded: %v", err)
			}
		})
	}
}
