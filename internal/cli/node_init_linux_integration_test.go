//go:build linux && integration

package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
)

func TestNodeBootstrapProcessHelper(t *testing.T) {
	if os.Getenv("ZTAP_NODE_BOOTSTRAP_HELPER") != "1" {
		t.Skip("helper")
	}
	gate := os.NewFile(3, "cgroup membership gate")
	if _, err := io.ReadFull(gate, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	_ = gate.Close()
	uid := os.Getenv("POD_UID")
	// API status deliberately has neither Running state nor a container ID.
	// Exact authenticated Pod UID plus actual kernel process membership is
	// sufficient for bootstrap, before the agent can synchronize informers.
	client := fake.NewSimpleClientset(
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-a", UID: "node-uid"}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "initializer", Namespace: "ztap-system", UID: types.UID(uid)}, Spec: corev1.PodSpec{NodeName: "node-a", HostNetwork: true}, Status: corev1.PodStatus{Phase: corev1.PodPending}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "static-host", Namespace: "kube-system", UID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", Annotations: map[string]string{"kubernetes.io/config.source": "file", "kubernetes.io/config.hash": strings.Repeat("c", 32), "kubernetes.io/config.mirror": strings.Repeat("c", 32)}}, Spec: corev1.PodSpec{NodeName: "node-a", HostNetwork: true}, Status: corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{{ContainerID: "containerd://" + strings.Repeat("d", 64), State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}}}}},
		&corev1.Endpoints{ObjectMeta: metav1.ObjectMeta{Name: "kubernetes", Namespace: "default"}, Subsets: []corev1.EndpointSubset{{Addresses: []corev1.EndpointAddress{{IP: "127.0.0.1"}}, Ports: []corev1.EndpointPort{{Port: 6443, Protocol: corev1.ProtocolTCP}}}}},
	)
	root, runDir := os.Getenv("ZTAP_NODE_BOOTSTRAP_ROOT"), os.Getenv("ZTAP_NODE_BOOTSTRAP_RUN")
	if err := initializeNodeBootstrap(context.Background(), client, &rest.Config{Host: "https://127.0.0.1:443"}, "node-a", root, runDir); err != nil {
		t.Fatal(err)
	}
	guard, err := loadNodeGuardBootstrap(runDir, root, "node-a", uid)
	if err != nil {
		t.Fatal(err)
	}
	if guard.BootstrapIdentity.PodUID != uid || len(guard.BootstrapIdentity.ContainerID) != 64 || guard.BootstrapIdentity.CgroupID == 0 || len(guard.HostNetwork) != 2 || len(guard.APIPeers) != 2 {
		t.Fatalf("incomplete verified bootstrap: %+v", guard)
	}
	static, err := client.CoreV1().Pods("kube-system").Get(context.Background(), "static-host", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	static.Status.ContainerStatuses[0].ContainerID = "containerd://" + strings.Repeat("b", 64)
	if _, err := scanBootstrapHostNetworkIdentities(root, static); err == nil {
		t.Fatal("a static annotation granted another container a host-network exemption")
	}
	static.Status.Phase = corev1.PodPending
	static.Status.ContainerStatuses = nil
	if _, err := scanBootstrapHostNetworkIdentities(root, static); err == nil {
		t.Fatal("a live static cgroup without published container identity was omitted from bootstrap")
	}
	if _, err := findBootstrapProcessIdentity(root, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"); err == nil {
		t.Fatal("another Pod UID inherited bootstrap")
	}
}

func TestLinuxNodeBootstrapVerifiesPendingRuntimeIdentity(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("bootstrap kernel gate requires root")
	}
	root := filepath.Join("/sys/fs/cgroup", fmt.Sprintf("ztap-bootstrap-%d", time.Now().UnixNano()))
	createPhase5CgroupDir(t, root)
	parent := filepath.Join(root, "kubepods.slice")
	createPhase5CgroupDir(t, parent)
	qos := filepath.Join(parent, "kubepods-burstable.slice")
	createPhase5CgroupDir(t, qos)
	uid := "11111111-2222-3333-4444-555555555555"
	pod := filepath.Join(qos, "kubepods-burstable-pod"+strings.ReplaceAll(uid, "-", "_")+".slice")
	createPhase5CgroupDir(t, pod)
	container := filepath.Join(pod, "cri-containerd-"+strings.Repeat("b", 64)+".scope")
	createPhase5CgroupDir(t, container)
	staticPod := filepath.Join(qos, "kubepods-burstable-pod"+strings.Repeat("c", 32)+".slice")
	createPhase5CgroupDir(t, staticPod)
	createPhase5CgroupDir(t, filepath.Join(staticPod, "cri-containerd-"+strings.Repeat("d", 64)+".scope"))
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = read.Close(); _ = write.Close() })
	cmd := exec.Command(os.Args[0], "-test.run=^TestNodeBootstrapProcessHelper$")
	cmd.Env = append(os.Environ(), "ZTAP_NODE_BOOTSTRAP_HELPER=1", "POD_UID="+uid, "ZTAP_NODE_BOOTSTRAP_ROOT="+root, "ZTAP_NODE_BOOTSTRAP_RUN="+t.TempDir())
	cmd.ExtraFiles = []*os.File{read}
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	t.Cleanup(func() {
		if !waited {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	})
	_ = read.Close()
	procs, err := openPhase5CgroupProcs(container)
	if err != nil {
		t.Fatal(err)
	}
	_, err = procs.WriteString(strconv.Itoa(cmd.Process.Pid))
	closeErr := procs.Close()
	if err != nil || closeErr != nil {
		t.Fatalf("move bootstrap process: %v %v", err, closeErr)
	}
	if _, err := write.Write([]byte{'1'}); err != nil {
		t.Fatal(err)
	}
	_ = write.Close()
	err = cmd.Wait()
	waited = true
	if err != nil {
		t.Fatal(err)
	}
}
