//go:build linux && integration

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/saadshabir/ZTAP/internal/enforcer"
	"github.com/saadshabir/ZTAP/internal/restartproof"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func TestAgentContinuityTrafficHelper(t *testing.T) { restartproof.RunHelper(t) }

func continuityObjects(index, ingress, egress int) []k8sruntime.Object {
	uid := phase5AgentCrashUID(index)
	protocol := corev1.ProtocolUDP
	ingressPort, egressPort := intstr.FromInt(ingress), intstr.FromInt(egress)
	return []k8sruntime.Object{
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "default"}},
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-a"}, Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: "192.0.2.10"}}}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "continuity-workload", Namespace: "default", UID: types.UID(uid)}, Spec: corev1.PodSpec{NodeName: "node-a"}, Status: corev1.PodStatus{Phase: corev1.PodRunning, QOSClass: corev1.PodQOSBurstable, PodIP: "10.0.4.1", ContainerStatuses: []corev1.ContainerStatus{{Name: "workload", ContainerID: fmt.Sprintf("containerd://%064x", index+1), State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}}}}},
		&networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "continuity", Namespace: "default"}, Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{}, PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress},
			Ingress: []networkingv1.NetworkPolicyIngressRule{{From: []networkingv1.NetworkPolicyPeer{{IPBlock: &networkingv1.IPBlock{CIDR: "127.0.0.1/32"}}}, Ports: []networkingv1.NetworkPolicyPort{{Protocol: &protocol, Port: &ingressPort}}}},
			Egress:  []networkingv1.NetworkPolicyEgressRule{{To: []networkingv1.NetworkPolicyPeer{{IPBlock: &networkingv1.IPBlock{CIDR: "127.0.0.1/32"}}}, Ports: []networkingv1.NetworkPolicyPort{{Protocol: &protocol, Port: &egressPort}}}},
		}},
	}
}

func TestAgentContinuityOwnerHelper(t *testing.T) {
	if os.Getenv("ZTAP_CONTINUITY_AGENT") != "1" {
		t.Skip("helper")
	}
	parse := func(name string) int {
		value, err := strconv.Atoi(os.Getenv(name))
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	client := fake.NewSimpleClientset(continuityObjects(parse("ZTAP_CONTINUITY_INDEX"), parse("ZTAP_CONTINUITY_INGRESS"), parse("ZTAP_CONTINUITY_EGRESS"))...)
	var unavailable atomic.Bool
	unavailable.Store(os.Getenv("ZTAP_CONTINUITY_API_OUTAGE") == "1")
	reject := func(k8stesting.Action) (bool, k8sruntime.Object, error) {
		if unavailable.Load() {
			return true, nil, errors.New("injected Kubernetes API outage")
		}
		return false, nil, nil
	}
	client.PrependReactor("list", "*", reject)
	client.PrependWatchReactor("*", func(k8stesting.Action) (bool, watch.Interface, error) {
		if unavailable.Load() {
			return true, nil, errors.New("injected Kubernetes API outage")
		}
		return false, nil, nil
	})
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		done <- runNativeKubernetesAgent(ctx, client, NativeAgentOptions{NodeName: "node-a", CgroupRoot: "/sys/fs/cgroup", BPFFSRoot: os.Getenv("ZTAP_CONTINUITY_BPFFS"), RunDir: os.Getenv("ZTAP_CONTINUITY_RUN"), Listen: listener.Addr().String(), StatusListener: listener})
	}()
	agent := &phase5AgentProcess{address: listener.Addr().String(), done: done}
	predicate := func(metrics string) bool {
		return phase5MetricEquals(metrics, "ztap_active_policy_epoch", 1) && phase5MetricEquals(metrics, "ztap_agent_ready", 1)
	}
	if unavailable.Load() {
		predicate = func(metrics string) bool {
			return phase5MetricEquals(metrics, "ztap_active_policy_epoch", 1) && phase5MetricEquals(metrics, "ztap_agent_ready", 0)
		}
	}
	if _, err := waitPhase5AgentMetrics(agent, predicate, 20*time.Second); err != nil {
		t.Fatal(err)
	}
	ready := os.NewFile(3, "native agent ready")
	defer func() { _ = ready.Close() }()
	if _, err := ready.Write([]byte{'1'}); err != nil {
		t.Fatal(err)
	}
	if unavailable.Load() {
		release := os.NewFile(4, "API recovery")
		defer func() { _ = release.Close() }()
		if _, err := io.ReadFull(release, make([]byte, 1)); err != nil {
			t.Fatal(err)
		}
		unavailable.Store(false)
		if _, err := waitPhase5AgentMetrics(agent, func(metrics string) bool {
			return phase5MetricEquals(metrics, "ztap_agent_ready", 1) && phase5MetricEquals(metrics, "ztap_active_policy_epoch", 1)
		}, 20*time.Second); err != nil {
			t.Fatal(err)
		}
		if _, err := ready.Write([]byte{'r'}); err != nil {
			t.Fatal(err)
		}
	}
	<-ctx.Done()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func runAgentContinuitySample(t *testing.T, mode string, index int, apiOutage bool) restartproof.Sample {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Fatal("continuity gate requires Linux eBPF privileges")
	}
	cgroup := createPhase5AgentCrashCgroup(t, index)
	var stat syscall.Stat_t
	if err := syscall.Stat(cgroup, &stat); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join("/sys/fs/bpf", fmt.Sprintf("ztap-agent-continuity-%d", time.Now().UnixNano()))
	if err := os.Mkdir(root, 0o750); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := enforcer.RemoveEnforcement(context.Background(), root); err != nil {
			t.Error(err)
			return
		}
		if err := os.Remove(filepath.Join(root, "ztap")); err != nil && !os.IsNotExist(err) {
			t.Error(err)
		}
		if err := os.Remove(root); err != nil {
			t.Error(err)
		}
	})
	traffic := restartproof.Start(t, cgroup, "TestAgentContinuityTrafficHelper")
	runDir := t.TempDir()
	start := func(outage bool) (*exec.Cmd, *os.File, *os.File) {
		reader, writer, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		releaseRead, releaseWrite, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(os.Args[0], "-test.run=^TestAgentContinuityOwnerHelper$")
		cmd.Env = append(os.Environ(), "ZTAP_CONTINUITY_AGENT=1", "ZTAP_CONTINUITY_INDEX="+strconv.Itoa(index), "ZTAP_CONTINUITY_INGRESS="+strconv.Itoa(int(traffic.Ports.AllowedPort)), "ZTAP_CONTINUITY_EGRESS="+strconv.Itoa(int(traffic.EgressPort())), "ZTAP_CONTINUITY_BPFFS="+root, "ZTAP_CONTINUITY_RUN="+runDir)
		if outage {
			cmd.Env = append(cmd.Env, "ZTAP_CONTINUITY_API_OUTAGE=1")
		}
		cmd.ExtraFiles = []*os.File{writer, releaseRead}
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		_ = writer.Close()
		_ = releaseRead.Close()
		t.Cleanup(func() {
			if cmd.ProcessState == nil {
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
			}
			_ = reader.Close()
			_ = releaseWrite.Close()
		})
		_ = reader.SetReadDeadline(time.Now().Add(30 * time.Second))
		if _, err := io.ReadFull(reader, make([]byte, 1)); err != nil {
			t.Fatal(err)
		}
		return cmd, reader, releaseWrite
	}
	current, _, _ := start(false)
	status, err := ebpf.LoadPinnedMap(filepath.Join(root, "ztap", "agent_status"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = status.Close() }()
	agentEpoch := func() uint64 {
		value := struct {
			Schema    uint32
			Lifecycle uint32
			Epoch     uint64
			Heartbeat uint64
		}{}
		zero := uint32(0)
		if err := status.Lookup(&zero, &value); err != nil {
			t.Fatal(err)
		}
		return value.Epoch
	}
	outer, err := ebpf.LoadPinnedMap(filepath.Join(root, "ztap", "active_config"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = outer.Close() }()
	kernelEpoch := func() uint64 {
		zero := uint32(0)
		var id uint32
		if err := outer.Lookup(&zero, &id); err != nil {
			t.Fatal(err)
		}
		inner, err := ebpf.NewMapFromID(ebpf.MapID(id))
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = inner.Close() }()
		var config struct {
			Slot    uint32
			Padding uint32
			Epoch   uint64
		}
		if err := inner.Lookup(&zero, &config); err != nil {
			t.Fatal(err)
		}
		return config.Epoch
	}
	decisions, err := ebpf.LoadPinnedMap(filepath.Join(root, "ztap", "decision_epoch_counts"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = decisions.Close() }()
	blocked := func(direction uint8) uint64 {
		key := struct {
			Epoch     uint64
			Direction uint8
			Action    uint8
			Reason    uint8
			Padding   [5]byte
		}{Epoch: kernelEpoch(), Direction: direction, Reason: 6}
		var perCPU []uint64
		if err := decisions.Lookup(&key, &perCPU); err != nil {
			t.Fatal(err)
		}
		var total uint64
		for _, value := range perCPU {
			total += value
		}
		return total
	}

	counts := func() restartproof.Counts {
		report := traffic.Snapshot()
		return restartproof.Counts{IngressAllowed: report.IngressAllowed, IngressProhibited: report.IngressDenied, Replies: report.Replies, EgressAllowed: traffic.Egress[0].Load(), EgressProhibited: traffic.Egress[1].Load(), IngressBlocked: blocked(1), EgressBlocked: blocked(0)}
	}
	sample := restartproof.Sample{Mode: mode, CgroupID: stat.Ino, PolicyEpochBefore: kernelEpoch(), AgentEpochBefore: agentEpoch()}
	traffic.Begin()
	time.Sleep(500 * time.Millisecond)
	sample.Before = counts()
	outageStarted := time.Now()
	switch mode {
	case "SIGTERM":
		if err := current.Process.Signal(syscall.SIGTERM); err != nil {
			t.Fatal(err)
		}
		if err := current.Wait(); err != nil {
			t.Fatal(err)
		}
	case "SIGSTOP":
		if err := current.Process.Signal(syscall.SIGSTOP); err != nil {
			t.Fatal(err)
		}
	default:
		if err := current.Process.Kill(); err != nil {
			t.Fatal(err)
		}
		_ = current.Wait()
	}
	time.Sleep(1500 * time.Millisecond)
	if mode == "SIGSTOP" {
		_ = current.Process.Kill()
		_ = current.Wait()
	}
	replacement, ready, release := start(apiOutage)
	if apiOutage {
		// The recovered epoch is visible while the replacement cannot list/watch
		// any Kubernetes resource and its readiness remains degraded.
		time.Sleep(1500 * time.Millisecond)
	}
	sample.OutageMS = float64(time.Since(outageStarted)) / float64(time.Millisecond)
	sample.During = counts()
	sample.AgentEpochAfter = agentEpoch()
	if apiOutage {
		if _, err := release.Write([]byte{'r'}); err != nil {
			t.Fatal(err)
		}
		_ = ready.SetReadDeadline(time.Now().Add(30 * time.Second))
		if _, err := io.ReadFull(ready, make([]byte, 1)); err != nil {
			t.Fatal(err)
		}
	}
	sample.PolicyEpochAfter = kernelEpoch()
	time.Sleep(500 * time.Millisecond)
	sample.After = counts()
	if err := restartproof.ValidateSamples([]restartproof.Sample{sample}, 1, mode); err != nil {
		t.Fatal(err)
	}
	if err := replacement.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if err := replacement.Wait(); err != nil {
		t.Fatal(err)
	}
	t.Logf("agent-continuity-v2 mode=%s cgroup=%d outage_ms=%.2f before=%+v during=%+v after=%+v", mode, sample.CgroupID, sample.OutageMS, sample.Before, sample.During, sample.After)
	return sample
}

func TestPhase5AgentRestartContinuity(t *testing.T) {
	if os.Getenv("ZTAP_PHASE5_PERFORMANCE") != "1" {
		t.Skip("performance harness")
	}
	samples := make([]restartproof.Sample, 0, phase5AgentRestartSamples)
	for index := 0; index < phase5AgentRestartSamples; index++ {
		t.Run(strconv.Itoa(index), func(t *testing.T) {
			samples = append(samples, runAgentContinuitySample(t, "SIGTERM", 200000+index, false))
		})
	}
	if len(samples) != phase5AgentRestartSamples {
		t.Fatal("continuity samples incomplete")
	}
	writePhase5AgentRestartEvidence(t, phase5AgentRestartEvidence{SchemaVersion: restartproof.EvidenceVersion, Continuity: samples, TimestampUTC: time.Now().UTC().Format(time.RFC3339Nano), RunID: phase5AgentRunID(t), GoVersion: runtime.Version(), GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, CPUs: runtime.NumCPU(), KernelRelease: phase5AgentKernelRelease(t), Subjects: 1, Policies: 1, Rules: 2, Scope: restartproof.ContinuityScope})
}
func TestPhase5AgentCrashContinuity(t *testing.T) {
	if os.Getenv("ZTAP_PHASE5_PERFORMANCE") != "1" {
		t.Skip("performance harness")
	}
	samples := make([]restartproof.Sample, 0, phase5AgentCrashSamples)
	for index := 0; index < phase5AgentCrashSamples; index++ {
		t.Run(strconv.Itoa(index), func(t *testing.T) {
			samples = append(samples, runAgentContinuitySample(t, "SIGKILL", 201000+index, true))
		})
	}
	if len(samples) != phase5AgentCrashSamples {
		t.Fatal("continuity samples incomplete")
	}
	writePhase5AgentCrashEvidence(t, phase5AgentCrashEvidence{SchemaVersion: restartproof.EvidenceVersion, Continuity: samples, Samples: len(samples), TimestampUTC: time.Now().UTC().Format(time.RFC3339Nano), RunID: phase5AgentRunID(t), GoVersion: runtime.Version(), GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, CPUs: runtime.NumCPU(), KernelRelease: phase5AgentKernelRelease(t), Subjects: 1, Policies: 1, Rules: 2, Scope: restartproof.ContinuityScope})
}
func TestLinuxNativeAgentOutageContinuity(t *testing.T) {
	for index, mode := range []string{"SIGTERM", "SIGKILL", "SIGSTOP"} {
		t.Run(mode, func(t *testing.T) { runAgentContinuitySample(t, mode, 202000+index, mode == "SIGKILL") })
	}
}
