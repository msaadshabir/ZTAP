//go:build linux && integration
// +build linux,integration

package enforcer

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"ztap/pkg/policy"
)

// TestEBPFIntegrationLoadAndAttach verifies that the compiled eBPF program loads,
// populates the policy map, and attaches to a real Linux cgroup. Requires root.
func TestEBPFIntegrationLoadAndAttach(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("integration test only runs on Linux")
	}

	if os.Geteuid() != 0 {
		t.Skip("requires root privileges; re-run with sudo or CAP_BPF + CAP_NET_ADMIN")
	}

	compileTestBPF(t)

	enf, err := NewEBPFEnforcer()
	if err != nil {
		t.Fatalf("failed to create enforcer: %v", err)
	}
	t.Cleanup(func() {
		if err := enf.Close(); err != nil {
			t.Errorf("failed to close enforcer: %v", err)
		}
	})

	policies := []policy.NetworkPolicy{allowTCPPolicy("allow-web", "10.1.2.0/24", 443)}
	if err := enf.LoadPolicies(policies); err != nil {
		t.Fatalf("failed to load policies: %v", err)
	}

	cgroupPath := createTestCgroup(t)
	if err := enf.Attach(cgroupPath); err != nil {
		t.Fatalf("failed to attach program: %v", err)
	}

	targetIP := net.ParseIP("10.1.2.0").To4()
	if targetIP == nil {
		t.Fatal("failed to parse target IPv4 address")
	}

	key := policyKey{
		IP:        ipToUint32(targetIP),
		Port:      443,
		Protocol:  protocolToNum("TCP"),
		Direction: DirectionEgress,
	}
	var value policyValue
	if err := enf.objs.PolicyMap.Lookup(&key, &value); err != nil {
		t.Fatalf("failed to lookup policy map: %v", err)
	}

	if value.Action != 1 {
		t.Fatalf("expected allow action (1), got %d", value.Action)
	}
}

func compileTestBPF(t *testing.T) {
	t.Helper()

	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("unable to determine caller path")
	}

	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", ".."))
	cmd := exec.Command("make")
	cmd.Dir = filepath.Join(repoRoot, "bpf")
	cmd.Env = append(os.Environ(), "BPF_CLANG=clang", "BPF_LLVM_STRIP=llvm-strip")

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to build eBPF program: %v\n%s", err, string(output))
	}

	// Set override so the enforcer uses the fresh build instead of embedded bytecode
	os.Setenv("ZTAP_BPF_OBJECT", filepath.Join(repoRoot, "bpf", "filter.o"))
	t.Cleanup(func() {
		os.Unsetenv("ZTAP_BPF_OBJECT")
	})
}

func createTestCgroup(t *testing.T) string {
	t.Helper()

	name := fmt.Sprintf("ztap-test-%d", time.Now().UnixNano())
	path := filepath.Join("/sys/fs/cgroup", name)

	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatalf("failed to create test cgroup %s: %v", path, err)
	}

	t.Cleanup(func() {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			t.Errorf("failed to remove test cgroup %s: %v", path, err)
		}
	})

	return path
}

func allowTCPPolicy(name, cidr string, port int) policy.NetworkPolicy {
	policyObj := policy.NetworkPolicy{
		APIVersion: "ztap/v1",
		Kind:       "NetworkPolicy",
	}
	policyObj.Metadata.Name = name
	policyObj.Spec.PodSelector.MatchLabels = map[string]string{"app": "test"}

	egressRule := policy.EgressRule{
		To: policy.EgressTarget{
			IPBlock: policy.IPBlockSpec{CIDR: cidr},
		},
		Ports: []policy.PortSpec{
			{Protocol: "TCP", Port: port},
		},
	}

	policyObj.Spec.Egress = append(policyObj.Spec.Egress, egressRule)
	return policyObj
}

// TestEBPFGracefulReload verifies that updating policies via EnforceWithEBPFReal
// works without error and updates existing rules.
func TestEBPFGracefulReload(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("integration test only runs on Linux")
	}

	if os.Geteuid() != 0 {
		t.Skip("requires root privileges")
	}

	compileTestBPF(t)

	cgroupPath := createTestCgroup(t)
	defer StopEBPFEnforcement() // Ensure we clean up active enforcement

	// Step 1: Initial enforcement
	p1 := allowTCPPolicy("policy-1", "10.0.0.1/32", 80)
	opts1 := EnforcementOptions{
		Policies:   []policy.NetworkPolicy{p1},
		CgroupPath: cgroupPath,
	}

	if err := EnforceWithEBPFReal(opts1); err != nil {
		t.Fatalf("Initial enforcement failed: %v", err)
	}

	// Capture initial enforcer and its members
	enf1 := activeEBPFEnforcer
	if enf1 == nil {
		t.Fatal("activeEBPFEnforcer is nil after initial enforcement")
	}
	if enf1.egressLink == nil {
		t.Fatal("egressLink is nil")
	}

	// Step 2: Graceful reload with different policy
	p2 := allowTCPPolicy("policy-1", "10.0.0.2/32", 443)
	opts2 := EnforcementOptions{
		Policies:   []policy.NetworkPolicy{p2},
		CgroupPath: cgroupPath,
	}

	if err := EnforceWithEBPFReal(opts2); err != nil {
		t.Fatalf("Graceful reload failed: %v", err)
	}

	enf2 := activeEBPFEnforcer
	if enf2 == nil {
		t.Fatal("activeEBPFEnforcer is nil after reload")
	}

	if enf2 == enf1 {
		t.Fatal("activeEBPFEnforcer did not change after reload")
	}

	// Verify that ownership of the link was transferred
	if enf1.egressLink != nil {
		t.Error("old enforcer still owns egressLink")
	}
	if enf2.egressLink == nil {
		t.Error("new enforcer does not own egressLink")
	}

	// Step 3: Verify the map content of the new enforcer
	key := policyKey{
		IP:        ipToUint32(net.ParseIP("10.0.0.2")),
		Port:      443,
		Protocol:  protocolToNum("TCP"),
		Direction: DirectionEgress,
	}
	var val policyValue
	if err := enf2.objs.PolicyMap.Lookup(&key, &val); err != nil {
		t.Fatalf("New policy rule not found in map: %v", err)
	}
	if val.Action != 1 {
		t.Errorf("Expected action 1, got %d", val.Action)
	}

	// Verify old rule is NOT in the new map
	oldKey := policyKey{
		IP:        ipToUint32(net.ParseIP("10.0.0.1")),
		Port:      80,
		Protocol:  protocolToNum("TCP"),
		Direction: DirectionEgress,
	}
	if err := enf2.objs.PolicyMap.Lookup(&oldKey, &val); err == nil {
		t.Error("Old policy rule still exists in the new map")
	}
}
