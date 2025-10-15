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
		DestIP:   ipToUint32(targetIP),
		DestPort: 443,
		Protocol: protocolToNum("TCP"),
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

	egressRule := struct {
		To struct {
			PodSelector struct {
				MatchLabels map[string]string "yaml:\"matchLabels\""
			} "yaml:\"podSelector,omitempty\""
			IPBlock struct {
				CIDR string "yaml:\"cidr\""
			} "yaml:\"ipBlock,omitempty\""
		} "yaml:\"to\""
		Ports []struct {
			Protocol string "yaml:\"protocol\""
			Port     int    "yaml:\"port\""
		} "yaml:\"ports\""
	}{}

	egressRule.To.IPBlock.CIDR = cidr
	egressRule.Ports = append(egressRule.Ports, struct {
		Protocol string "yaml:\"protocol\""
		Port     int    "yaml:\"port\""
	}{
		Protocol: "TCP",
		Port:     port,
	})

	policyObj.Spec.Egress = append(policyObj.Spec.Egress, egressRule)
	return policyObj
}
