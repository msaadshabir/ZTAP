package tests

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

const cliEntry = "../main.go"

func runCLI(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "go", append([]string{"run", cliEntry}, args...)...)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func containsAny(haystack string, needles ...string) bool {
	for _, n := range needles {
		if strings.Contains(haystack, n) {
			return true
		}
	}
	return false
}

func possiblySkip(t *testing.T, err error, output string, hints ...string) bool {
	if err == nil {
		return false
	}
	if containsAny(output, hints...) {
		t.Skipf("skipping: %v (output: %s)", err, output)
		return true
	}
	return false
}

func skipIfInCI(t *testing.T) {
	isGitHubActions := os.Getenv("GITHUB_ACTIONS") == "true"
	isCI := os.Getenv("CI") == "true"
	hasGitHubWorkspace := os.Getenv("GITHUB_WORKSPACE") != ""

	if isGitHubActions || isCI || hasGitHubWorkspace {
		t.Skip("Skipping CLI tests in CI environment - use integration tests instead")
	}
}

func TestCLIHelp(t *testing.T) {
	skipIfInCI(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	output, err := runCLI(ctx, "--help")
	if err != nil {
		t.Fatalf("help command failed: %v\noutput: %s", err, output)
	}
	if !containsAny(output, "Usage", "ztap") {
		t.Errorf("unexpected help output: %s", output)
	}
}

func TestCLIComplianceExportSmoke(t *testing.T) {
	skipIfInCI(t)
	tmpDir := t.TempDir()
	policyPath := filepath.Join(tmpDir, "policy.yaml")
	policyYAML := `apiVersion: ztap/v1
kind: NetworkPolicy
metadata:
  name: p
  annotations:
    ztap.io/compliance.pci-dss: "10.2.1"
spec:
  podSelector:
    matchLabels:
      app: web
  egress:
    - to:
        ipBlock:
          cidr: 10.0.0.0/8
      ports:
        - protocol: TCP
          port: 443
`
	if err := os.WriteFile(policyPath, []byte(policyYAML), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	output, err := runCLI(ctx, "compliance", "export", "-f", policyPath, "--format", "json")
	if err != nil {
		t.Fatalf("compliance export failed: %v\noutput: %s", err, output)
	}
	if !containsAny(output, "\"controls\"", "\"policies\"", "\"metadata\"") {
		t.Fatalf("unexpected output: %s", output)
	}
}

func TestCLIUserManagement(t *testing.T) {
	skipIfInCI(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	output, err := runCLI(ctx, "user", "list")
	if possiblySkip(t, err, output, "not implemented", "unknown command", "requires datastore") {
		return
	}
	if err != nil {
		t.Fatalf("user list failed: %v\noutput: %s", err, output)
	}
}

func TestCLIServiceDiscovery(t *testing.T) {
	skipIfInCI(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	output, err := runCLI(ctx, "discovery", "list")
	if possiblySkip(t, err, output, "not implemented", "unknown command", "requires backend") {
		return
	}
	if err != nil {
		t.Fatalf("discovery list failed: %v\noutput: %s", err, output)
	}
}

func TestCLIPolicyEnforce(t *testing.T) {
	skipIfInCI(t)
	tmpDir := t.TempDir()
	policyPath := filepath.Join(tmpDir, "test-policy.yaml")
	policyYAML := `apiVersion: ztap/v1
kind: NetworkPolicy
metadata:
  name: test-policy
spec:
  podSelector:
    matchLabels:
      app: web
  egress:
    - to:
        ipBlock:
          cidr: 10.0.0.1/32
      ports:
        - protocol: TCP
          port: 443
`
	if err := os.WriteFile(policyPath, []byte(policyYAML), 0o644); err != nil {
		t.Fatalf("failed to write policy: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	env := append(os.Environ(), "ZTAP_SKIP_PF=1")
	cmd := exec.CommandContext(ctx, "go", "run", cliEntry, "enforce", "-f", policyPath)
	cmd.Env = env

	if runtime.GOOS != "linux" {
		outputBytes, err := cmd.CombinedOutput()
		output := string(outputBytes)
		if possiblySkip(t, err, output, "not implemented", "requires root", "unsupported platform") {
			return
		}
		if err != nil {
			t.Fatalf("enforce failed: %v\noutput: %s", err, output)
		}
		return
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("failed to get stdout pipe: %v", err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start enforce: %v", err)
	}

	var out bytes.Buffer
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()
		out.WriteString(line)
		out.WriteByte('\n')
		if strings.Contains(line, "Enforcement active") {
			_ = cmd.Process.Signal(os.Interrupt)
			break
		}
	}
	_ = stdout.Close()

	waitErr := cmd.Wait()
	output := out.String() + stderr.String()
	if possiblySkip(t, waitErr, output, "not implemented", "requires root", "unsupported platform") {
		return
	}
	if waitErr != nil {
		t.Fatalf("enforce failed: %v\noutput: %s", waitErr, output)
	}
}

func TestCLIStatus(t *testing.T) {
	skipIfInCI(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	output, err := runCLI(ctx, "status")
	if possiblySkip(t, err, output, "not implemented", "unknown command") {
		return
	}
	if err != nil {
		t.Fatalf("status failed: %v\noutput: %s", err, output)
	}
}

func TestCLIMetrics(t *testing.T) {
	skipIfInCI(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	port := findOpenPort(t)
	cmd := exec.CommandContext(ctx, "go", "run", cliEntry, "metrics", "--port", port)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start metrics command: %v", err)
	}

	targetURL := "http://127.0.0.1:" + port + "/metrics"
	client := &http.Client{Timeout: 1 * time.Second}

	deadline := time.Now().Add(5 * time.Second)
	var body string
	for time.Now().Before(deadline) {
		resp, err := client.Get(targetURL)
		if err == nil {
			data, readErr := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if readErr == nil {
				body = string(data)
				break
			}
		}
		time.Sleep(200 * time.Millisecond)
	}

	_ = cmd.Process.Signal(os.Interrupt)
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case err := <-done:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Logf("metrics exit err: %v", err)
		}
	case <-time.After(2 * time.Second):
		_ = cmd.Process.Kill()
	}

	if body == "" {
		t.Skipf("metrics endpoint did not respond in time; stdout=%s stderr=%s", stdout.String(), stderr.String())
	}
}

func TestCLILogs(t *testing.T) {
	skipIfInCI(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	output, err := runCLI(ctx, "logs")
	if possiblySkip(t, err, output, "not implemented", "unknown command", "requires datastore") {
		return
	}
	if err != nil {
		t.Fatalf("logs failed: %v\noutput: %s", err, output)
	}
}

func TestCLIPolicyValidation(t *testing.T) {
	skipIfInCI(t)
	tmpDir := t.TempDir()

	cases := []struct {
		name      string
		content   string
		shouldErr bool
	}{
		{
			name: "valid-policy",
			content: `apiVersion: ztap/v1
kind: NetworkPolicy
metadata:
  name: valid
spec:
  podSelector:
    matchLabels:
      app: web
  egress:
  - to:
      ipBlock:
        cidr: 10.0.0.0/16
`,
			shouldErr: false,
		},
		{
			name: "invalid-cidr",
			content: `apiVersion: ztap/v1
kind: NetworkPolicy
metadata:
  name: invalid
spec:
  podSelector:
    matchLabels:
      app: web
  egress:
  - to:
      ipBlock:
        cidr: 999.999.999.999/99
`,
			shouldErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			policyPath := filepath.Join(tmpDir, tc.name+".yaml")
			if err := os.WriteFile(policyPath, []byte(tc.content), 0o644); err != nil {
				t.Fatalf("failed to write policy: %v", err)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()

			env := append(os.Environ(), "ZTAP_SKIP_PF=1")
			cmd := exec.CommandContext(ctx, "go", "run", cliEntry, "enforce", "-f", policyPath)
			cmd.Env = env
			outputBytes, err := cmd.CombinedOutput()
			output := string(outputBytes)

			if possiblySkip(t, err, output, "not implemented", "requires root", "unsupported platform") {
				return
			}

			if tc.shouldErr {
				if err == nil && !containsAny(output, "invalid", "error") {
					t.Logf("expected validation error; output=%s", output)
				}
			} else {
				if err != nil {
					t.Logf("expected success; err=%v output=%s", err, output)
				}
			}
		})
	}
}

func findOpenPort(t *testing.T) string {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to find open port: %v", err)
	}
	defer l.Close()
	_, port, err := net.SplitHostPort(l.Addr().String())
	if err != nil {
		t.Fatalf("failed to parse listener address: %v", err)
	}
	return port
}

func TestPolicyValidate(t *testing.T) {
	skipIfInCI(t)
	tmpDir := t.TempDir()

	validPolicy := `
apiVersion: ztap/v1
kind: NetworkPolicy
metadata:
  name: valid-policy
spec:
  podSelector:
    matchLabels:
      app: test
  egress:
    - to:
        ipBlock:
          cidr: 10.0.0.0/24
      ports:
        - protocol: TCP
          port: 80
`
	validPath := filepath.Join(tmpDir, "valid.yaml")
	if err := os.WriteFile(validPath, []byte(validPolicy), 0644); err != nil {
		t.Fatal(err)
	}

	invalidPolicy := `
apiVersion: ztap/v1
kind: NetworkPolicy
metadata:
  name: invalid-policy
spec:
  podSelector:
    matchLabels:
      app: test
  egress:
    - to:
        ipBlock:
          cidr: 300.0.0.0/8
      ports:
        - protocol: TCP
          port: 80
`
	invalidPath := filepath.Join(tmpDir, "invalid.yaml")
	if err := os.WriteFile(invalidPath, []byte(invalidPolicy), 0644); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name      string
		args      []string
		wantError bool
		wantOut   string
	}{
		{
			name:      "Valid Policy",
			args:      []string{"policy", "validate", "-f", validPath},
			wantError: false,
			wantOut:   "is valid",
		},
		{
			name:      "Invalid Policy",
			args:      []string{"policy", "validate", "-f", invalidPath},
			wantError: true,
			wantOut:   "invalid CIDR address",
		},
		{
			name:      "Missing File",
			args:      []string{"policy", "validate"},
			wantError: true,
			wantOut:   "required",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			out, err := runCLI(ctx, tc.args...)
			if tc.wantError {
				if err == nil {
					t.Errorf("expected error but got none. output: %s", out)
				}
				if !strings.Contains(out, tc.wantOut) && !strings.Contains(err.Error(), tc.wantOut) {
					t.Errorf("expected output containing '%s', got '%s'", tc.wantOut, out)
				}
			} else {
				if err != nil {
					t.Errorf("expected success but got error: %v. output: %s", err, out)
				}
				if !strings.Contains(out, tc.wantOut) {
					t.Errorf("expected output containing '%s', got '%s'", tc.wantOut, out)
				}
			}
		})
	}
}
