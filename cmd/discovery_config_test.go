package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ztap/pkg/discovery"
)

func resetDiscoveryState() {
	globalDiscovery = nil
}

func TestGetDiscoveryBackendDefaultsToInMemory(t *testing.T) {
	t.Cleanup(resetDiscoveryState)
	resetDiscoveryState()
	t.Setenv("ZTAP_CONFIG", filepath.Join(t.TempDir(), "missing.yaml"))

	backend, err := getDiscoveryBackend()
	if err != nil {
		t.Fatalf("getDiscoveryBackend returned error: %v", err)
	}

	if _, ok := backend.(*discovery.InMemoryDiscovery); !ok {
		t.Fatalf("expected in-memory discovery backend, got %T", backend)
	}
}

func TestGetDiscoveryBackendFromConfig(t *testing.T) {
	t.Cleanup(resetDiscoveryState)
	resetDiscoveryState()

	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	configYAML := `
discovery:
  backend: dns
  dns:
    domain: example.com
  cache:
    ttl: 1s
`
	if err := os.WriteFile(configPath, []byte(configYAML), 0o644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	t.Setenv("ZTAP_CONFIG", configPath)

	backend, err := getDiscoveryBackend()
	if err != nil {
		t.Fatalf("getDiscoveryBackend returned error: %v", err)
	}

	cacheBackend, ok := backend.(*discovery.CacheDiscovery)
	if !ok {
		t.Fatalf("expected cached backend, got %T", backend)
	}

	err = cacheBackend.RegisterService("svc", "127.0.0.1", nil)
	if err == nil || !strings.Contains(err.Error(), "does not support registration") {
		t.Fatalf("expected DNS backend registration error, got %v", err)
	}
}
