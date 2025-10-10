package tests

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"ztap/pkg/discovery"
	"ztap/pkg/policy"
)

// TestPolicyDiscoveryIntegration tests the integration between policy engine and service discovery
func TestPolicyDiscoveryIntegration(t *testing.T) {
	// Setup service discovery
	disc := discovery.NewInMemoryDiscovery()

	// Register services
	disc.RegisterService("web-1", "10.0.1.1", map[string]string{"app": "web", "tier": "frontend"})
	disc.RegisterService("web-2", "10.0.1.2", map[string]string{"app": "web", "tier": "frontend"})
	disc.RegisterService("db-1", "10.0.2.1", map[string]string{"app": "database", "tier": "backend"})

	// Create policy resolver
	resolver := policy.NewPolicyResolver(disc)

	// Test resolving web services
	ips, err := resolver.ResolveLabels(map[string]string{"app": "web"})
	if err != nil {
		t.Fatalf("Failed to resolve web services: %v", err)
	}

	if len(ips) != 2 {
		t.Errorf("Expected 2 web service IPs, got %d", len(ips))
	}

	// Test resolving database services
	ips, err = resolver.ResolveLabels(map[string]string{"app": "database"})
	if err != nil {
		t.Fatalf("Failed to resolve database services: %v", err)
	}

	if len(ips) != 1 {
		t.Errorf("Expected 1 database service IP, got %d", len(ips))
	}

	if ips[0] != "10.0.2.1" {
		t.Errorf("Expected database IP 10.0.2.1, got %s", ips[0])
	}
}

// TestPolicyLoadAndValidate tests loading and validating policies
func TestPolicyLoadAndValidate(t *testing.T) {
	// Create temp policy file
	tmpDir := t.TempDir()
	policyFile := filepath.Join(tmpDir, "test-policy.yaml")

	policyContent := `
apiVersion: ztap/v1
kind: NetworkPolicy
metadata:
  name: web-to-db
spec:
  podSelector:
    matchLabels:
      app: web
  egress:
    - to:
        ipBlock:
          cidr: 10.0.2.0/24
      ports:
        - protocol: TCP
          port: 5432
`
	err := os.WriteFile(policyFile, []byte(policyContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write policy file: %v", err)
	}

	// Load policy
	policies, err := policy.LoadFromFile(policyFile)
	if err != nil {
		t.Fatalf("Failed to load policy: %v", err)
	}

	if len(policies) != 1 {
		t.Fatalf("Expected 1 policy, got %d", len(policies))
	}

	// Validate policy
	pol := policies[0]
	err = pol.Validate()
	if err != nil {
		t.Errorf("Policy validation failed: %v", err)
	}

	// Verify policy details
	if pol.Metadata.Name != "web-to-db" {
		t.Errorf("Expected policy name 'web-to-db', got '%s'", pol.Metadata.Name)
	}

	if pol.Spec.PodSelector.MatchLabels["app"] != "web" {
		t.Errorf("Expected podSelector app=web, got %s", pol.Spec.PodSelector.MatchLabels["app"])
	}

	if len(pol.Spec.Egress) != 1 {
		t.Fatalf("Expected 1 egress rule, got %d", len(pol.Spec.Egress))
	}

	egress := pol.Spec.Egress[0]
	if egress.To.IPBlock.CIDR != "10.0.2.0/24" {
		t.Errorf("Expected CIDR 10.0.2.0/24, got %s", egress.To.IPBlock.CIDR)
	}

	if egress.Ports[0].Protocol != "TCP" || egress.Ports[0].Port != 5432 {
		t.Errorf("Expected TCP port 5432, got %s port %d",
			egress.Ports[0].Protocol, egress.Ports[0].Port)
	}
}

// TestDiscoveryWithCache tests caching layer on service discovery
func TestDiscoveryWithCache(t *testing.T) {
	// Create backend discovery
	backend := discovery.NewInMemoryDiscovery()
	backend.RegisterService("web-1", "10.0.1.1", map[string]string{"app": "web"})

	// Create cached discovery with short TTL
	cached := discovery.NewCacheDiscovery(backend, 500*time.Millisecond)

	// First resolution (cache miss)
	start := time.Now()
	ips1, err := cached.ResolveLabels(map[string]string{"app": "web"})
	duration1 := time.Since(start)

	if err != nil {
		t.Fatalf("Failed to resolve: %v", err)
	}

	if len(ips1) != 1 {
		t.Errorf("Expected 1 IP, got %d", len(ips1))
	}

	// Second resolution (cache hit - should be faster)
	start = time.Now()
	ips2, err := cached.ResolveLabels(map[string]string{"app": "web"})
	duration2 := time.Since(start)

	if err != nil {
		t.Fatalf("Failed to resolve: %v", err)
	}

	if len(ips2) != 1 {
		t.Errorf("Expected 1 IP, got %d", len(ips2))
	}

	// Cache hit should be faster (though this is not guaranteed on all systems)
	if duration2 > duration1 {
		t.Logf("Warning: Cached resolution (%v) was slower than first resolution (%v)",
			duration2, duration1)
	}

	// Add new service
	backend.RegisterService("web-2", "10.0.1.2", map[string]string{"app": "web"})

	// Still gets cached result
	ips3, err := cached.ResolveLabels(map[string]string{"app": "web"})
	if err != nil {
		t.Fatalf("Failed to resolve: %v", err)
	}

	if len(ips3) != 1 {
		t.Errorf("Expected cached result with 1 IP, got %d", len(ips3))
	}

	// Wait for cache expiration
	time.Sleep(600 * time.Millisecond)

	// Now should get updated result
	ips4, err := cached.ResolveLabels(map[string]string{"app": "web"})
	if err != nil {
		t.Fatalf("Failed to resolve: %v", err)
	}

	if len(ips4) != 2 {
		t.Errorf("Expected updated result with 2 IPs, got %d", len(ips4))
	}
}

// TestDynamicServiceUpdates tests watching for service changes
func TestDynamicServiceUpdates(t *testing.T) {
	disc := discovery.NewInMemoryDiscovery()

	// Register initial service
	disc.RegisterService("web-1", "10.0.1.1", map[string]string{"app": "web"})

	// Start watching
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ch, err := disc.Watch(ctx, map[string]string{"app": "web"})
	if err != nil {
		t.Fatalf("Failed to start watch: %v", err)
	}

	// Get initial state
	select {
	case ips := <-ch:
		if len(ips) != 1 {
			t.Errorf("Expected 1 IP initially, got %d", len(ips))
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Timeout waiting for initial state")
	}

	// Add service in goroutine to simulate dynamic update
	go func() {
		time.Sleep(100 * time.Millisecond)
		disc.RegisterService("web-2", "10.0.1.2", map[string]string{"app": "web"})
	}()

	// Wait for update notification
	select {
	case ips := <-ch:
		if len(ips) != 2 {
			t.Errorf("Expected 2 IPs after update, got %d", len(ips))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for update notification")
	}

	// Remove service
	go func() {
		time.Sleep(100 * time.Millisecond)
		disc.DeregisterService("web-1")
	}()

	// Wait for removal notification
	select {
	case ips := <-ch:
		if len(ips) != 1 {
			t.Errorf("Expected 1 IP after removal, got %d", len(ips))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for removal notification")
	}
}

// TestMultiplePoliciesWithDiscovery tests handling multiple policies with service discovery
func TestMultiplePoliciesWithDiscovery(t *testing.T) {
	// Setup discovery
	disc := discovery.NewInMemoryDiscovery()
	disc.RegisterService("web-1", "10.0.1.1", map[string]string{"app": "web", "env": "prod"})
	disc.RegisterService("web-2", "10.0.1.2", map[string]string{"app": "web", "env": "dev"})
	disc.RegisterService("db-1", "10.0.2.1", map[string]string{"app": "database", "env": "prod"})

	resolver := policy.NewPolicyResolver(disc)

	// Test various label queries
	tests := []struct {
		name          string
		labels        map[string]string
		expectedCount int
	}{
		{"all web services", map[string]string{"app": "web"}, 2},
		{"prod web service", map[string]string{"app": "web", "env": "prod"}, 1},
		{"dev web service", map[string]string{"app": "web", "env": "dev"}, 1},
		{"all databases", map[string]string{"app": "database"}, 1},
		{"prod services", map[string]string{"env": "prod"}, 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ips, err := resolver.ResolveLabels(tt.labels)
			if err != nil {
				t.Fatalf("Failed to resolve: %v", err)
			}

			if len(ips) != tt.expectedCount {
				t.Errorf("Expected %d IPs, got %d", tt.expectedCount, len(ips))
			}
		})
	}
}

// TestPolicyValidationErrors tests various policy validation scenarios
func TestPolicyValidationErrors(t *testing.T) {
	tmpDir := t.TempDir()

	tests := []struct {
		name        string
		content     string
		expectError bool
	}{
		{
			name: "valid policy",
			content: `
apiVersion: ztap/v1
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
          cidr: 10.0.0.0/8
      ports:
        - protocol: TCP
          port: 443
`,
			expectError: false,
		},
		{
			name: "invalid CIDR",
			content: `
apiVersion: ztap/v1
kind: NetworkPolicy
metadata:
  name: invalid-cidr
spec:
  podSelector:
    matchLabels:
      app: web
  egress:
    - to:
        ipBlock:
          cidr: not-a-cidr
      ports:
        - protocol: TCP
          port: 443
`,
			expectError: true,
		},
		{
			name: "invalid port",
			content: `
apiVersion: ztap/v1
kind: NetworkPolicy
metadata:
  name: invalid-port
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
          port: 999999
`,
			expectError: true,
		},
		{
			name: "invalid protocol",
			content: `
apiVersion: ztap/v1
kind: NetworkPolicy
metadata:
  name: invalid-protocol
spec:
  podSelector:
    matchLabels:
      app: web
  egress:
    - to:
        ipBlock:
          cidr: 10.0.0.0/8
      ports:
        - protocol: HTTP
          port: 80
`,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policyFile := filepath.Join(tmpDir, tt.name+".yaml")
			err := os.WriteFile(policyFile, []byte(tt.content), 0644)
			if err != nil {
				t.Fatalf("Failed to write policy file: %v", err)
			}

			policies, err := policy.LoadFromFile(policyFile)
			if err != nil {
				t.Fatalf("Failed to load policy: %v", err)
			}

			if len(policies) == 0 {
				t.Fatal("No policies loaded")
			}

			err = policies[0].Validate()
			if tt.expectError && err == nil {
				t.Error("Expected validation error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected validation error: %v", err)
			}
		})
	}
}
