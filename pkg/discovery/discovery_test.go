package discovery

import (
	"context"
	"testing"
	"time"
)

func TestInMemoryDiscovery_RegisterAndResolve(t *testing.T) {
	disc := NewInMemoryDiscovery()

	// Register services
	err := disc.RegisterService("web-1", "10.0.1.1", map[string]string{
		"app":  "web",
		"tier": "frontend",
	})
	if err != nil {
		t.Fatalf("Failed to register service: %v", err)
	}

	err = disc.RegisterService("web-2", "10.0.1.2", map[string]string{
		"app":  "web",
		"tier": "frontend",
	})
	if err != nil {
		t.Fatalf("Failed to register service: %v", err)
	}

	err = disc.RegisterService("db-1", "10.0.2.1", map[string]string{
		"app":  "database",
		"tier": "backend",
	})
	if err != nil {
		t.Fatalf("Failed to register service: %v", err)
	}

	// Resolve by app label
	ips, err := disc.ResolveLabels(map[string]string{"app": "web"})
	if err != nil {
		t.Fatalf("Failed to resolve labels: %v", err)
	}

	if len(ips) != 2 {
		t.Errorf("Expected 2 IPs, got %d", len(ips))
	}

	// Resolve by multiple labels
	ips, err = disc.ResolveLabels(map[string]string{
		"app":  "web",
		"tier": "frontend",
	})
	if err != nil {
		t.Fatalf("Failed to resolve labels: %v", err)
	}

	if len(ips) != 2 {
		t.Errorf("Expected 2 IPs, got %d", len(ips))
	}

	// Resolve database
	ips, err = disc.ResolveLabels(map[string]string{"app": "database"})
	if err != nil {
		t.Fatalf("Failed to resolve labels: %v", err)
	}

	if len(ips) != 1 {
		t.Errorf("Expected 1 IP, got %d", len(ips))
	}

	if ips[0] != "10.0.2.1" {
		t.Errorf("Expected IP 10.0.2.1, got %s", ips[0])
	}
}

func TestInMemoryDiscovery_NoMatch(t *testing.T) {
	disc := NewInMemoryDiscovery()

	disc.RegisterService("web-1", "10.0.1.1", map[string]string{"app": "web"})

	// Try to resolve non-existent label
	_, err := disc.ResolveLabels(map[string]string{"app": "database"})
	if err == nil {
		t.Error("Expected error for non-existent label")
	}
}

func TestInMemoryDiscovery_InvalidIP(t *testing.T) {
	disc := NewInMemoryDiscovery()

	err := disc.RegisterService("invalid", "not-an-ip", map[string]string{"app": "test"})
	if err == nil {
		t.Error("Expected error for invalid IP")
	}
}

func TestInMemoryDiscovery_Deregister(t *testing.T) {
	disc := NewInMemoryDiscovery()

	disc.RegisterService("web-1", "10.0.1.1", map[string]string{"app": "web"})
	disc.RegisterService("web-2", "10.0.1.2", map[string]string{"app": "web"})

	// Verify 2 services
	ips, _ := disc.ResolveLabels(map[string]string{"app": "web"})
	if len(ips) != 2 {
		t.Errorf("Expected 2 IPs before deregister, got %d", len(ips))
	}

	// Deregister one
	err := disc.DeregisterService("web-1")
	if err != nil {
		t.Fatalf("Failed to deregister: %v", err)
	}

	// Verify only 1 remains
	ips, _ = disc.ResolveLabels(map[string]string{"app": "web"})
	if len(ips) != 1 {
		t.Errorf("Expected 1 IP after deregister, got %d", len(ips))
	}

	if ips[0] != "10.0.1.2" {
		t.Errorf("Expected IP 10.0.1.2, got %s", ips[0])
	}
}

func TestInMemoryDiscovery_ListServices(t *testing.T) {
	disc := NewInMemoryDiscovery()

	disc.RegisterService("web-1", "10.0.1.1", map[string]string{"app": "web"})
	disc.RegisterService("db-1", "10.0.2.1", map[string]string{"app": "database"})

	services := disc.ListServices()
	if len(services) != 2 {
		t.Errorf("Expected 2 services, got %d", len(services))
	}

	// Verify service details
	foundWeb := false
	foundDB := false
	for _, svc := range services {
		if svc.Name == "web-1" {
			foundWeb = true
			if svc.IP != "10.0.1.1" {
				t.Errorf("Expected IP 10.0.1.1, got %s", svc.IP)
			}
			if svc.Labels["app"] != "web" {
				t.Errorf("Expected app=web, got %s", svc.Labels["app"])
			}
		}
		if svc.Name == "db-1" {
			foundDB = true
		}
	}

	if !foundWeb || !foundDB {
		t.Error("Not all services found in list")
	}
}

func TestInMemoryDiscovery_Watch(t *testing.T) {
	disc := NewInMemoryDiscovery()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Register initial service
	disc.RegisterService("web-1", "10.0.1.1", map[string]string{"app": "web"})

	// Start watching
	ch, err := disc.Watch(ctx, map[string]string{"app": "web"})
	if err != nil {
		t.Fatalf("Failed to start watch: %v", err)
	}

	// Get initial state
	select {
	case ips := <-ch:
		if len(ips) != 1 {
			t.Errorf("Expected 1 IP in initial state, got %d", len(ips))
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Timeout waiting for initial state")
	}

	// Register another service
	disc.RegisterService("web-2", "10.0.1.2", map[string]string{"app": "web"})

	// Wait for update
	select {
	case ips := <-ch:
		if len(ips) != 2 {
			t.Errorf("Expected 2 IPs after registration, got %d", len(ips))
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Timeout waiting for update")
	}

	// Cancel context and verify channel closes
	cancel()
	time.Sleep(100 * time.Millisecond)

	select {
	case _, ok := <-ch:
		if ok {
			t.Error("Expected channel to be closed")
		}
	default:
		t.Error("Expected channel to be closed")
	}
}

func TestDNSDiscovery(t *testing.T) {
	disc := NewDNSDiscovery("example.com")

	// DNS discovery doesn't support registration
	err := disc.RegisterService("test", "10.0.1.1", map[string]string{"app": "test"})
	if err == nil {
		t.Error("Expected error for registration on DNS discovery")
	}

	err = disc.DeregisterService("test")
	if err == nil {
		t.Error("Expected error for deregistration on DNS discovery")
	}
}

func TestCacheDiscovery(t *testing.T) {
	backend := NewInMemoryDiscovery()
	backend.RegisterService("web-1", "10.0.1.1", map[string]string{"app": "web"})

	cache := NewCacheDiscovery(backend, 1*time.Second)

	// First resolution (cache miss)
	ips1, err := cache.ResolveLabels(map[string]string{"app": "web"})
	if err != nil {
		t.Fatalf("Failed to resolve: %v", err)
	}

	// Second resolution (cache hit)
	ips2, err := cache.ResolveLabels(map[string]string{"app": "web"})
	if err != nil {
		t.Fatalf("Failed to resolve: %v", err)
	}

	if len(ips1) != len(ips2) {
		t.Error("Cached result differs from original")
	}

	// Register new service
	backend.RegisterService("web-2", "10.0.1.2", map[string]string{"app": "web"})

	// Still gets cached result (1 IP)
	ips3, err := cache.ResolveLabels(map[string]string{"app": "web"})
	if err != nil {
		t.Fatalf("Failed to resolve: %v", err)
	}

	if len(ips3) != 1 {
		t.Errorf("Expected cached result with 1 IP, got %d", len(ips3))
	}

	// Wait for cache to expire
	time.Sleep(1100 * time.Millisecond)

	// Now gets fresh result (2 IPs)
	ips4, err := cache.ResolveLabels(map[string]string{"app": "web"})
	if err != nil {
		t.Fatalf("Failed to resolve: %v", err)
	}

	if len(ips4) != 2 {
		t.Errorf("Expected fresh result with 2 IPs, got %d", len(ips4))
	}
}

func TestCacheDiscovery_ClearCache(t *testing.T) {
	backend := NewInMemoryDiscovery()
	backend.RegisterService("web-1", "10.0.1.1", map[string]string{"app": "web"})

	cache := NewCacheDiscovery(backend, 10*time.Second)

	// Populate cache
	cache.ResolveLabels(map[string]string{"app": "web"})

	// Add new service
	backend.RegisterService("web-2", "10.0.1.2", map[string]string{"app": "web"})

	// Clear cache
	cache.ClearCache()

	// Should get fresh result
	ips, err := cache.ResolveLabels(map[string]string{"app": "web"})
	if err != nil {
		t.Fatalf("Failed to resolve: %v", err)
	}

	if len(ips) != 2 {
		t.Errorf("Expected 2 IPs after cache clear, got %d", len(ips))
	}
}

func TestMatchLabels(t *testing.T) {
	tests := []struct {
		name          string
		serviceLabels map[string]string
		selector      map[string]string
		expectedMatch bool
	}{
		{
			name:          "exact match",
			serviceLabels: map[string]string{"app": "web", "tier": "frontend"},
			selector:      map[string]string{"app": "web"},
			expectedMatch: true,
		},
		{
			name:          "multiple label match",
			serviceLabels: map[string]string{"app": "web", "tier": "frontend", "env": "prod"},
			selector:      map[string]string{"app": "web", "tier": "frontend"},
			expectedMatch: true,
		},
		{
			name:          "no match",
			serviceLabels: map[string]string{"app": "web"},
			selector:      map[string]string{"app": "database"},
			expectedMatch: false,
		},
		{
			name:          "partial match fails",
			serviceLabels: map[string]string{"app": "web"},
			selector:      map[string]string{"app": "web", "tier": "frontend"},
			expectedMatch: false,
		},
		{
			name:          "empty selector matches all",
			serviceLabels: map[string]string{"app": "web"},
			selector:      map[string]string{},
			expectedMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := matchLabels(tt.serviceLabels, tt.selector)
			if result != tt.expectedMatch {
				t.Errorf("Expected %v, got %v", tt.expectedMatch, result)
			}
		})
	}
}
