package inventory

import (
	"os"
	"path/filepath"
	"testing"

	"ztap/internal/policy"
)

func TestInventoryMatchLabels(t *testing.T) {
	inv := &Inventory{
		Version:  "1.0",
		Provider: ProviderAWS,
		Resources: []Resource{
			{ID: "i-1", Name: "web-1", Labels: map[string]string{"app": "web", "env": "prod"}},
			{ID: "i-2", Name: "db-1", Labels: map[string]string{"app": "db", "env": "prod"}},
			{ID: "i-3", Name: "web-2", Labels: map[string]string{"app": "web", "env": "dev"}},
		},
	}

	// Test single label match
	selector := policy.PodSelectorSpec{
		MatchLabels: map[string]string{"app": "web"},
	}
	matched := inv.Match(selector)
	if len(matched) != 2 {
		t.Fatalf("expected 2 matches for app=web, got %d", len(matched))
	}

	// Test multiple label match
	selector = policy.PodSelectorSpec{
		MatchLabels: map[string]string{"app": "web", "env": "prod"},
	}
	matched = inv.Match(selector)
	if len(matched) != 1 {
		t.Fatalf("expected 1 match for app=web,env=prod, got %d", len(matched))
	}
	if matched[0].ID != "i-1" {
		t.Fatalf("expected i-1, got %s", matched[0].ID)
	}

	// Test no match
	selector = policy.PodSelectorSpec{
		MatchLabels: map[string]string{"app": "cache"},
	}
	matched = inv.Match(selector)
	if len(matched) != 0 {
		t.Fatalf("expected 0 matches for app=cache, got %d", len(matched))
	}
}

func TestInventoryMatchExpressions(t *testing.T) {
	inv := &Inventory{
		Version:  "1.0",
		Provider: ProviderAWS,
		Resources: []Resource{
			{ID: "i-1", Name: "web-1", Labels: map[string]string{"app": "web", "env": "prod"}},
			{ID: "i-2", Name: "db-1", Labels: map[string]string{"app": "db", "env": "prod"}},
			{ID: "i-3", Name: "web-2", Labels: map[string]string{"app": "web", "env": "dev"}},
			{ID: "i-4", Name: "cache-1", Labels: map[string]string{"app": "cache", "env": "staging"}},
		},
	}

	// Test "In" operator
	selector := policy.PodSelectorSpec{
		MatchExpressions: []policy.LabelSelectorRequirement{
			{Key: "env", Operator: "In", Values: []string{"prod", "dev"}},
		},
	}
	matched := inv.Match(selector)
	if len(matched) != 3 {
		t.Fatalf("expected 3 matches for env in (prod,dev), got %d", len(matched))
	}

	// Test "NotIn" operator
	selector = policy.PodSelectorSpec{
		MatchExpressions: []policy.LabelSelectorRequirement{
			{Key: "env", Operator: "NotIn", Values: []string{"prod"}},
		},
	}
	matched = inv.Match(selector)
	if len(matched) != 2 {
		t.Fatalf("expected 2 matches for env notin (prod), got %d", len(matched))
	}

	// Test "Exists" operator
	selector = policy.PodSelectorSpec{
		MatchExpressions: []policy.LabelSelectorRequirement{
			{Key: "app", Operator: "Exists"},
		},
	}
	matched = inv.Match(selector)
	if len(matched) != 4 {
		t.Fatalf("expected 4 matches for app exists, got %d", len(matched))
	}

	// Test "DoesNotExist" operator
	selector = policy.PodSelectorSpec{
		MatchExpressions: []policy.LabelSelectorRequirement{
			{Key: "tier", Operator: "DoesNotExist"},
		},
	}
	matched = inv.Match(selector)
	if len(matched) != 4 {
		t.Fatalf("expected 4 matches for tier doesnotexist, got %d", len(matched))
	}
}

func TestInventoryResolveIPs(t *testing.T) {
	inv := &Inventory{
		Version:  "1.0",
		Provider: ProviderAWS,
		Resources: []Resource{
			{ID: "i-1", Name: "web-1", PrivateIP: "10.0.0.1", PublicIP: "203.0.113.1", Labels: map[string]string{"app": "web"}},
			{ID: "i-2", Name: "web-2", PrivateIP: "10.0.0.2", PublicIP: "203.0.113.2", Labels: map[string]string{"app": "web"}},
			{ID: "i-3", Name: "db-1", PrivateIP: "10.0.0.3", Labels: map[string]string{"app": "db"}},
			{ID: "i-4", Name: "db-2", PublicIP: "203.0.113.4", Labels: map[string]string{"app": "db"}},
		},
	}

	selector := policy.PodSelectorSpec{
		MatchLabels: map[string]string{"app": "web"},
	}

	// Test private IP mode
	ips, err := inv.ResolveIPs(selector, IPModePrivate)
	if err != nil {
		t.Fatalf("ResolveIPs failed: %v", err)
	}
	if len(ips) != 2 {
		t.Fatalf("expected 2 private IPs, got %d", len(ips))
	}
	if ips[0] != "10.0.0.1" || ips[1] != "10.0.0.2" {
		t.Fatalf("unexpected IPs: %v", ips)
	}

	// Test public IP mode
	ips, err = inv.ResolveIPs(selector, IPModePublic)
	if err != nil {
		t.Fatalf("ResolveIPs failed: %v", err)
	}
	if len(ips) != 2 {
		t.Fatalf("expected 2 public IPs, got %d", len(ips))
	}

	// Test both IP mode
	ips, err = inv.ResolveIPs(selector, IPModeBoth)
	if err != nil {
		t.Fatalf("ResolveIPs failed: %v", err)
	}
	if len(ips) != 4 {
		t.Fatalf("expected 4 IPs (both), got %d", len(ips))
	}

	// Test with missing IPs
	selector = policy.PodSelectorSpec{
		MatchLabels: map[string]string{"app": "db"},
	}
	ips, err = inv.ResolveIPs(selector, IPModePrivate)
	if err != nil {
		t.Fatalf("ResolveIPs failed: %v", err)
	}
	if len(ips) != 1 || ips[0] != "10.0.0.3" {
		t.Fatalf("expected 1 private IP (10.0.0.3), got %v", ips)
	}
}

func TestInventoryResolveIPsDeduplication(t *testing.T) {
	inv := &Inventory{
		Version:  "1.0",
		Provider: ProviderAWS,
		Resources: []Resource{
			{ID: "i-1", Name: "web-1", PrivateIP: "10.0.0.1", Labels: map[string]string{"app": "web"}},
			{ID: "i-2", Name: "web-2", PrivateIP: "10.0.0.1", Labels: map[string]string{"app": "web"}}, // Duplicate IP
			{ID: "i-3", Name: "web-3", PrivateIP: "10.0.0.2", Labels: map[string]string{"app": "web"}},
		},
	}

	selector := policy.PodSelectorSpec{
		MatchLabels: map[string]string{"app": "web"},
	}

	ips, err := inv.ResolveIPs(selector, IPModePrivate)
	if err != nil {
		t.Fatalf("ResolveIPs failed: %v", err)
	}
	if len(ips) != 2 {
		t.Fatalf("expected 2 unique IPs after deduplication, got %d", len(ips))
	}
	if ips[0] != "10.0.0.1" || ips[1] != "10.0.0.2" {
		t.Fatalf("unexpected IPs: %v", ips)
	}
}

func TestInventoryLoadSave(t *testing.T) {
	// Create temp directory
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "test-inventory.json")

	// Create inventory
	original := &Inventory{
		Version:  "1.0",
		Provider: ProviderAWS,
		Scope:    "us-east-1",
		Resources: []Resource{
			{ID: "i-1", Name: "web-1", PrivateIP: "10.0.0.1", Labels: map[string]string{"app": "web"}},
			{ID: "i-2", Name: "db-1", PrivateIP: "10.0.0.2", Labels: map[string]string{"app": "db"}},
		},
	}

	// Save to file
	if err := original.SaveToFile(path); err != nil {
		t.Fatalf("SaveToFile failed: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Fatal("inventory file was not created")
	}

	// Load from file
	loaded, err := LoadFromFile(path)
	if err != nil {
		t.Fatalf("LoadFromFile failed: %v", err)
	}

	// Verify loaded data
	if loaded.Version != original.Version {
		t.Fatalf("version mismatch: expected %s, got %s", original.Version, loaded.Version)
	}
	if loaded.Provider != original.Provider {
		t.Fatalf("provider mismatch: expected %s, got %s", original.Provider, loaded.Provider)
	}
	if loaded.Scope != original.Scope {
		t.Fatalf("scope mismatch: expected %s, got %s", original.Scope, loaded.Scope)
	}
	if len(loaded.Resources) != len(original.Resources) {
		t.Fatalf("resources count mismatch: expected %d, got %d", len(original.Resources), len(loaded.Resources))
	}
}

func TestInventoryLoadFromFileNotFound(t *testing.T) {
	_, err := LoadFromFile("/nonexistent/path/inventory.json")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestInventoryLoadFromFileInvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "invalid.json")

	if err := os.WriteFile(path, []byte("not valid json"), 0600); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	_, err := LoadFromFile(path)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestInventoryEmptyMatch(t *testing.T) {
	inv := &Inventory{
		Version:   "1.0",
		Provider:  ProviderAWS,
		Resources: []Resource{},
	}

	selector := policy.PodSelectorSpec{
		MatchLabels: map[string]string{"app": "web"},
	}

	matched := inv.Match(selector)
	if len(matched) != 0 {
		t.Fatalf("expected 0 matches for empty inventory, got %d", len(matched))
	}

	ips, err := inv.ResolveIPs(selector, IPModePrivate)
	if err != nil {
		t.Fatalf("ResolveIPs failed: %v", err)
	}
	if len(ips) != 0 {
		t.Fatalf("expected 0 IPs for empty inventory, got %d", len(ips))
	}
}
