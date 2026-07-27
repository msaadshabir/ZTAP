// Package inventory provides structured cloud resource inventory with selector matching
// and IP resolution capabilities.
package inventory

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"time"

	"ztap/pkg/policy"
)

// Provider constants
const (
	ProviderAWS   = "aws"
	ProviderAzure = "azure"
	ProviderGCP   = "gcp"
)

// IPMode defines which IPs to extract from resources
type IPMode string

const (
	IPModePrivate IPMode = "private"
	IPModePublic  IPMode = "public"
	IPModeBoth    IPMode = "both"
)

// Resource represents a cloud resource with metadata and labels
type Resource struct {
	ID        string            `json:"id"`
	Name      string            `json:"name"`
	Type      string            `json:"type"`
	PrivateIP string            `json:"private_ip,omitempty"`
	PublicIP  string            `json:"public_ip,omitempty"`
	Labels    map[string]string `json:"labels"`
	Provider  string            `json:"provider"`
	Scope     string            `json:"scope,omitempty"` // region, resource group, network, etc.
}

// Inventory represents a collection of resources from a cloud provider
type Inventory struct {
	Version   string     `json:"version"`
	Provider  string     `json:"provider"`
	Scope     string     `json:"scope"`
	Generated time.Time  `json:"generated"`
	Resources []Resource `json:"resources"`
}

// Match finds resources matching the given selector
func (inv *Inventory) Match(selector policy.PodSelectorSpec) []Resource {
	var matched []Resource
	for _, r := range inv.Resources {
		if policy.MatchesSelector(r.Labels, selector) {
			matched = append(matched, r)
		}
	}
	return matched
}

// ResolveIPs extracts IPs from matched resources based on mode
func (inv *Inventory) ResolveIPs(selector policy.PodSelectorSpec, mode IPMode) ([]string, error) {
	matched := inv.Match(selector)
	if len(matched) == 0 {
		return nil, nil // Caller should handle empty result
	}

	seen := make(map[string]struct{})
	var ips []string

	for _, r := range matched {
		if mode == IPModePrivate || mode == IPModeBoth {
			if r.PrivateIP != "" {
				if _, ok := seen[r.PrivateIP]; !ok {
					seen[r.PrivateIP] = struct{}{}
					ips = append(ips, r.PrivateIP)
				}
			}
		}
		if mode == IPModePublic || mode == IPModeBoth {
			if r.PublicIP != "" {
				if _, ok := seen[r.PublicIP]; !ok {
					seen[r.PublicIP] = struct{}{}
					ips = append(ips, r.PublicIP)
				}
			}
		}
	}

	slices.Sort(ips)
	return ips, nil
}

// LoadFromFile reads inventory from a JSON file
func LoadFromFile(path string) (*Inventory, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading inventory file: %w", err)
	}

	var inv Inventory
	if err := json.Unmarshal(data, &inv); err != nil {
		return nil, fmt.Errorf("parsing inventory JSON: %w", err)
	}

	return &inv, nil
}

// SaveToFile writes inventory to a JSON file
func (inv *Inventory) SaveToFile(path string) error {
	data, err := json.MarshalIndent(inv, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding inventory JSON: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("writing inventory file: %w", err)
	}

	return nil
}
