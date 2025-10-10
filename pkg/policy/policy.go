package policy

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"

	"gopkg.in/yaml.v2"
)

// NetworkPolicy defines a zero-trust rule
type NetworkPolicy struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	Metadata   struct {
		Name string `yaml:"name"`
	} `yaml:"metadata"`
	Spec struct {
		PodSelector struct {
			MatchLabels map[string]string `yaml:"matchLabels"`
		} `yaml:"podSelector"`
		Egress []struct {
			To struct {
				PodSelector struct {
					MatchLabels map[string]string `yaml:"matchLabels"`
				} `yaml:"podSelector,omitempty"`
				IPBlock struct {
					CIDR string `yaml:"cidr"`
				} `yaml:"ipBlock,omitempty"`
			} `yaml:"to"`
			Ports []struct {
				Protocol string `yaml:"protocol"`
				Port     int    `yaml:"port"`
			} `yaml:"ports"`
		} `yaml:"egress"`
	} `yaml:"spec"`
}

// LoadFromFile reads policies from a YAML file
func LoadFromFile(filename string) ([]NetworkPolicy, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var policies []NetworkPolicy
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	for {
		var policy NetworkPolicy
		if err := decoder.Decode(&policy); err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		policies = append(policies, policy)
	}
	return policies, nil
}

// ValidationError represents a policy validation error
type ValidationError struct {
	PolicyName string
	Field      string
	Message    string
}

func (e ValidationError) Error() string {
	return fmt.Sprintf("policy '%s': %s: %s", e.PolicyName, e.Field, e.Message)
}

// Validate checks if a policy is valid
func (p *NetworkPolicy) Validate() error {
	// Check API version
	if p.APIVersion == "" {
		return ValidationError{p.Metadata.Name, "apiVersion", "missing"}
	}

	validVersions := regexp.MustCompile(`^ztap/v\d+$`)
	if !validVersions.MatchString(p.APIVersion) {
		return ValidationError{p.Metadata.Name, "apiVersion", "must be in format ztap/v1"}
	}

	// Check kind
	if p.Kind != "NetworkPolicy" {
		return ValidationError{p.Metadata.Name, "kind", "must be NetworkPolicy"}
	}

	// Check metadata
	if p.Metadata.Name == "" {
		return ValidationError{p.Metadata.Name, "metadata.name", "missing"}
	}

	// Validate name format (DNS-1123 subdomain)
	validName := regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
	if !validName.MatchString(p.Metadata.Name) {
		return ValidationError{p.Metadata.Name, "metadata.name", "must be lowercase alphanumeric with hyphens"}
	}

	// Check podSelector
	if len(p.Spec.PodSelector.MatchLabels) == 0 {
		return ValidationError{p.Metadata.Name, "spec.podSelector", "must have at least one label"}
	}

	// Validate egress rules
	for i, egress := range p.Spec.Egress {
		// Must have either podSelector or ipBlock
		hasPodSelector := len(egress.To.PodSelector.MatchLabels) > 0
		hasIPBlock := egress.To.IPBlock.CIDR != ""

		if !hasPodSelector && !hasIPBlock {
			return ValidationError{
				p.Metadata.Name,
				fmt.Sprintf("spec.egress[%d].to", i),
				"must specify either podSelector or ipBlock",
			}
		}

		if hasPodSelector && hasIPBlock {
			return ValidationError{
				p.Metadata.Name,
				fmt.Sprintf("spec.egress[%d].to", i),
				"cannot specify both podSelector and ipBlock",
			}
		}

		// Validate CIDR if present
		if hasIPBlock {
			_, _, err := net.ParseCIDR(egress.To.IPBlock.CIDR)
			if err != nil {
				return ValidationError{
					p.Metadata.Name,
					fmt.Sprintf("spec.egress[%d].to.ipBlock.cidr", i),
					fmt.Sprintf("invalid CIDR: %v", err),
				}
			}
		}

		// Validate ports
		if len(egress.Ports) == 0 {
			return ValidationError{
				p.Metadata.Name,
				fmt.Sprintf("spec.egress[%d].ports", i),
				"must specify at least one port",
			}
		}

		for j, port := range egress.Ports {
			// Validate protocol
			validProtocols := map[string]bool{"TCP": true, "UDP": true, "ICMP": true}
			if !validProtocols[port.Protocol] {
				return ValidationError{
					p.Metadata.Name,
					fmt.Sprintf("spec.egress[%d].ports[%d].protocol", i, j),
					"must be TCP, UDP, or ICMP",
				}
			}

			// Validate port number
			if port.Port < 1 || port.Port > 65535 {
				return ValidationError{
					p.Metadata.Name,
					fmt.Sprintf("spec.egress[%d].ports[%d].port", i, j),
					"must be between 1 and 65535",
				}
			}
		}
	}

	return nil
}

// ResolveLabels converts label selectors to IP addresses
// In production, this would query a service discovery system
func ResolveLabels(labels map[string]string) ([]string, error) {
	// Placeholder: In production, query DNS, Consul, etcd, or cloud provider
	// For now, return empty list (enforcer will log warning)
	return nil, fmt.Errorf("label resolution not yet implemented")
}
