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

// ServiceDiscovery interface for label resolution
type ServiceDiscovery interface {
	ResolveLabels(labels map[string]string) ([]string, error)
}

// PortSpec defines a protocol and port combination for network rules.
type PortSpec struct {
	Protocol string `yaml:"protocol"`
	Port     int    `yaml:"port"`
}

// PodSelectorSpec defines label-based pod selection.
type PodSelectorSpec struct {
	MatchLabels map[string]string `yaml:"matchLabels"`
}

// IPBlockSpec defines CIDR-based IP selection.
type IPBlockSpec struct {
	CIDR string `yaml:"cidr"`
}

// EgressTarget defines the destination for egress rules.
type EgressTarget struct {
	PodSelector PodSelectorSpec `yaml:"podSelector,omitempty"`
	IPBlock     IPBlockSpec     `yaml:"ipBlock,omitempty"`
}

// EgressRule defines an outbound traffic rule.
type EgressRule struct {
	To    EgressTarget `yaml:"to"`
	Ports []PortSpec   `yaml:"ports"`
}

// IngressSource defines the source for ingress rules.
type IngressSource struct {
	PodSelector PodSelectorSpec `yaml:"podSelector,omitempty"`
	IPBlock     IPBlockSpec     `yaml:"ipBlock,omitempty"`
}

// IngressRule defines an inbound traffic rule.
type IngressRule struct {
	From  IngressSource `yaml:"from"`
	Ports []PortSpec    `yaml:"ports"`
}

// NetworkPolicySpec defines the specification for a network policy.
type NetworkPolicySpec struct {
	PodSelector PodSelectorSpec `yaml:"podSelector"`
	Egress      []EgressRule    `yaml:"egress,omitempty"`
	Ingress     []IngressRule   `yaml:"ingress,omitempty"`
}

// NetworkPolicyMetadata defines metadata for a network policy.
type NetworkPolicyMetadata struct {
	Name string `yaml:"name"`
}

// NetworkPolicy defines a zero-trust rule with bidirectional enforcement support.
type NetworkPolicy struct {
	APIVersion string                `yaml:"apiVersion"`
	Kind       string                `yaml:"kind"`
	Metadata   NetworkPolicyMetadata `yaml:"metadata"`
	Spec       NetworkPolicySpec     `yaml:"spec"`
}

// LoadFromFile reads policies from a YAML file
func LoadFromFile(filename string) ([]NetworkPolicy, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return LoadFromBytes(data)
}

// LoadFromBytes reads policies from YAML bytes
func LoadFromBytes(data []byte) ([]NetworkPolicy, error) {
	// Pre-allocate with estimated capacity (assume ~1 policy per 500 bytes)
	estimatedPolicies := len(data)/500 + 1
	if estimatedPolicies < 1 {
		estimatedPolicies = 1
	}
	policies := make([]NetworkPolicy, 0, estimatedPolicies)
	
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

	// Must have at least one egress or ingress rule
	if len(p.Spec.Egress) == 0 && len(p.Spec.Ingress) == 0 {
		return ValidationError{p.Metadata.Name, "spec", "must have at least one egress or ingress rule"}
	}

	// Validate egress rules
	for i, egress := range p.Spec.Egress {
		if err := p.validateEgressRule(i, egress); err != nil {
			return err
		}
	}

	// Validate ingress rules
	for i, ingress := range p.Spec.Ingress {
		if err := p.validateIngressRule(i, ingress); err != nil {
			return err
		}
	}

	return nil
}

// validateEgressRule validates a single egress rule.
func (p *NetworkPolicy) validateEgressRule(index int, egress EgressRule) error {
	// Must have either podSelector or ipBlock
	hasPodSelector := len(egress.To.PodSelector.MatchLabels) > 0
	hasIPBlock := egress.To.IPBlock.CIDR != ""

	if !hasPodSelector && !hasIPBlock {
		return ValidationError{
			p.Metadata.Name,
			fmt.Sprintf("spec.egress[%d].to", index),
			"must specify either podSelector or ipBlock",
		}
	}

	if hasPodSelector && hasIPBlock {
		return ValidationError{
			p.Metadata.Name,
			fmt.Sprintf("spec.egress[%d].to", index),
			"cannot specify both podSelector and ipBlock",
		}
	}

	// Validate CIDR if present
	if hasIPBlock {
		_, _, err := net.ParseCIDR(egress.To.IPBlock.CIDR)
		if err != nil {
			return ValidationError{
				p.Metadata.Name,
				fmt.Sprintf("spec.egress[%d].to.ipBlock.cidr", index),
				fmt.Sprintf("invalid CIDR: %v", err),
			}
		}
	}

	// Validate ports
	if len(egress.Ports) == 0 {
		return ValidationError{
			p.Metadata.Name,
			fmt.Sprintf("spec.egress[%d].ports", index),
			"must specify at least one port",
		}
	}

	for j, port := range egress.Ports {
		if err := p.validatePort(fmt.Sprintf("spec.egress[%d].ports[%d]", index, j), port); err != nil {
			return err
		}
	}

	return nil
}

// validateIngressRule validates a single ingress rule.
func (p *NetworkPolicy) validateIngressRule(index int, ingress IngressRule) error {
	// Must have either podSelector or ipBlock
	hasPodSelector := len(ingress.From.PodSelector.MatchLabels) > 0
	hasIPBlock := ingress.From.IPBlock.CIDR != ""

	if !hasPodSelector && !hasIPBlock {
		return ValidationError{
			p.Metadata.Name,
			fmt.Sprintf("spec.ingress[%d].from", index),
			"must specify either podSelector or ipBlock",
		}
	}

	if hasPodSelector && hasIPBlock {
		return ValidationError{
			p.Metadata.Name,
			fmt.Sprintf("spec.ingress[%d].from", index),
			"cannot specify both podSelector and ipBlock",
		}
	}

	// Validate CIDR if present
	if hasIPBlock {
		_, _, err := net.ParseCIDR(ingress.From.IPBlock.CIDR)
		if err != nil {
			return ValidationError{
				p.Metadata.Name,
				fmt.Sprintf("spec.ingress[%d].from.ipBlock.cidr", index),
				fmt.Sprintf("invalid CIDR: %v", err),
			}
		}
	}

	// Validate ports
	if len(ingress.Ports) == 0 {
		return ValidationError{
			p.Metadata.Name,
			fmt.Sprintf("spec.ingress[%d].ports", index),
			"must specify at least one port",
		}
	}

	for j, port := range ingress.Ports {
		if err := p.validatePort(fmt.Sprintf("spec.ingress[%d].ports[%d]", index, j), port); err != nil {
			return err
		}
	}

	return nil
}

// validatePort validates a single port specification.
func (p *NetworkPolicy) validatePort(field string, port PortSpec) error {
	// Validate protocol
	validProtocols := map[string]bool{"TCP": true, "UDP": true, "ICMP": true}
	if !validProtocols[port.Protocol] {
		return ValidationError{
			p.Metadata.Name,
			field + ".protocol",
			"must be TCP, UDP, or ICMP",
		}
	}

	// Validate port number
	if port.Port < 1 || port.Port > 65535 {
		return ValidationError{
			p.Metadata.Name,
			field + ".port",
			"must be between 1 and 65535",
		}
	}

	return nil
}

// PolicyResolver handles label resolution with service discovery
type PolicyResolver struct {
	discovery ServiceDiscovery
}

// NewPolicyResolver creates a new resolver with the given discovery backend
func NewPolicyResolver(discovery ServiceDiscovery) *PolicyResolver {
	return &PolicyResolver{discovery: discovery}
}

// ResolveLabels converts label selectors to IP addresses using service discovery
func (r *PolicyResolver) ResolveLabels(labels map[string]string) ([]string, error) {
	if r.discovery == nil {
		return nil, fmt.Errorf("no service discovery backend configured")
	}
	return r.discovery.ResolveLabels(labels)
}

// ResolveLabels (standalone) is deprecated, use PolicyResolver instead
// Kept for backward compatibility
func ResolveLabels(labels map[string]string) ([]string, error) {
	return nil, fmt.Errorf("label resolution requires service discovery backend")
}
