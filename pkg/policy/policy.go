package policy

import (
	"bytes"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"regexp"

	yaml "gopkg.in/yaml.v2"
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

// NamedPolicy couples a policy with its source identifier (e.g., sync name).
type NamedPolicy struct {
	PolicyName string
	Policy     NetworkPolicy
}

// LoadFromFile reads policies from a YAML file
func LoadFromFile(filename string) ([]NetworkPolicy, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return LoadFromBytes(data)
}

const (
	// estimatedBytesPerPolicy is a conservative estimate for YAML policy size
	estimatedBytesPerPolicy = 1000
)

// LoadFromBytes reads policies from YAML bytes
func LoadFromBytes(data []byte) ([]NetworkPolicy, error) {
	// Pre-allocate with estimated capacity
	// This is a conservative estimate to reduce reallocations while not over-allocating
	estimatedPolicies := len(data)/estimatedBytesPerPolicy + 1
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

	if err := p.detectRuleConflicts(); err != nil {
		return err
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

func (p *NetworkPolicy) detectRuleConflicts() error {
	type ruleRef struct {
		dir      string
		cidr     string
		labels   map[string]string
		protocol string
		port     int
		index    int
	}

	var refs []ruleRef

	for i, egress := range p.Spec.Egress {
		refs = append(refs, ruleRef{
			dir:      "egress",
			cidr:     egress.To.IPBlock.CIDR,
			labels:   egress.To.PodSelector.MatchLabels,
			protocol: egress.Ports[0].Protocol,
			port:     egress.Ports[0].Port,
			index:    i,
		})
		for j := 1; j < len(egress.Ports); j++ {
			refs = append(refs, ruleRef{
				dir:      "egress",
				cidr:     egress.To.IPBlock.CIDR,
				labels:   egress.To.PodSelector.MatchLabels,
				protocol: egress.Ports[j].Protocol,
				port:     egress.Ports[j].Port,
				index:    i,
			})
		}
	}

	for i, ingress := range p.Spec.Ingress {
		refs = append(refs, ruleRef{
			dir:      "ingress",
			cidr:     ingress.From.IPBlock.CIDR,
			labels:   ingress.From.PodSelector.MatchLabels,
			protocol: ingress.Ports[0].Protocol,
			port:     ingress.Ports[0].Port,
			index:    i,
		})
		for j := 1; j < len(ingress.Ports); j++ {
			refs = append(refs, ruleRef{
				dir:      "ingress",
				cidr:     ingress.From.IPBlock.CIDR,
				labels:   ingress.From.PodSelector.MatchLabels,
				protocol: ingress.Ports[j].Protocol,
				port:     ingress.Ports[j].Port,
				index:    i,
			})
		}
	}

	for i := 0; i < len(refs); i++ {
		a := refs[i]
		for j := 0; j < i; j++ {
			b := refs[j]
			if a.dir != b.dir || a.protocol != b.protocol || a.port != b.port {
				continue
			}
			if targetsOverlap(a.labels, a.cidr, b.labels, b.cidr) {
				field := fmt.Sprintf("spec.%s[%d]", a.dir, a.index)
				return ValidationError{
					PolicyName: p.Metadata.Name,
					Field:      field,
					Message:    fmt.Sprintf("overlaps with spec.%s[%d]", b.dir, b.index),
				}
			}
		}
	}

	return nil
}

func labelsOverlap(a, b map[string]string) bool {
	for k, v := range a {
		if bv, ok := b[k]; ok && bv != v {
			return false
		}
	}
	for k, v := range b {
		if av, ok := a[k]; ok && av != v {
			return false
		}
	}
	return true
}

func cidrOverlap(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	_, na, errA := net.ParseCIDR(a)
	_, nb, errB := net.ParseCIDR(b)
	if errA != nil || errB != nil {
		return false
	}
	if len(na.IP) != len(nb.IP) {
		return false
	}
	saStart, saEnd := cidrRange(na)
	sbStart, sbEnd := cidrRange(nb)
	if saStart == nil || sbStart == nil {
		return false
	}
	// overlap if ranges intersect
	if saStart.Cmp(sbEnd) == 1 || sbStart.Cmp(saEnd) == 1 {
		return false
	}
	return true
}

func cidrRange(n *net.IPNet) (*big.Int, *big.Int) {
	ip := n.IP
	mask := n.Mask
	if len(ip) == 0 || len(mask) == 0 {
		return nil, nil
	}
	start := ipToInt(ip)
	maskInt := new(big.Int).SetBytes(mask)
	if start == nil || maskInt == nil {
		return nil, nil
	}
	bits := len(ip) * 8
	max := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(bits)), big.NewInt(1))
	invMask := new(big.Int).Xor(maskInt, max)
	end := new(big.Int).Or(start, invMask)
	return start, end
}

func ipToInt(ip net.IP) *big.Int {
	if len(ip) == 0 {
		return nil
	}
	return new(big.Int).SetBytes(ip)
}

func targetsOverlap(labelsA map[string]string, cidrA string, labelsB map[string]string, cidrB string) bool {
	if cidrA != "" && cidrB != "" {
		return cidrOverlap(cidrA, cidrB)
	}
	if len(labelsA) > 0 && len(labelsB) > 0 {
		return labelsOverlap(labelsA, labelsB)
	}
	return false
}

func overlapsEgress(rule EgressRule, port PortSpec, other NetworkPolicy) bool {
	for _, r := range other.Spec.Egress {
		for _, p := range r.Ports {
			if p.Protocol != port.Protocol || p.Port != port.Port {
				continue
			}
			if targetsOverlap(rule.To.PodSelector.MatchLabels, rule.To.IPBlock.CIDR, r.To.PodSelector.MatchLabels, r.To.IPBlock.CIDR) {
				return true
			}
		}
	}
	return false
}

func overlapsIngress(rule IngressRule, port PortSpec, other NetworkPolicy) bool {
	for _, r := range other.Spec.Ingress {
		for _, p := range r.Ports {
			if p.Protocol != port.Protocol || p.Port != port.Port {
				continue
			}
			if targetsOverlap(rule.From.PodSelector.MatchLabels, rule.From.IPBlock.CIDR, r.From.PodSelector.MatchLabels, r.From.IPBlock.CIDR) {
				return true
			}
		}
	}
	return false
}

// CheckConflicts verifies that a candidate policy does not overlap existing policies on identical peers/ports.
func CheckConflicts(existing []NamedPolicy, candidate NamedPolicy) error {
	for _, np := range existing {
		if np.PolicyName == candidate.PolicyName {
			continue
		}
		for _, egress := range candidate.Policy.Spec.Egress {
			for _, port := range egress.Ports {
				if overlapsEgress(egress, port, np.Policy) {
					return ValidationError{
						PolicyName: candidate.Policy.Metadata.Name,
						Field:      "conflict",
						Message:    fmt.Sprintf("conflicts with policy %s on %s/%d", np.PolicyName, port.Protocol, port.Port),
					}
				}
			}
		}

		for _, ingress := range candidate.Policy.Spec.Ingress {
			for _, port := range ingress.Ports {
				if overlapsIngress(ingress, port, np.Policy) {
					return ValidationError{
						PolicyName: candidate.Policy.Metadata.Name,
						Field:      "conflict",
						Message:    fmt.Sprintf("conflicts with policy %s on %s/%d", np.PolicyName, port.Protocol, port.Port),
					}
				}
			}
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
