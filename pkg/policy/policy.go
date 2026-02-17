package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"net"
	"net/netip"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"ztap/pkg/logging"

	yaml "gopkg.in/yaml.v2"
)

// ServiceDiscovery interface for label resolution
type ServiceDiscovery interface {
	ResolveLabels(labels map[string]string) ([]string, error)
	RegisterService(name string, ip string, labels map[string]string) error
	DeregisterService(name string) error
	Watch(ctx context.Context, labels map[string]string) (<-chan []string, error)
	Stop() error
}

// ScopedServiceDiscovery is an optional extension for multi-tenant environments.
//
// Scope is typically a Kubernetes namespace.
type ScopedServiceDiscovery interface {
	ResolveLabelsScoped(scope string, labels map[string]string) ([]string, error)
	WatchScoped(ctx context.Context, scope string, labels map[string]string) (<-chan []string, error)
}

// PodPort describes a named port on a pod.
type PodPort struct {
	Name     string
	Port     int
	Protocol string
}

// PodInfo describes a resolved pod target.
type PodInfo struct {
	IP        string
	Namespace string
	Labels    map[string]string
	Ports     []PodPort
}

// PodResolver resolves pods (including ports) for selectors.
type PodResolver interface {
	ResolvePods(selector PodSelectorSpec) ([]PodInfo, error)
	ResolvePodsScoped(scope string, selector PodSelectorSpec) ([]PodInfo, error)
}

// SelectorResolver enables resolving label selectors with matchExpressions.
type SelectorResolver interface {
	ResolveSelector(selector PodSelectorSpec) ([]string, error)
	ResolveSelectorScoped(scope string, selector PodSelectorSpec) ([]string, error)
}

// NamespaceResolver resolves namespaces that match a selector.
type NamespaceResolver interface {
	ResolveNamespaces(selector PodSelectorSpec) ([]string, error)
}

// PortSpec defines a protocol and port combination for network rules.
type PortSpec struct {
	Protocol string `yaml:"protocol" json:"protocol"`
	Port     int    `yaml:"-" json:"-"`
	PortName string `yaml:"-" json:"-"`
	EndPort  *int   `yaml:"endPort,omitempty" json:"endPort,omitempty"`
}

// LabelSelectorRequirement defines a selector requirement.
type LabelSelectorRequirement struct {
	Key      string   `yaml:"key" json:"key"`
	Operator string   `yaml:"operator" json:"operator"`
	Values   []string `yaml:"values,omitempty" json:"values,omitempty"`
}

// PodSelectorSpec defines label-based pod selection.
type PodSelectorSpec struct {
	MatchLabels      map[string]string          `yaml:"matchLabels,omitempty" json:"matchLabels,omitempty"`
	MatchExpressions []LabelSelectorRequirement `yaml:"matchExpressions,omitempty" json:"matchExpressions,omitempty"`
}

type portSpecWire struct {
	Protocol string `yaml:"protocol" json:"protocol"`
	Port     any    `yaml:"port" json:"port"`
	EndPort  *int   `yaml:"endPort,omitempty" json:"endPort,omitempty"`
}

func (p *PortSpec) UnmarshalYAML(unmarshal func(any) error) error {
	var raw portSpecWire
	if err := unmarshal(&raw); err != nil {
		return err
	}
	portNum, portName, err := parsePortValue(raw.Port)
	if err != nil {
		return err
	}
	p.Protocol = raw.Protocol
	p.Port = portNum
	p.PortName = portName
	p.EndPort = raw.EndPort
	return nil
}

func (p PortSpec) MarshalYAML() (any, error) {
	return portSpecWire{
		Protocol: p.Protocol,
		Port:     portValueForMarshal(p.Port, p.PortName),
		EndPort:  p.EndPort,
	}, nil
}

func (p *PortSpec) UnmarshalJSON(data []byte) error {
	var raw struct {
		Protocol string          `json:"protocol"`
		Port     json.RawMessage `json:"port"`
		EndPort  *int            `json:"endPort,omitempty"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	portNum, portName, err := parsePortJSON(raw.Port)
	if err != nil {
		return err
	}
	p.Protocol = raw.Protocol
	p.Port = portNum
	p.PortName = portName
	p.EndPort = raw.EndPort
	return nil
}

func (p PortSpec) MarshalJSON() ([]byte, error) {
	out := struct {
		Protocol string `json:"protocol"`
		Port     any    `json:"port"`
		EndPort  *int   `json:"endPort,omitempty"`
	}{
		Protocol: p.Protocol,
		Port:     portValueForMarshal(p.Port, p.PortName),
		EndPort:  p.EndPort,
	}
	return json.Marshal(out)
}

func parsePortValue(raw any) (int, string, error) {
	if raw == nil {
		return 0, "", nil
	}
	switch v := raw.(type) {
	case int:
		return v, "", nil
	case int64:
		return int(v), "", nil
	case uint64:
		if v > uint64(math.MaxInt) {
			return 0, "", fmt.Errorf("port must be between 1 and 65535")
		}
		return int(v), "", nil // #nosec G115 -- bounded by MaxInt check above
	case float64:
		if v != float64(int(v)) {
			return 0, "", fmt.Errorf("port must be an integer")
		}
		return int(v), "", nil
	case json.Number:
		val, err := v.Int64()
		if err != nil {
			return 0, "", fmt.Errorf("port must be an integer: %w", err)
		}
		return int(val), "", nil
	case string:
		s := strings.TrimSpace(v)
		if s == "" {
			return 0, "", nil
		}
		if n, err := strconv.Atoi(s); err == nil {
			return n, "", nil
		}
		return 0, s, nil
	default:
		return 0, "", fmt.Errorf("port must be an integer or string")
	}
}

func parsePortJSON(raw json.RawMessage) (int, string, error) {
	if len(raw) == 0 {
		return 0, "", nil
	}
	var num int
	if err := json.Unmarshal(raw, &num); err == nil {
		return num, "", nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		s = strings.TrimSpace(s)
		if s == "" {
			return 0, "", nil
		}
		if n, err := strconv.Atoi(s); err == nil {
			return n, "", nil
		}
		return 0, s, nil
	}
	return 0, "", fmt.Errorf("port must be an integer or string")
}

func portValueForMarshal(port int, portName string) any {
	if strings.TrimSpace(portName) != "" {
		return portName
	}
	return port
}

// IPBlockSpec defines CIDR-based IP selection.
type IPBlockSpec struct {
	CIDR   string   `yaml:"cidr"`
	Except []string `yaml:"except,omitempty"`
}

// EgressTarget defines the destination for egress rules.
type EgressTarget struct {
	PodSelector       PodSelectorSpec `yaml:"podSelector,omitempty"`
	NamespaceSelector PodSelectorSpec `yaml:"namespaceSelector,omitempty"`
	IPBlock           IPBlockSpec     `yaml:"ipBlock,omitempty"`
}

// EgressRule defines an outbound traffic rule.
type EgressRule struct {
	To    EgressTarget `yaml:"to"`
	Ports []PortSpec   `yaml:"ports"`
}

// IngressSource defines the source for ingress rules.
type IngressSource struct {
	PodSelector       PodSelectorSpec `yaml:"podSelector,omitempty"`
	NamespaceSelector PodSelectorSpec `yaml:"namespaceSelector,omitempty"`
	IPBlock           IPBlockSpec     `yaml:"ipBlock,omitempty"`
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
	Name        string            `yaml:"name"`
	Labels      map[string]string `yaml:"labels,omitempty"`
	Annotations map[string]string `yaml:"annotations,omitempty"`
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
	// Tenant is an optional isolation scope.
	//
	// When empty, it is treated as "default" for conflict scoping.
	Tenant     string
	PolicyName string
	Policy     NetworkPolicy
}

func (np NamedPolicy) KeyString() string {
	tenant := strings.TrimSpace(np.Tenant)
	if tenant == "" {
		tenant = "default"
	}
	name := strings.TrimSpace(np.PolicyName)
	if name == "" {
		return tenant
	}
	return tenant + "/" + name
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
	if err := p.validateLabelSelector("spec.podSelector", p.Spec.PodSelector); err != nil {
		return err
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

func selectorIsEmpty(selector PodSelectorSpec) bool {
	return len(selector.MatchLabels) == 0 && len(selector.MatchExpressions) == 0
}

func selectorIsSimple(selector PodSelectorSpec) bool {
	return len(selector.MatchLabels) > 0 && len(selector.MatchExpressions) == 0
}

// HasNamedPorts reports whether any port entry is named.
func HasNamedPorts(ports []PortSpec) bool {
	for _, port := range ports {
		if strings.TrimSpace(port.PortName) != "" {
			return true
		}
	}
	return false
}

// NamedPortKey returns a stable key for a named port lookup.
func NamedPortKey(name string, protocol string) string {
	return strings.ToLower(strings.TrimSpace(name)) + "/" + strings.ToUpper(strings.TrimSpace(protocol))
}

// BuildNamedPortMap builds a map of name+protocol -> port.
// Returns an error if a name+protocol resolves to multiple ports.
func BuildNamedPortMap(ports []PodPort) (map[string]int, error) {
	portMap := make(map[string]int)
	for _, port := range ports {
		name := strings.TrimSpace(port.Name)
		if name == "" {
			continue
		}
		key := NamedPortKey(name, port.Protocol)
		if existing, ok := portMap[key]; ok && existing != port.Port {
			return nil, fmt.Errorf("named port %s resolves to multiple ports", name)
		}
		portMap[key] = port.Port
	}
	return portMap, nil
}

// ResolveNamedPorts replaces named ports with numeric ports using the provided map.
// Numeric ports and ranges are preserved.
func ResolveNamedPorts(ports []PortSpec, portMap map[string]int) ([]PortSpec, []string) {
	if len(ports) == 0 {
		return nil, nil
	}
	resolved := make([]PortSpec, 0, len(ports))
	missing := make([]string, 0)
	for _, port := range ports {
		name := strings.TrimSpace(port.PortName)
		if name == "" {
			resolved = append(resolved, port)
			continue
		}
		key := NamedPortKey(name, port.Protocol)
		mapped, ok := portMap[key]
		if !ok {
			missing = append(missing, name)
			continue
		}
		updated := port
		updated.Port = mapped
		updated.PortName = ""
		resolved = append(resolved, updated)
	}
	return resolved, missing
}

// MatchesSelector evaluates a selector against a label set.
func MatchesSelector(labels map[string]string, selector PodSelectorSpec) bool {
	if selectorIsEmpty(selector) {
		return true
	}
	for key, value := range selector.MatchLabels {
		if labels[key] != value {
			return false
		}
	}
	for _, expr := range selector.MatchExpressions {
		labelValue, exists := labels[expr.Key]
		switch expr.Operator {
		case "In":
			if !exists || !stringInSlice(labelValue, expr.Values) {
				return false
			}
		case "NotIn":
			if exists && stringInSlice(labelValue, expr.Values) {
				return false
			}
		case "Exists":
			if !exists {
				return false
			}
		case "DoesNotExist":
			if exists {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func stringInSlice(value string, values []string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}

func (p *NetworkPolicy) validateLabelSelector(field string, selector PodSelectorSpec) error {
	if selectorIsEmpty(selector) {
		return ValidationError{p.Metadata.Name, field, "must include matchLabels or matchExpressions"}
	}
	for i, expr := range selector.MatchExpressions {
		keyField := fmt.Sprintf("%s.matchExpressions[%d].key", field, i)
		opField := fmt.Sprintf("%s.matchExpressions[%d].operator", field, i)
		valuesField := fmt.Sprintf("%s.matchExpressions[%d].values", field, i)
		if strings.TrimSpace(expr.Key) == "" {
			return ValidationError{p.Metadata.Name, keyField, "missing"}
		}
		switch expr.Operator {
		case "In", "NotIn":
			if len(expr.Values) == 0 {
				return ValidationError{p.Metadata.Name, valuesField, "must include at least one value"}
			}
			for _, v := range expr.Values {
				if strings.TrimSpace(v) == "" {
					return ValidationError{p.Metadata.Name, valuesField, "values must be non-empty"}
				}
			}
		case "Exists", "DoesNotExist":
			if len(expr.Values) > 0 {
				return ValidationError{p.Metadata.Name, valuesField, "must be empty for Exists/DoesNotExist"}
			}
		default:
			return ValidationError{p.Metadata.Name, opField, "must be In, NotIn, Exists, or DoesNotExist"}
		}
	}
	return nil
}

func (p *NetworkPolicy) validateIPBlock(field string, block IPBlockSpec) error {
	if strings.TrimSpace(block.CIDR) == "" {
		return ValidationError{p.Metadata.Name, field + ".cidr", "missing"}
	}
	base, err := netip.ParsePrefix(strings.TrimSpace(block.CIDR))
	if err != nil {
		return ValidationError{p.Metadata.Name, field + ".cidr", fmt.Sprintf("invalid CIDR: %v", err)}
	}
	base = base.Masked()
	for i, raw := range block.Except {
		exceptField := fmt.Sprintf("%s.except[%d]", field, i)
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			return ValidationError{p.Metadata.Name, exceptField, "must be a CIDR"}
		}
		except, err := netip.ParsePrefix(trimmed)
		if err != nil {
			return ValidationError{p.Metadata.Name, exceptField, fmt.Sprintf("invalid CIDR: %v", err)}
		}
		except = except.Masked()
		if base.Addr().Is4() != except.Addr().Is4() {
			return ValidationError{p.Metadata.Name, exceptField, "must match CIDR address family"}
		}
		if !prefixContains(base, except) {
			return ValidationError{p.Metadata.Name, exceptField, "must be within cidr"}
		}
	}
	return nil
}

// validateEgressRule validates a single egress rule.
func (p *NetworkPolicy) validateEgressRule(index int, egress EgressRule) error {
	// Must have either selectors or ipBlock
	hasPodSelector := !selectorIsEmpty(egress.To.PodSelector)
	hasNamespaceSelector := !selectorIsEmpty(egress.To.NamespaceSelector)
	hasIPBlock := egress.To.IPBlock.CIDR != ""

	if !hasPodSelector && !hasNamespaceSelector && !hasIPBlock {
		return ValidationError{
			p.Metadata.Name,
			fmt.Sprintf("spec.egress[%d].to", index),
			"must specify podSelector, namespaceSelector, or ipBlock",
		}
	}

	if hasIPBlock && (hasPodSelector || hasNamespaceSelector) {
		return ValidationError{
			p.Metadata.Name,
			fmt.Sprintf("spec.egress[%d].to", index),
			"cannot combine ipBlock with selectors",
		}
	}

	if hasPodSelector {
		if err := p.validateLabelSelector(fmt.Sprintf("spec.egress[%d].to.podSelector", index), egress.To.PodSelector); err != nil {
			return err
		}
	}

	if hasNamespaceSelector {
		if err := p.validateLabelSelector(fmt.Sprintf("spec.egress[%d].to.namespaceSelector", index), egress.To.NamespaceSelector); err != nil {
			return err
		}
	}

	// Validate CIDR if present
	if hasIPBlock {
		if err := p.validateIPBlock(fmt.Sprintf("spec.egress[%d].to.ipBlock", index), egress.To.IPBlock); err != nil {
			return err
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
	if hasIPBlock && HasNamedPorts(egress.Ports) {
		return ValidationError{
			p.Metadata.Name,
			fmt.Sprintf("spec.egress[%d].ports", index),
			"named ports require podSelector or namespaceSelector",
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
	// Must have either selectors or ipBlock
	hasPodSelector := !selectorIsEmpty(ingress.From.PodSelector)
	hasNamespaceSelector := !selectorIsEmpty(ingress.From.NamespaceSelector)
	hasIPBlock := ingress.From.IPBlock.CIDR != ""

	if !hasPodSelector && !hasNamespaceSelector && !hasIPBlock {
		return ValidationError{
			p.Metadata.Name,
			fmt.Sprintf("spec.ingress[%d].from", index),
			"must specify podSelector, namespaceSelector, or ipBlock",
		}
	}

	if hasIPBlock && (hasPodSelector || hasNamespaceSelector) {
		return ValidationError{
			p.Metadata.Name,
			fmt.Sprintf("spec.ingress[%d].from", index),
			"cannot combine ipBlock with selectors",
		}
	}

	if hasPodSelector {
		if err := p.validateLabelSelector(fmt.Sprintf("spec.ingress[%d].from.podSelector", index), ingress.From.PodSelector); err != nil {
			return err
		}
	}

	if hasNamespaceSelector {
		if err := p.validateLabelSelector(fmt.Sprintf("spec.ingress[%d].from.namespaceSelector", index), ingress.From.NamespaceSelector); err != nil {
			return err
		}
	}

	// Validate CIDR if present
	if hasIPBlock {
		if err := p.validateIPBlock(fmt.Sprintf("spec.ingress[%d].from.ipBlock", index), ingress.From.IPBlock); err != nil {
			return err
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

	portName := strings.TrimSpace(port.PortName)
	if portName != "" {
		validName := regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
		if !validName.MatchString(portName) {
			return ValidationError{
				p.Metadata.Name,
				field + ".port",
				"named port must be lowercase alphanumeric with hyphens",
			}
		}
		if port.EndPort != nil {
			return ValidationError{
				p.Metadata.Name,
				field + ".endPort",
				"cannot use endPort with named ports",
			}
		}
		if strings.EqualFold(port.Protocol, "ICMP") {
			return ValidationError{
				p.Metadata.Name,
				field + ".port",
				"named ports are not valid for ICMP",
			}
		}
		return nil
	}

	// Validate port number
	if port.Port < 1 || port.Port > 65535 {
		return ValidationError{
			p.Metadata.Name,
			field + ".port",
			"must be between 1 and 65535",
		}
	}
	if port.EndPort != nil {
		if strings.EqualFold(port.Protocol, "ICMP") {
			return ValidationError{
				p.Metadata.Name,
				field + ".endPort",
				"endPort is not valid for ICMP",
			}
		}
		if *port.EndPort < port.Port || *port.EndPort > 65535 {
			return ValidationError{
				p.Metadata.Name,
				field + ".endPort",
				"must be between port and 65535",
			}
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
		labels := map[string]string(nil)
		cidr := ""
		if egress.To.IPBlock.CIDR != "" {
			if len(egress.To.IPBlock.Except) > 0 {
				continue
			}
			cidr = egress.To.IPBlock.CIDR
		} else if selectorIsSimple(egress.To.PodSelector) && selectorIsEmpty(egress.To.NamespaceSelector) {
			labels = egress.To.PodSelector.MatchLabels
		} else {
			continue
		}
		for _, port := range egress.Ports {
			if port.PortName != "" || port.EndPort != nil {
				continue
			}
			refs = append(refs, ruleRef{
				dir:      "egress",
				cidr:     cidr,
				labels:   labels,
				protocol: port.Protocol,
				port:     port.Port,
				index:    i,
			})
		}
	}

	for i, ingress := range p.Spec.Ingress {
		labels := map[string]string(nil)
		cidr := ""
		if ingress.From.IPBlock.CIDR != "" {
			if len(ingress.From.IPBlock.Except) > 0 {
				continue
			}
			cidr = ingress.From.IPBlock.CIDR
		} else if selectorIsSimple(ingress.From.PodSelector) && selectorIsEmpty(ingress.From.NamespaceSelector) {
			labels = ingress.From.PodSelector.MatchLabels
		} else {
			continue
		}
		for _, port := range ingress.Ports {
			if port.PortName != "" || port.EndPort != nil {
				continue
			}
			refs = append(refs, ruleRef{
				dir:      "ingress",
				cidr:     cidr,
				labels:   labels,
				protocol: port.Protocol,
				port:     port.Port,
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

func prefixContains(parent, child netip.Prefix) bool {
	if !parent.IsValid() || !child.IsValid() {
		return false
	}
	if parent.Bits() > child.Bits() {
		return false
	}
	return parent.Contains(child.Masked().Addr())
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
	max := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(bits)), big.NewInt(1)) // #nosec G115 -- bits derived from IP length and is non-negative
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
	if port.PortName != "" || port.EndPort != nil {
		return false
	}
	if len(rule.To.IPBlock.Except) > 0 {
		return false
	}
	if rule.To.IPBlock.CIDR == "" && (!selectorIsSimple(rule.To.PodSelector) || !selectorIsEmpty(rule.To.NamespaceSelector)) {
		return false
	}
	for _, r := range other.Spec.Egress {
		if len(r.To.IPBlock.Except) > 0 {
			continue
		}
		if r.To.IPBlock.CIDR == "" && (!selectorIsSimple(r.To.PodSelector) || !selectorIsEmpty(r.To.NamespaceSelector)) {
			continue
		}
		for _, p := range r.Ports {
			if p.PortName != "" || p.EndPort != nil {
				continue
			}
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
	if port.PortName != "" || port.EndPort != nil {
		return false
	}
	if len(rule.From.IPBlock.Except) > 0 {
		return false
	}
	if rule.From.IPBlock.CIDR == "" && (!selectorIsSimple(rule.From.PodSelector) || !selectorIsEmpty(rule.From.NamespaceSelector)) {
		return false
	}
	for _, r := range other.Spec.Ingress {
		if len(r.From.IPBlock.Except) > 0 {
			continue
		}
		if r.From.IPBlock.CIDR == "" && (!selectorIsSimple(r.From.PodSelector) || !selectorIsEmpty(r.From.NamespaceSelector)) {
			continue
		}
		for _, p := range r.Ports {
			if p.PortName != "" || p.EndPort != nil {
				continue
			}
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
	canonTenant := func(t string) string {
		t = strings.TrimSpace(t)
		if t == "" {
			return "default"
		}
		return t
	}

	candidateTenant := canonTenant(candidate.Tenant)
	candidateName := strings.TrimSpace(candidate.PolicyName)

	for _, np := range existing {
		if canonTenant(np.Tenant) != candidateTenant {
			continue
		}
		if strings.TrimSpace(np.PolicyName) == candidateName {
			continue
		}
		for _, egress := range candidate.Policy.Spec.Egress {
			for _, port := range egress.Ports {
				if overlapsEgress(egress, port, np.Policy) {
					return ValidationError{
						PolicyName: candidate.Policy.Metadata.Name,
						Field:      "conflict",
						Message:    fmt.Sprintf("conflicts with policy %s on %s/%d", np.KeyString(), port.Protocol, port.Port),
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
						Message:    fmt.Sprintf("conflicts with policy %s on %s/%d", np.KeyString(), port.Protocol, port.Port),
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

func (r *PolicyResolver) ResolveLabelsScoped(scope string, labels map[string]string) ([]string, error) {
	if r.discovery == nil {
		return nil, fmt.Errorf("no service discovery backend configured")
	}

	scope = strings.TrimSpace(scope)
	if scope != "" {
		if scoped, ok := r.discovery.(ScopedServiceDiscovery); ok {
			return scoped.ResolveLabelsScoped(scope, labels)
		}
	}

	return r.discovery.ResolveLabels(labels)
}

func (r *PolicyResolver) resolvePodsScoped(scope string, selector PodSelectorSpec) ([]PodInfo, error) {
	resolver, ok := r.discovery.(PodResolver)
	if !ok {
		return nil, fmt.Errorf("discovery backend does not support pod resolution")
	}
	scope = strings.TrimSpace(scope)
	if scope != "" {
		return resolver.ResolvePodsScoped(scope, selector)
	}
	return resolver.ResolvePods(selector)
}

func (r *PolicyResolver) resolveTargetPods(scope string, podSelector PodSelectorSpec, namespaceSelector PodSelectorSpec) ([]PodInfo, error) {
	if r.discovery == nil {
		return nil, fmt.Errorf("no service discovery backend configured")
	}
	if !selectorIsEmpty(namespaceSelector) {
		resolver, ok := r.discovery.(NamespaceResolver)
		if !ok {
			return nil, fmt.Errorf("discovery backend does not support namespaceSelector")
		}
		namespaces, err := resolver.ResolveNamespaces(namespaceSelector)
		if err != nil {
			return nil, err
		}
		if len(namespaces) == 0 {
			return nil, noMatchesError{reason: "namespaceSelector resolved to zero namespaces"}
		}
		pods := make([]PodInfo, 0)
		for _, ns := range namespaces {
			resolved, err := r.resolvePodsScoped(ns, podSelector)
			if err != nil {
				if isNoMatchesError(err) {
					continue
				}
				return nil, err
			}
			pods = append(pods, resolved...)
		}
		if len(pods) == 0 {
			return nil, noMatchesError{reason: "selector resolved to zero pods"}
		}
		return pods, nil
	}
	return r.resolvePodsScoped(scope, podSelector)
}

func (r *PolicyResolver) resolveSelectorIPs(scope string, selector PodSelectorSpec) ([]string, error) {
	if r.discovery == nil {
		return nil, fmt.Errorf("no service discovery backend configured")
	}
	if selectorIsEmpty(selector) {
		return r.ResolveLabelsScoped(scope, map[string]string{})
	}
	if len(selector.MatchExpressions) > 0 {
		resolver, ok := r.discovery.(SelectorResolver)
		if !ok {
			return nil, fmt.Errorf("discovery backend does not support matchExpressions")
		}
		scope = strings.TrimSpace(scope)
		if scope != "" {
			return resolver.ResolveSelectorScoped(scope, selector)
		}
		return resolver.ResolveSelector(selector)
	}
	return r.ResolveLabelsScoped(scope, selector.MatchLabels)
}

// ResolvePeerTargets resolves peer selectors (pod+namespace) into IPs.
func (r *PolicyResolver) ResolvePeerTargets(scope string, podSelector PodSelectorSpec, namespaceSelector PodSelectorSpec) ([]string, error) {
	if r.discovery == nil {
		return nil, fmt.Errorf("no service discovery backend configured")
	}
	if !selectorIsEmpty(namespaceSelector) {
		resolver, ok := r.discovery.(NamespaceResolver)
		if !ok {
			return nil, fmt.Errorf("discovery backend does not support namespaceSelector")
		}
		namespaces, err := resolver.ResolveNamespaces(namespaceSelector)
		if err != nil {
			return nil, err
		}
		if len(namespaces) == 0 {
			return nil, noMatchesError{reason: "namespaceSelector resolved to zero namespaces"}
		}
		ips := make([]string, 0)
		for _, ns := range namespaces {
			resolved, err := r.resolveSelectorIPs(ns, podSelector)
			if err != nil {
				if isNoMatchesError(err) {
					continue
				}
				return nil, err
			}
			ips = append(ips, resolved...)
		}
		if len(ips) == 0 {
			return nil, noMatchesError{reason: "selector resolved to zero pods"}
		}
		return dedupeAndSortStrings(ips), nil
	}
	return r.resolveSelectorIPs(scope, podSelector)
}

// ResolveLabels (standalone) is deprecated, use PolicyResolver instead
// Kept for backward compatibility
func ResolveLabels(labels map[string]string) ([]string, error) {
	return nil, fmt.Errorf("label resolution requires service discovery backend")
}

// ResolvePodSelectorsToIPBlocks translates all podSelector targets in the given policies
// into concrete /32 ipBlock targets using the resolver's discovery backend.
func (r *PolicyResolver) ResolvePodSelectorsToIPBlocks(policies []NetworkPolicy) ([]NetworkPolicy, error) {
	return r.ResolvePodSelectorsToIPBlocksScoped("", policies)
}

// ResolvePodSelectorsToIPBlocksScoped is the tenant/scope-aware variant of ResolvePodSelectorsToIPBlocks.
//
// If the underlying discovery backend does not implement ScopedServiceDiscovery (or scope is empty),
// this falls back to the legacy non-scoped ResolveLabels behavior.
func (r *PolicyResolver) ResolvePodSelectorsToIPBlocksScoped(scope string, policies []NetworkPolicy) ([]NetworkPolicy, error) {
	if r.discovery == nil {
		return nil, fmt.Errorf("no service discovery backend configured")
	}

	resolvedPolicies := make([]NetworkPolicy, 0, len(policies))

	for _, p := range policies {
		rp := p // Shallow copy
		rp.Spec.Egress = nil
		rp.Spec.Ingress = nil

		// Resolve Egress
		for _, egress := range p.Spec.Egress {
			hasSelectors := !selectorIsEmpty(egress.To.PodSelector) || !selectorIsEmpty(egress.To.NamespaceSelector)
			hasNamedPorts := HasNamedPorts(egress.Ports)
			if hasSelectors {
				if hasNamedPorts {
					pods, err := r.resolveTargetPods(scope, egress.To.PodSelector, egress.To.NamespaceSelector)
					if err != nil {
						if isNoMatchesError(err) {
							logging.Warnf("policy %s: egress selector resolved to zero pods (%v)", p.Metadata.Name, err)
							continue
						}
						return nil, fmt.Errorf("policy %s: failed to resolve egress selector: %w", p.Metadata.Name, err)
					}

					rulesAdded := 0
					for _, pod := range pods {
						cidr, err := ipToHostCIDR(pod.IP)
						if err != nil {
							return nil, fmt.Errorf("policy %s: invalid resolved IP for egress selector: %w", p.Metadata.Name, err)
						}
						portMap, err := BuildNamedPortMap(pod.Ports)
						if err != nil {
							target := strings.TrimSpace(pod.IP)
							if ns := strings.TrimSpace(pod.Namespace); ns != "" {
								target = ns + "/" + target
							}
							logging.Warnf("policy %s: named ports for destination %s are ambiguous: %v", p.Metadata.Name, target, err)
							continue
						}
						resolvedPorts, missing := ResolveNamedPorts(egress.Ports, portMap)
						if len(missing) > 0 {
							missing = dedupeAndSortStrings(missing)
							target := strings.TrimSpace(pod.IP)
							if ns := strings.TrimSpace(pod.Namespace); ns != "" {
								target = ns + "/" + target
							}
							logging.Warnf("policy %s: named ports %v not found on destination %s", p.Metadata.Name, missing, target)
						}
						if len(resolvedPorts) == 0 {
							continue
						}
						newEgress := egress
						newEgress.Ports = resolvedPorts
						newEgress.To.PodSelector = PodSelectorSpec{}
						newEgress.To.NamespaceSelector = PodSelectorSpec{}
						newEgress.To.IPBlock = IPBlockSpec{CIDR: cidr}
						rp.Spec.Egress = append(rp.Spec.Egress, newEgress)
						rulesAdded++
					}
					if rulesAdded == 0 {
						logging.Warnf("policy %s: named ports resolved to zero egress rules", p.Metadata.Name)
						continue
					}
					continue
				}

				ips, err := r.ResolvePeerTargets(scope, egress.To.PodSelector, egress.To.NamespaceSelector)
				if err != nil {
					if isNoMatchesError(err) {
						logging.Warnf("policy %s: egress selector resolved to zero pods (%v)", p.Metadata.Name, err)
						continue
					}
					return nil, fmt.Errorf("policy %s: failed to resolve egress selector: %w", p.Metadata.Name, err)
				}

				cidrs, err := ipsToHostCIDRs(ips)
				if err != nil {
					return nil, fmt.Errorf("policy %s: invalid resolved IP for egress selector: %w", p.Metadata.Name, err)
				}
				for _, cidr := range cidrs {
					newEgress := egress
					newEgress.To.PodSelector = PodSelectorSpec{}
					newEgress.To.NamespaceSelector = PodSelectorSpec{}
					newEgress.To.IPBlock = IPBlockSpec{CIDR: cidr}
					rp.Spec.Egress = append(rp.Spec.Egress, newEgress)
				}
				continue
			}

			if hasNamedPorts {
				return nil, fmt.Errorf("policy %s: named ports require podSelector or namespaceSelector in egress rules", p.Metadata.Name)
			}
			rp.Spec.Egress = append(rp.Spec.Egress, egress)
		}

		// Resolve Ingress
		for _, ingress := range p.Spec.Ingress {
			hasSelectors := !selectorIsEmpty(ingress.From.PodSelector) || !selectorIsEmpty(ingress.From.NamespaceSelector)
			hasNamedPorts := HasNamedPorts(ingress.Ports)
			if hasSelectors {
				if hasNamedPorts {
					pods, err := r.resolveTargetPods(scope, ingress.From.PodSelector, ingress.From.NamespaceSelector)
					if err != nil {
						if isNoMatchesError(err) {
							logging.Warnf("policy %s: ingress selector resolved to zero pods (%v)", p.Metadata.Name, err)
							continue
						}
						return nil, fmt.Errorf("policy %s: failed to resolve ingress selector: %w", p.Metadata.Name, err)
					}

					rulesAdded := 0
					for _, pod := range pods {
						cidr, err := ipToHostCIDR(pod.IP)
						if err != nil {
							return nil, fmt.Errorf("policy %s: invalid resolved IP for ingress selector: %w", p.Metadata.Name, err)
						}
						portMap, err := BuildNamedPortMap(pod.Ports)
						if err != nil {
							target := strings.TrimSpace(pod.IP)
							if ns := strings.TrimSpace(pod.Namespace); ns != "" {
								target = ns + "/" + target
							}
							logging.Warnf("policy %s: named ports for source %s are ambiguous: %v", p.Metadata.Name, target, err)
							continue
						}
						resolvedPorts, missing := ResolveNamedPorts(ingress.Ports, portMap)
						if len(missing) > 0 {
							missing = dedupeAndSortStrings(missing)
							target := strings.TrimSpace(pod.IP)
							if ns := strings.TrimSpace(pod.Namespace); ns != "" {
								target = ns + "/" + target
							}
							logging.Warnf("policy %s: named ports %v not found on source %s", p.Metadata.Name, missing, target)
						}
						if len(resolvedPorts) == 0 {
							continue
						}
						newIngress := ingress
						newIngress.Ports = resolvedPorts
						newIngress.From.PodSelector = PodSelectorSpec{}
						newIngress.From.NamespaceSelector = PodSelectorSpec{}
						newIngress.From.IPBlock = IPBlockSpec{CIDR: cidr}
						rp.Spec.Ingress = append(rp.Spec.Ingress, newIngress)
						rulesAdded++
					}
					if rulesAdded == 0 {
						logging.Warnf("policy %s: named ports resolved to zero ingress rules", p.Metadata.Name)
						continue
					}
					continue
				}

				ips, err := r.ResolvePeerTargets(scope, ingress.From.PodSelector, ingress.From.NamespaceSelector)
				if err != nil {
					if isNoMatchesError(err) {
						logging.Warnf("policy %s: ingress selector resolved to zero pods (%v)", p.Metadata.Name, err)
						continue
					}
					return nil, fmt.Errorf("policy %s: failed to resolve ingress selector: %w", p.Metadata.Name, err)
				}

				cidrs, err := ipsToHostCIDRs(ips)
				if err != nil {
					return nil, fmt.Errorf("policy %s: invalid resolved IP for ingress selector: %w", p.Metadata.Name, err)
				}
				for _, cidr := range cidrs {
					newIngress := ingress
					newIngress.From.PodSelector = PodSelectorSpec{}
					newIngress.From.NamespaceSelector = PodSelectorSpec{}
					newIngress.From.IPBlock = IPBlockSpec{CIDR: cidr}
					rp.Spec.Ingress = append(rp.Spec.Ingress, newIngress)
				}
				continue
			}
			if hasNamedPorts {
				return nil, fmt.Errorf("policy %s: named ports require podSelector or namespaceSelector in ingress rules", p.Metadata.Name)
			}
			rp.Spec.Ingress = append(rp.Spec.Ingress, ingress)
		}

		resolvedPolicies = append(resolvedPolicies, rp)
	}

	return resolvedPolicies, nil
}

func isNoMatchesError(err error) bool {
	type noMatches interface {
		NoMatches() bool
	}
	var nm noMatches
	if errors.As(err, &nm) {
		return nm.NoMatches()
	}
	return false
}

type noMatchesError struct {
	reason string
}

func (e noMatchesError) Error() string {
	if strings.TrimSpace(e.reason) == "" {
		return "no matches found"
	}
	return e.reason
}

func (e noMatchesError) NoMatches() bool {
	return true
}

func dedupeAndSortStrings(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, v := range values {
		trimmed := strings.TrimSpace(v)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	sort.Strings(out)
	return out
}

func ipsToHostCIDRs(ips []string) ([]string, error) {
	if len(ips) == 0 {
		return []string{}, nil
	}
	seen := make(map[string]struct{}, len(ips))
	out := make([]string, 0, len(ips))
	for _, raw := range ips {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		parsed := net.ParseIP(raw)
		if parsed == nil {
			return nil, fmt.Errorf("%q is not a valid IP address", raw)
		}
		if v4 := parsed.To4(); v4 != nil {
			ipStr := v4.String()
			if _, ok := seen[ipStr]; ok {
				continue
			}
			seen[ipStr] = struct{}{}
			out = append(out, ipStr+"/32")
			continue
		}
		if v6 := parsed.To16(); v6 != nil {
			ipStr := v6.String()
			if _, ok := seen[ipStr]; ok {
				continue
			}
			seen[ipStr] = struct{}{}
			out = append(out, ipStr+"/128")
			continue
		}
		return nil, fmt.Errorf("%q is not a valid IP address", raw)
	}
	sort.Strings(out)
	return out, nil
}

func ipToHostCIDR(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("empty IP")
	}
	parsed := net.ParseIP(raw)
	if parsed == nil {
		return "", fmt.Errorf("%q is not a valid IP address", raw)
	}
	if v4 := parsed.To4(); v4 != nil {
		return v4.String() + "/32", nil
	}
	if v6 := parsed.To16(); v6 != nil {
		return v6.String() + "/128", nil
	}
	return "", fmt.Errorf("%q is not a valid IP address", raw)
}

const maxIPBlockExpansion = 1024

// NormalizePolicies expands ipBlock.except into explicit CIDRs.
func NormalizePolicies(policies []NetworkPolicy) ([]NetworkPolicy, error) {
	if len(policies) == 0 {
		return nil, nil
	}

	out := make([]NetworkPolicy, 0, len(policies))
	for _, p := range policies {
		cp := p
		cp.Spec.Egress = nil
		cp.Spec.Ingress = nil

		for _, egress := range p.Spec.Egress {
			if egress.To.IPBlock.CIDR != "" && len(egress.To.IPBlock.Except) > 0 {
				cidrs, err := expandIPBlockExcept(egress.To.IPBlock, maxIPBlockExpansion)
				if err != nil {
					return nil, fmt.Errorf("policy %s: expand egress ipBlock: %w", p.Metadata.Name, err)
				}
				for _, cidr := range cidrs {
					newEgress := egress
					newEgress.To.IPBlock = IPBlockSpec{CIDR: cidr}
					cp.Spec.Egress = append(cp.Spec.Egress, newEgress)
				}
				continue
			}
			cp.Spec.Egress = append(cp.Spec.Egress, egress)
		}

		for _, ingress := range p.Spec.Ingress {
			if ingress.From.IPBlock.CIDR != "" && len(ingress.From.IPBlock.Except) > 0 {
				cidrs, err := expandIPBlockExcept(ingress.From.IPBlock, maxIPBlockExpansion)
				if err != nil {
					return nil, fmt.Errorf("policy %s: expand ingress ipBlock: %w", p.Metadata.Name, err)
				}
				for _, cidr := range cidrs {
					newIngress := ingress
					newIngress.From.IPBlock = IPBlockSpec{CIDR: cidr}
					cp.Spec.Ingress = append(cp.Spec.Ingress, newIngress)
				}
				continue
			}
			cp.Spec.Ingress = append(cp.Spec.Ingress, ingress)
		}

		out = append(out, cp)
	}

	return out, nil
}

// NeedsTargetResolution reports whether any policy uses pod or namespace selectors in peers.
func NeedsTargetResolution(policies []NetworkPolicy) bool {
	for _, p := range policies {
		for _, e := range p.Spec.Egress {
			if !selectorIsEmpty(e.To.PodSelector) || !selectorIsEmpty(e.To.NamespaceSelector) {
				return true
			}
		}
		for _, in := range p.Spec.Ingress {
			if !selectorIsEmpty(in.From.PodSelector) || !selectorIsEmpty(in.From.NamespaceSelector) {
				return true
			}
		}
	}
	return false
}

func expandIPBlockExcept(block IPBlockSpec, limit int) ([]string, error) {
	if strings.TrimSpace(block.CIDR) == "" {
		return nil, fmt.Errorf("missing cidr")
	}
	base, err := netip.ParsePrefix(strings.TrimSpace(block.CIDR))
	if err != nil {
		return nil, err
	}
	base = base.Masked()
	if len(block.Except) == 0 {
		return []string{base.String()}, nil
	}
	if limit <= 0 {
		limit = maxIPBlockExpansion
	}

	excepts := make([]netip.Prefix, 0, len(block.Except))
	for _, raw := range block.Except {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}
		except, err := netip.ParsePrefix(trimmed)
		if err != nil {
			return nil, err
		}
		excepts = append(excepts, except.Masked())
	}

	remaining := []netip.Prefix{base}
	for _, exc := range excepts {
		next := make([]netip.Prefix, 0, len(remaining))
		for _, rem := range remaining {
			parts, err := subtractPrefix(rem, exc, limit-len(next))
			if err != nil {
				return nil, err
			}
			next = append(next, parts...)
			if len(next) > limit {
				return nil, fmt.Errorf("cidr expansion exceeds %d entries", limit)
			}
		}
		remaining = next
		if len(remaining) == 0 {
			break
		}
	}

	sort.Slice(remaining, func(i, j int) bool { return remaining[i].String() < remaining[j].String() })
	output := make([]string, 0, len(remaining))
	for _, rem := range remaining {
		output = append(output, rem.String())
	}
	return output, nil
}

func subtractPrefix(base, except netip.Prefix, limit int) ([]netip.Prefix, error) {
	if !base.Overlaps(except) {
		return []netip.Prefix{base}, nil
	}
	if prefixContains(except, base) {
		return nil, nil
	}

	remaining := make([]netip.Prefix, 0)
	stack := []netip.Prefix{base}
	for len(stack) > 0 {
		p := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if !p.Overlaps(except) {
			remaining = append(remaining, p)
			continue
		}
		if prefixContains(except, p) {
			continue
		}
		childA, childB, err := splitPrefix(p)
		if err != nil {
			return nil, err
		}
		stack = append(stack, childA, childB)
		if limit > 0 && len(remaining)+len(stack) > limit {
			return nil, fmt.Errorf("cidr expansion exceeds %d entries", limit)
		}
	}
	return remaining, nil
}

func splitPrefix(prefix netip.Prefix) (netip.Prefix, netip.Prefix, error) {
	bits := prefix.Bits()
	maxBits := 128
	if prefix.Addr().Is4() {
		maxBits = 32
	}
	if bits >= maxBits {
		return netip.Prefix{}, netip.Prefix{}, fmt.Errorf("cannot split prefix %s", prefix.String())
	}
	base := prefix.Masked().Addr()
	childBits := bits + 1
	childA := netip.PrefixFrom(base, childBits)
	childBAddr, err := addrWithBit(base, bits)
	if err != nil {
		return netip.Prefix{}, netip.Prefix{}, err
	}
	childB := netip.PrefixFrom(childBAddr, childBits)
	return childA, childB, nil
}

func addrWithBit(addr netip.Addr, bit int) (netip.Addr, error) {
	if addr.Is4() {
		if bit < 0 || bit >= 32 {
			return netip.Addr{}, fmt.Errorf("invalid bit %d", bit)
		}
		b := addr.As4()
		byteIdx := bit / 8
		bitIdx := 7 - (bit % 8)
		b[byteIdx] |= 1 << bitIdx
		return netip.AddrFrom4(b), nil
	}
	if bit < 0 || bit >= 128 {
		return netip.Addr{}, fmt.Errorf("invalid bit %d", bit)
	}
	b := addr.As16()
	byteIdx := bit / 8
	bitIdx := 7 - (bit % 8)
	b[byteIdx] |= 1 << bitIdx
	return netip.AddrFrom16(b), nil
}
