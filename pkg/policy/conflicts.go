package policy

import (
	"fmt"
	"net"
)

// ConflictType represents the type of policy conflict
type ConflictType string

const (
	ConflictDuplicateName     ConflictType = "duplicate_name"
	ConflictOverlappingCIDR   ConflictType = "overlapping_cidr"
	ConflictSameSelectorRules ConflictType = "same_selector_rules"
)

// Conflict represents a detected policy conflict
type Conflict struct {
	Type        ConflictType
	Policy1     string
	Policy2     string
	Description string
}

func (c Conflict) Error() string {
	return fmt.Sprintf("%s: %s conflicts with %s: %s", c.Type, c.Policy1, c.Policy2, c.Description)
}

// DetectConflicts analyzes a set of policies and returns any conflicts
func DetectConflicts(policies []NetworkPolicy) []Conflict {
	conflicts := make([]Conflict, 0)

	for i := 0; i < len(policies); i++ {
		for j := i + 1; j < len(policies); j++ {
			conflicts = append(conflicts, detectPairwiseConflicts(policies[i], policies[j])...)
		}
	}

	return conflicts
}

// detectPairwiseConflicts detects conflicts between two policies
func detectPairwiseConflicts(p1, p2 NetworkPolicy) []Conflict {
	conflicts := make([]Conflict, 0)

	// Check for duplicate names
	if p1.Metadata.Name == p2.Metadata.Name {
		conflicts = append(conflicts, Conflict{
			Type:        ConflictDuplicateName,
			Policy1:     p1.Metadata.Name,
			Policy2:     p2.Metadata.Name,
			Description: "policies have the same name",
		})
		return conflicts
	}

	// Check if policies target the same pods
	if !labelsMatch(p1.Spec.PodSelector.MatchLabels, p2.Spec.PodSelector.MatchLabels) {
		return conflicts
	}

	// Check for egress conflicts
	for i, egress1 := range p1.Spec.Egress {
		for j, egress2 := range p2.Spec.Egress {
			if conflict := detectEgressConflict(p1.Metadata.Name, p2.Metadata.Name, i, j, egress1, egress2); conflict != nil {
				conflicts = append(conflicts, *conflict)
			}
		}
	}

	// Check for ingress conflicts
	for i, ingress1 := range p1.Spec.Ingress {
		for j, ingress2 := range p2.Spec.Ingress {
			if conflict := detectIngressConflict(p1.Metadata.Name, p2.Metadata.Name, i, j, ingress1, ingress2); conflict != nil {
				conflicts = append(conflicts, *conflict)
			}
		}
	}

	return conflicts
}

// detectEgressConflict detects conflicts between two egress rules
func detectEgressConflict(policy1, policy2 string, idx1, idx2 int, egress1, egress2 EgressRule) *Conflict {
	// Check for same target with different ports/protocols (exact match)
	if (egress1.To.IPBlock.CIDR != "" && egress1.To.IPBlock.CIDR == egress2.To.IPBlock.CIDR) ||
		(len(egress1.To.PodSelector.MatchLabels) > 0 && len(egress2.To.PodSelector.MatchLabels) > 0 &&
			labelsMatch(egress1.To.PodSelector.MatchLabels, egress2.To.PodSelector.MatchLabels)) {
		if !portsMatch(egress1.Ports, egress2.Ports) {
			return &Conflict{
				Type:    ConflictSameSelectorRules,
				Policy1: policy1,
				Policy2: policy2,
				Description: fmt.Sprintf("egress rules target same destination but specify different ports/protocols (rule %d vs %d)",
					idx1, idx2),
			}
		}
		return nil
	}

	// Check for overlapping CIDR ranges (non-identical)
	if egress1.To.IPBlock.CIDR != "" && egress2.To.IPBlock.CIDR != "" &&
		egress1.To.IPBlock.CIDR != egress2.To.IPBlock.CIDR {
		overlap, err := cidrsOverlap(egress1.To.IPBlock.CIDR, egress2.To.IPBlock.CIDR)
		if err == nil && overlap {
			if !portsMatch(egress1.Ports, egress2.Ports) {
				return &Conflict{
					Type:    ConflictOverlappingCIDR,
					Policy1: policy1,
					Policy2: policy2,
					Description: fmt.Sprintf("egress rules with overlapping CIDRs but different port/protocol specifications (rule %d vs %d)",
						idx1, idx2),
				}
			}
		}
	}

	return nil
}

// detectIngressConflict detects conflicts between two ingress rules
func detectIngressConflict(policy1, policy2 string, idx1, idx2 int, ingress1, ingress2 IngressRule) *Conflict {
	// Check for same source with different ports/protocols (exact match)
	if (ingress1.From.IPBlock.CIDR != "" && ingress1.From.IPBlock.CIDR == ingress2.From.IPBlock.CIDR) ||
		(len(ingress1.From.PodSelector.MatchLabels) > 0 && len(ingress2.From.PodSelector.MatchLabels) > 0 &&
			labelsMatch(ingress1.From.PodSelector.MatchLabels, ingress2.From.PodSelector.MatchLabels)) {
		if !portsMatch(ingress1.Ports, ingress2.Ports) {
			return &Conflict{
				Type:    ConflictSameSelectorRules,
				Policy1: policy1,
				Policy2: policy2,
				Description: fmt.Sprintf("ingress rules have same source but specify different ports/protocols (rule %d vs %d)",
					idx1, idx2),
			}
		}
		return nil
	}

	// Check for overlapping CIDR ranges (non-identical)
	if ingress1.From.IPBlock.CIDR != "" && ingress2.From.IPBlock.CIDR != "" &&
		ingress1.From.IPBlock.CIDR != ingress2.From.IPBlock.CIDR {
		overlap, err := cidrsOverlap(ingress1.From.IPBlock.CIDR, ingress2.From.IPBlock.CIDR)
		if err == nil && overlap {
			if !portsMatch(ingress1.Ports, ingress2.Ports) {
				return &Conflict{
					Type:    ConflictOverlappingCIDR,
					Policy1: policy1,
					Policy2: policy2,
					Description: fmt.Sprintf("ingress rules with overlapping CIDRs but different port/protocol specifications (rule %d vs %d)",
						idx1, idx2),
				}
			}
		}
	}

	return nil
}

// labelsMatch checks if two label sets are identical
func labelsMatch(labels1, labels2 map[string]string) bool {
	if len(labels1) != len(labels2) {
		return false
	}
	for k, v := range labels1 {
		if labels2[k] != v {
			return false
		}
	}
	return true
}

// portsMatch checks if two port specifications are identical
func portsMatch(ports1, ports2 []PortSpec) bool {
	if len(ports1) != len(ports2) {
		return false
	}

	portMap := make(map[string]bool)
	for _, p := range ports1 {
		portMap[fmt.Sprintf("%s:%d", p.Protocol, p.Port)] = true
	}

	for _, p := range ports2 {
		if !portMap[fmt.Sprintf("%s:%d", p.Protocol, p.Port)] {
			return false
		}
	}

	return true
}

// cidrsOverlap checks if two CIDR ranges overlap
func cidrsOverlap(cidr1, cidr2 string) (bool, error) {
	_, net1, err := net.ParseCIDR(cidr1)
	if err != nil {
		return false, fmt.Errorf("invalid CIDR %s: %w", cidr1, err)
	}

	_, net2, err := net.ParseCIDR(cidr2)
	if err != nil {
		return false, fmt.Errorf("invalid CIDR %s: %w", cidr2, err)
	}

	// Check if net1 contains net2's network address or vice versa
	return net1.Contains(net2.IP) || net2.Contains(net1.IP), nil
}
