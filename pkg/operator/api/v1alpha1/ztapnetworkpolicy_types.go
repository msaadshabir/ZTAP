package v1alpha1

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// ZtapNetworkPolicySpec defines the desired state of ZtapNetworkPolicy.
type ZtapNetworkPolicySpec struct {
	PodSelector PodSelectorSpec `json:"podSelector"`
	Egress      []EgressRule    `json:"egress,omitempty"`
	Ingress     []IngressRule   `json:"ingress,omitempty"`
}

// PodSelectorSpec defines label-based pod selection.
type PodSelectorSpec struct {
	MatchLabels      map[string]string          `json:"matchLabels,omitempty"`
	MatchExpressions []LabelSelectorRequirement `json:"matchExpressions,omitempty"`
}

// LabelSelectorRequirement defines a selector requirement.
type LabelSelectorRequirement struct {
	Key      string   `json:"key"`
	Operator string   `json:"operator"`
	Values   []string `json:"values,omitempty"`
}

// IPBlockSpec defines CIDR-based IP selection.
type IPBlockSpec struct {
	CIDR   string   `json:"cidr"`
	Except []string `json:"except,omitempty"`
}

// PortSpec defines a protocol and port combination for network rules.
type PortSpec struct {
	Protocol string `json:"protocol"`
	Port     int    `json:"-"`
	PortName string `json:"-"`
	EndPort  *int   `json:"endPort,omitempty"`
}

type portSpecWire struct {
	Protocol string `json:"protocol"`
	Port     any    `json:"port"`
	EndPort  *int   `json:"endPort,omitempty"`
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
	out := portSpecWire{
		Protocol: p.Protocol,
		Port:     portValueForMarshal(p.Port, p.PortName),
		EndPort:  p.EndPort,
	}
	return json.Marshal(out)
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

// EgressTarget defines the destination for egress rules.
type EgressTarget struct {
	PodSelector       *PodSelectorSpec `json:"podSelector,omitempty"`
	NamespaceSelector *PodSelectorSpec `json:"namespaceSelector,omitempty"`
	IPBlock           *IPBlockSpec     `json:"ipBlock,omitempty"`
}

// IngressSource defines the source for ingress rules.
type IngressSource struct {
	PodSelector       *PodSelectorSpec `json:"podSelector,omitempty"`
	NamespaceSelector *PodSelectorSpec `json:"namespaceSelector,omitempty"`
	IPBlock           *IPBlockSpec     `json:"ipBlock,omitempty"`
}

// EgressRule defines an outbound traffic rule.
type EgressRule struct {
	To    EgressTarget `json:"to"`
	Ports []PortSpec   `json:"ports"`
}

// IngressRule defines an inbound traffic rule.
type IngressRule struct {
	From  IngressSource `json:"from"`
	Ports []PortSpec    `json:"ports"`
}

// ZtapNetworkPolicyStatus defines the observed state of ZtapNetworkPolicy.
type ZtapNetworkPolicyStatus struct {
	ObservedGeneration   int64              `json:"observedGeneration,omitempty"`
	LastPublishedVersion int64              `json:"lastPublishedVersion,omitempty"`
	Conditions           []metav1.Condition `json:"conditions,omitempty"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status
//+kubebuilder:resource:shortName=ztnp

// ZtapNetworkPolicy is the Schema for the ztapnetworkpolicies API.
type ZtapNetworkPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ZtapNetworkPolicySpec   `json:"spec,omitempty"`
	Status ZtapNetworkPolicyStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// ZtapNetworkPolicyList contains a list of ZtapNetworkPolicy.
type ZtapNetworkPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ZtapNetworkPolicy `json:"items"`
}

// DeepCopyInto copies all properties of this object into another object of the
// same type.
func (in *ZtapNetworkPolicy) DeepCopyInto(out *ZtapNetworkPolicy) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	if specCopy := in.Spec.DeepCopy(); specCopy != nil {
		out.Spec = *specCopy
	}
	if statusCopy := in.Status.DeepCopy(); statusCopy != nil {
		out.Status = *statusCopy
	}
}

// DeepCopy creates a new DeepCopy of the receiver.
func (in *ZtapNetworkPolicy) DeepCopy() *ZtapNetworkPolicy {
	if in == nil {
		return nil
	}
	out := new(ZtapNetworkPolicy)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject copies the receiver into a new runtime.Object.
func (in *ZtapNetworkPolicy) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto copies the receiver into out.
func (in *ZtapNetworkPolicyList) DeepCopyInto(out *ZtapNetworkPolicyList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		out.Items = make([]ZtapNetworkPolicy, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&out.Items[i])
		}
	}
}

// DeepCopy creates a new DeepCopy of the list.
func (in *ZtapNetworkPolicyList) DeepCopy() *ZtapNetworkPolicyList {
	if in == nil {
		return nil
	}
	out := new(ZtapNetworkPolicyList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject copies the list into a new runtime.Object.
func (in *ZtapNetworkPolicyList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopy creates a deep copy of the spec.
func (in *ZtapNetworkPolicySpec) DeepCopy() *ZtapNetworkPolicySpec {
	if in == nil {
		return nil
	}
	out := new(ZtapNetworkPolicySpec)
	*out = *in

	if in.PodSelector.MatchLabels != nil {
		out.PodSelector.MatchLabels = make(map[string]string, len(in.PodSelector.MatchLabels))
		for k, v := range in.PodSelector.MatchLabels {
			out.PodSelector.MatchLabels[k] = v
		}
	}
	if in.PodSelector.MatchExpressions != nil {
		out.PodSelector.MatchExpressions = make([]LabelSelectorRequirement, len(in.PodSelector.MatchExpressions))
		copy(out.PodSelector.MatchExpressions, in.PodSelector.MatchExpressions)
	}

	if in.Egress != nil {
		out.Egress = make([]EgressRule, len(in.Egress))
		for i := range in.Egress {
			out.Egress[i] = in.Egress[i].DeepCopy()
		}
	}
	if in.Ingress != nil {
		out.Ingress = make([]IngressRule, len(in.Ingress))
		for i := range in.Ingress {
			out.Ingress[i] = in.Ingress[i].DeepCopy()
		}
	}

	return out
}

// DeepCopy creates a deep copy of the status.
func (in *ZtapNetworkPolicyStatus) DeepCopy() *ZtapNetworkPolicyStatus {
	if in == nil {
		return nil
	}
	out := new(ZtapNetworkPolicyStatus)
	*out = *in
	if in.Conditions != nil {
		out.Conditions = make([]metav1.Condition, len(in.Conditions))
		for i := range in.Conditions {
			in.Conditions[i].DeepCopyInto(&out.Conditions[i])
		}
	}
	return out
}

func (in *EgressRule) DeepCopy() EgressRule {
	out := EgressRule{
		Ports: make([]PortSpec, len(in.Ports)),
		To:    in.To.DeepCopy(),
	}
	for i := range in.Ports {
		out.Ports[i] = in.Ports[i]
		if in.Ports[i].EndPort != nil {
			v := *in.Ports[i].EndPort
			out.Ports[i].EndPort = &v
		}
	}
	return out
}

func (in *IngressRule) DeepCopy() IngressRule {
	out := IngressRule{
		Ports: make([]PortSpec, len(in.Ports)),
		From:  in.From.DeepCopy(),
	}
	for i := range in.Ports {
		out.Ports[i] = in.Ports[i]
		if in.Ports[i].EndPort != nil {
			v := *in.Ports[i].EndPort
			out.Ports[i].EndPort = &v
		}
	}
	return out
}

func (in *EgressTarget) DeepCopy() EgressTarget {
	out := EgressTarget{}
	if in.PodSelector != nil {
		ps := PodSelectorSpec{}
		if in.PodSelector.MatchLabels != nil {
			ps.MatchLabels = make(map[string]string, len(in.PodSelector.MatchLabels))
			for k, v := range in.PodSelector.MatchLabels {
				ps.MatchLabels[k] = v
			}
		}
		if in.PodSelector.MatchExpressions != nil {
			ps.MatchExpressions = make([]LabelSelectorRequirement, len(in.PodSelector.MatchExpressions))
			copy(ps.MatchExpressions, in.PodSelector.MatchExpressions)
		}
		out.PodSelector = &ps
	}
	if in.NamespaceSelector != nil {
		ns := PodSelectorSpec{}
		if in.NamespaceSelector.MatchLabels != nil {
			ns.MatchLabels = make(map[string]string, len(in.NamespaceSelector.MatchLabels))
			for k, v := range in.NamespaceSelector.MatchLabels {
				ns.MatchLabels[k] = v
			}
		}
		if in.NamespaceSelector.MatchExpressions != nil {
			ns.MatchExpressions = make([]LabelSelectorRequirement, len(in.NamespaceSelector.MatchExpressions))
			copy(ns.MatchExpressions, in.NamespaceSelector.MatchExpressions)
		}
		out.NamespaceSelector = &ns
	}
	if in.IPBlock != nil {
		ip := *in.IPBlock
		if in.IPBlock.Except != nil {
			ip.Except = make([]string, len(in.IPBlock.Except))
			copy(ip.Except, in.IPBlock.Except)
		}
		out.IPBlock = &ip
	}
	return out
}

func (in *IngressSource) DeepCopy() IngressSource {
	out := IngressSource{}
	if in.PodSelector != nil {
		ps := PodSelectorSpec{}
		if in.PodSelector.MatchLabels != nil {
			ps.MatchLabels = make(map[string]string, len(in.PodSelector.MatchLabels))
			for k, v := range in.PodSelector.MatchLabels {
				ps.MatchLabels[k] = v
			}
		}
		if in.PodSelector.MatchExpressions != nil {
			ps.MatchExpressions = make([]LabelSelectorRequirement, len(in.PodSelector.MatchExpressions))
			copy(ps.MatchExpressions, in.PodSelector.MatchExpressions)
		}
		out.PodSelector = &ps
	}
	if in.NamespaceSelector != nil {
		ns := PodSelectorSpec{}
		if in.NamespaceSelector.MatchLabels != nil {
			ns.MatchLabels = make(map[string]string, len(in.NamespaceSelector.MatchLabels))
			for k, v := range in.NamespaceSelector.MatchLabels {
				ns.MatchLabels[k] = v
			}
		}
		if in.NamespaceSelector.MatchExpressions != nil {
			ns.MatchExpressions = make([]LabelSelectorRequirement, len(in.NamespaceSelector.MatchExpressions))
			copy(ns.MatchExpressions, in.NamespaceSelector.MatchExpressions)
		}
		out.NamespaceSelector = &ns
	}
	if in.IPBlock != nil {
		ip := *in.IPBlock
		if in.IPBlock.Except != nil {
			ip.Except = make([]string, len(in.IPBlock.Except))
			copy(ip.Except, in.IPBlock.Except)
		}
		out.IPBlock = &ip
	}
	return out
}
