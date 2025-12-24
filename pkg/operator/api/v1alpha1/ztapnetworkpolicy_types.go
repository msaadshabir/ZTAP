package v1alpha1

import (
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
	MatchLabels map[string]string `json:"matchLabels"`
}

// IPBlockSpec defines CIDR-based selection.
type IPBlockSpec struct {
	CIDR string `json:"cidr"`
}

// PortSpec defines a protocol and port combination for network rules.
type PortSpec struct {
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
}

// EgressTarget defines the destination for egress rules.
type EgressTarget struct {
	PodSelector *PodSelectorSpec `json:"podSelector,omitempty"`
	IPBlock     *IPBlockSpec     `json:"ipBlock,omitempty"`
}

// IngressSource defines the source for ingress rules.
type IngressSource struct {
	PodSelector *PodSelectorSpec `json:"podSelector,omitempty"`
	IPBlock     *IPBlockSpec     `json:"ipBlock,omitempty"`
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

func init() {
	SchemeBuilder.Register(&ZtapNetworkPolicy{}, &ZtapNetworkPolicyList{})
}

// DeepCopyInto copies all properties of this object into another object of the
// same type.
func (in *ZtapNetworkPolicy) DeepCopyInto(out *ZtapNetworkPolicy) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	out.Spec = in.Spec
	out.Status = in.Status
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
