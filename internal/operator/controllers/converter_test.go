package controllers

import (
	"bytes"
	"testing"

	yaml "gopkg.in/yaml.v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"ztap/internal/operator/api/v1alpha1"
)

func TestToInternalPolicyPreservesComplianceAnnotations(t *testing.T) {
	ztnp := &v1alpha1.ZtapNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "p1",
			Namespace: "ns1",
			Annotations: map[string]string{
				"ztap.io/compliance.pci-dss": "10.2.1",
				"ztap.io/compliance.soc2":    "CC7.2",
				"some.other/key":             "nope",
			},
		},
		Spec: v1alpha1.ZtapNetworkPolicySpec{
			PodSelector: v1alpha1.PodSelectorSpec{MatchLabels: map[string]string{"app": "x"}},
			Egress: []v1alpha1.EgressRule{{
				To: v1alpha1.EgressTarget{IPBlock: &v1alpha1.IPBlockSpec{CIDR: "10.0.0.0/8"}},
				Ports: []v1alpha1.PortSpec{{
					Protocol: "TCP",
					Port:     443,
				}},
			}},
		},
	}

	internal := ToInternalPolicy(ztnp)
	if internal.Metadata.Annotations == nil {
		t.Fatalf("expected annotations")
	}
	if internal.Metadata.Annotations["ztap.io/compliance.pci-dss"] != "10.2.1" {
		t.Fatalf("expected pci annotation to be preserved")
	}
	if internal.Metadata.Annotations["ztap.io/compliance.soc2"] != "CC7.2" {
		t.Fatalf("expected soc2 annotation to be preserved")
	}
	if _, ok := internal.Metadata.Annotations["some.other/key"]; ok {
		t.Fatalf("expected non-compliance annotation to be dropped")
	}

	b, err := yaml.Marshal(internal)
	if err != nil {
		t.Fatalf("yaml.Marshal: %v", err)
	}
	if !bytes.Contains(b, []byte("annotations:")) {
		t.Fatalf("expected annotations section in YAML")
	}
	if !bytes.Contains(b, []byte("ztap.io/compliance.pci-dss")) {
		t.Fatalf("expected pci annotation in YAML")
	}
}

func TestToInternalPolicyNoComplianceAnnotationsOmitsMetadataAnnotations(t *testing.T) {
	ztnp := &v1alpha1.ZtapNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "p1",
			Namespace: "ns1",
			Annotations: map[string]string{
				"some.other/key": "nope",
			},
		},
		Spec: v1alpha1.ZtapNetworkPolicySpec{
			PodSelector: v1alpha1.PodSelectorSpec{MatchLabels: map[string]string{"app": "x"}},
		},
	}

	internal := ToInternalPolicy(ztnp)
	if internal.Metadata.Annotations != nil {
		t.Fatalf("expected annotations to be nil when no compliance annotations present")
	}
}
