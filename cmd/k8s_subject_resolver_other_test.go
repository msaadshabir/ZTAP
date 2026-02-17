//go:build !linux

package cmd

import (
	"testing"

	"k8s.io/client-go/kubernetes/fake"
)

func TestNewK8sSubjectResolver_NonLinuxReturnsNil(t *testing.T) {
	resolver := newK8sSubjectResolver(fake.NewSimpleClientset(), "")
	if resolver != nil {
		t.Fatalf("expected nil resolver on non-linux platforms")
	}
}
