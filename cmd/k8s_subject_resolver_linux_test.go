//go:build linux

package cmd

import (
	"testing"

	"k8s.io/client-go/kubernetes/fake"
)

func TestNewK8sSubjectResolver_LinuxDefaults(t *testing.T) {
	resolver := newK8sSubjectResolver(fake.NewClientset(), "")
	linuxResolver, ok := resolver.(*k8sSubjectResolver)
	if !ok {
		t.Fatalf("expected linux resolver implementation")
	}
	if linuxResolver.cgroupRoot != "/sys/fs/cgroup" {
		t.Fatalf("expected default cgroup root, got %s", linuxResolver.cgroupRoot)
	}

	resolver = newK8sSubjectResolver(fake.NewClientset(), "/custom/cgroup")
	linuxResolver, ok = resolver.(*k8sSubjectResolver)
	if !ok {
		t.Fatalf("expected linux resolver implementation")
	}
	if linuxResolver.cgroupRoot != "/custom/cgroup" {
		t.Fatalf("expected custom cgroup root, got %s", linuxResolver.cgroupRoot)
	}
}
