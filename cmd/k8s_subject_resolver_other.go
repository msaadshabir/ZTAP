//go:build !linux

package cmd

import (
	"k8s.io/client-go/kubernetes"

	"ztap/pkg/enforcer"
)

func newK8sSubjectResolver(client kubernetes.Interface, cgroupRoot string) enforcer.SubjectResolver {
	return nil
}
