//go:build !linux

package cli

import (
	"k8s.io/client-go/kubernetes"

	"ztap/internal/enforcer"
)

func newK8sSubjectResolver(client kubernetes.Interface, cgroupRoot string) enforcer.SubjectResolver {
	return nil
}
