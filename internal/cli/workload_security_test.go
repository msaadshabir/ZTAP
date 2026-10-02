package cli

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func safeWorkloadSecurityContext() *corev1.SecurityContext {
	no := false
	return &corev1.SecurityContext{
		AllowPrivilegeEscalation: &no,
		Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"NET_RAW"}},
	}
}

func TestPacketSocketIsolationChecksEveryContainer(t *testing.T) {
	for _, kind := range []string{"regular", "init", "ephemeral"} {
		for _, unsafe := range []string{"missing", "default-escalation", "escalation", "privileged", "missing-drop", "add-raw", "add-admin"} {
			t.Run(kind+"/"+unsafe, func(t *testing.T) {
				security := safeWorkloadSecurityContext()
				yes := true
				switch unsafe {
				case "missing":
					security = nil
				case "default-escalation":
					security.AllowPrivilegeEscalation = nil
				case "escalation":
					security.AllowPrivilegeEscalation = &yes
				case "privileged":
					security.Privileged = &yes
				case "missing-drop":
					security.Capabilities.Drop = nil
				case "add-raw":
					security.Capabilities.Add = []corev1.Capability{"NET_RAW"}
				case "add-admin":
					security.Capabilities.Add = []corev1.Capability{"SYS_ADMIN"}
				}
				pod := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "unsafe"}, Spec: corev1.PodSpec{
					Containers: []corev1.Container{{Name: "safe", SecurityContext: safeWorkloadSecurityContext()}},
				}}
				switch kind {
				case "regular":
					pod.Spec.Containers = append(pod.Spec.Containers, corev1.Container{Name: "bad", SecurityContext: security})
				case "init":
					pod.Spec.InitContainers = []corev1.Container{{Name: "bad", SecurityContext: security}}
				case "ephemeral":
					pod.Spec.EphemeralContainers = []corev1.EphemeralContainer{{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "bad", SecurityContext: security}}}
				}
				if err := validatePacketSocketIsolation([]corev1.Pod{pod}); err == nil || !strings.Contains(err.Error(), "apps/unsafe container bad") {
					t.Fatalf("unsafe container accepted or unidentified: %v", err)
				}
			})
		}
	}
}

func TestPacketSocketIsolationAllowsSafeAndOutOfScopePods(t *testing.T) {
	security := safeWorkloadSecurityContext()
	security.Capabilities.Drop = []corev1.Capability{"ALL"}
	security.Capabilities.Add = []corev1.Capability{"NET_BIND_SERVICE"}
	pods := []corev1.Pod{
		{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "safe", SecurityContext: security}}}},
		{Spec: corev1.PodSpec{HostNetwork: true, Containers: []corev1.Container{{Name: "host"}}}},
		{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "done"}}}, Status: corev1.PodStatus{Phase: corev1.PodSucceeded}},
		{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "failed"}}}, Status: corev1.PodStatus{Phase: corev1.PodFailed}},
	}
	if err := validatePacketSocketIsolation(pods); err != nil {
		t.Fatal(err)
	}
}
