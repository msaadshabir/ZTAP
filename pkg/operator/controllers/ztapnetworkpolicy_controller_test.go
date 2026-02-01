package controllers

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	ztapv1alpha1 "ztap/pkg/operator/api/v1alpha1"
)

func TestZtapNetworkPolicyReconcileCreatesConfigMapAndStatus(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("add corev1 scheme: %v", err)
	}
	if err := ztapv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("add ztap scheme: %v", err)
	}

	policy := &ztapv1alpha1.ZtapNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "web-to-db",
			Namespace:  "default",
			UID:        types.UID("uid-123"),
			Generation: 1,
		},
		Spec: ztapv1alpha1.ZtapNetworkPolicySpec{
			PodSelector: ztapv1alpha1.PodSelectorSpec{
				MatchLabels: map[string]string{"app": "web"},
			},
			Egress: []ztapv1alpha1.EgressRule{{
				To: ztapv1alpha1.EgressTarget{IPBlock: &ztapv1alpha1.IPBlockSpec{CIDR: "10.0.0.0/8"}},
				Ports: []ztapv1alpha1.PortSpec{{
					Protocol: "TCP",
					Port:     443,
				}},
			}},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&ztapv1alpha1.ZtapNetworkPolicy{}).
		WithObjects(policy).
		Build()

	reconciler := &ZtapNetworkPolicyReconciler{Client: fakeClient, Scheme: scheme}

	ctx := context.Background()
	_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: "web-to-db", Namespace: "default"}})
	if err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}

	var updated ztapv1alpha1.ZtapNetworkPolicy
	if err := fakeClient.Get(ctx, types.NamespacedName{Name: "web-to-db", Namespace: "default"}, &updated); err != nil {
		t.Fatalf("get policy: %v", err)
	}
	if !containsFinalizer(updated.Finalizers, ztapFinalizer) {
		t.Fatalf("expected finalizer %q to be added", ztapFinalizer)
	}

	cmName := "ztap-policy-default-web-to-db"
	var cm corev1.ConfigMap
	if err := fakeClient.Get(ctx, types.NamespacedName{Name: cmName, Namespace: "default"}, &cm); err != nil {
		t.Fatalf("get configmap: %v", err)
	}
	if cm.Labels["app"] != "ztap" || cm.Labels["component"] != "policy-store" {
		t.Fatalf("unexpected configmap labels: %v", cm.Labels)
	}
	if cm.Annotations["ztap.io/policyName"] != "default/web-to-db" {
		t.Fatalf("unexpected policyName annotation: %q", cm.Annotations["ztap.io/policyName"])
	}
	if cm.Annotations["ztap.io/version"] != "1" {
		t.Fatalf("unexpected version annotation: %q", cm.Annotations["ztap.io/version"])
	}
	if cm.Data["policy.yaml"] == "" {
		t.Fatalf("expected policy.yaml to be populated")
	}

	if updated.Status.ObservedGeneration != 1 {
		t.Fatalf("expected observedGeneration=1, got %d", updated.Status.ObservedGeneration)
	}
	if updated.Status.LastPublishedVersion != 1 {
		t.Fatalf("expected lastPublishedVersion=1, got %d", updated.Status.LastPublishedVersion)
	}
	cond := findCondition(updated.Status.Conditions, "Validated")
	if cond == nil {
		t.Fatalf("expected Validated condition to be set")
	}
	if cond.Status != metav1.ConditionTrue || cond.Reason != "PolicyPublished" {
		t.Fatalf("unexpected Validated condition: status=%s reason=%s", cond.Status, cond.Reason)
	}
}

func TestZtapNetworkPolicyReconcileValidationFailure(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("add corev1 scheme: %v", err)
	}
	if err := ztapv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("add ztap scheme: %v", err)
	}

	policy := &ztapv1alpha1.ZtapNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "invalid",
			Namespace:  "default",
			UID:        types.UID("uid-456"),
			Generation: 2,
		},
		Spec: ztapv1alpha1.ZtapNetworkPolicySpec{
			PodSelector: ztapv1alpha1.PodSelectorSpec{
				MatchLabels: map[string]string{"app": "web"},
			},
			// Missing ingress/egress rules triggers validation error.
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&ztapv1alpha1.ZtapNetworkPolicy{}).
		WithObjects(policy).
		Build()

	reconciler := &ZtapNetworkPolicyReconciler{Client: fakeClient, Scheme: scheme}

	ctx := context.Background()
	_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: "invalid", Namespace: "default"}})
	if err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}

	var updated ztapv1alpha1.ZtapNetworkPolicy
	if err := fakeClient.Get(ctx, types.NamespacedName{Name: "invalid", Namespace: "default"}, &updated); err != nil {
		t.Fatalf("get policy: %v", err)
	}

	cmName := "ztap-policy-default-invalid"
	var cm corev1.ConfigMap
	if err := fakeClient.Get(ctx, types.NamespacedName{Name: cmName, Namespace: "default"}, &cm); err == nil {
		t.Fatalf("expected configmap not to be created on validation failure")
	}

	cond := findCondition(updated.Status.Conditions, "Validated")
	if cond == nil {
		t.Fatalf("expected Validated condition to be set")
	}
	if cond.Status != metav1.ConditionFalse || cond.Reason != "ValidationFailed" {
		t.Fatalf("unexpected Validated condition: status=%s reason=%s", cond.Status, cond.Reason)
	}
}

func TestZtapNetworkPolicyReconcileUpdatesConfigMap(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("add corev1 scheme: %v", err)
	}
	if err := ztapv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("add ztap scheme: %v", err)
	}

	policy := &ztapv1alpha1.ZtapNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "web-to-db",
			Namespace:  "default",
			UID:        types.UID("uid-789"),
			Generation: 3,
		},
		Spec: ztapv1alpha1.ZtapNetworkPolicySpec{
			PodSelector: ztapv1alpha1.PodSelectorSpec{
				MatchLabels: map[string]string{"app": "web"},
			},
			Egress: []ztapv1alpha1.EgressRule{{
				To: ztapv1alpha1.EgressTarget{IPBlock: &ztapv1alpha1.IPBlockSpec{CIDR: "10.0.0.0/8"}},
				Ports: []ztapv1alpha1.PortSpec{{
					Protocol: "TCP",
					Port:     443,
				}},
			}},
		},
	}

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ztap-policy-default-web-to-db",
			Namespace: "default",
			Labels: map[string]string{
				"app":       "ztap",
				"component": "policy-store",
			},
			Annotations: map[string]string{
				"ztap.io/policyName": "default/web-to-db",
				"ztap.io/version":    "1",
			},
		},
		Data: map[string]string{"policy.yaml": "stale"},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&ztapv1alpha1.ZtapNetworkPolicy{}).
		WithObjects(policy, cm).
		Build()

	reconciler := &ZtapNetworkPolicyReconciler{Client: fakeClient, Scheme: scheme}

	ctx := context.Background()
	_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: "web-to-db", Namespace: "default"}})
	if err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}

	var updatedCM corev1.ConfigMap
	if err := fakeClient.Get(ctx, types.NamespacedName{Name: "ztap-policy-default-web-to-db", Namespace: "default"}, &updatedCM); err != nil {
		t.Fatalf("get configmap: %v", err)
	}
	if updatedCM.Data["policy.yaml"] == "stale" {
		t.Fatalf("expected policy.yaml to be updated")
	}
	if updatedCM.Annotations["ztap.io/version"] != "3" {
		t.Fatalf("expected version annotation to be updated to 3, got %q", updatedCM.Annotations["ztap.io/version"])
	}
}

func TestZtapNetworkPolicyReconcileDeleteRemovesConfigMap(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("add corev1 scheme: %v", err)
	}
	if err := ztapv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("add ztap scheme: %v", err)
	}

	deletionTime := metav1.Now()
	policy := &ztapv1alpha1.ZtapNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "to-delete",
			Namespace:         "default",
			UID:               types.UID("uid-999"),
			Generation:        1,
			Finalizers:        []string{ztapFinalizer},
			DeletionTimestamp: &deletionTime,
		},
		Spec: ztapv1alpha1.ZtapNetworkPolicySpec{
			PodSelector: ztapv1alpha1.PodSelectorSpec{MatchLabels: map[string]string{"app": "web"}},
			Egress: []ztapv1alpha1.EgressRule{{
				To: ztapv1alpha1.EgressTarget{IPBlock: &ztapv1alpha1.IPBlockSpec{CIDR: "10.0.0.0/8"}},
				Ports: []ztapv1alpha1.PortSpec{{
					Protocol: "TCP",
					Port:     443,
				}},
			}},
		},
	}

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ztap-policy-default-to-delete",
			Namespace: "default",
		},
		Data: map[string]string{"policy.yaml": "data"},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&ztapv1alpha1.ZtapNetworkPolicy{}).
		WithObjects(policy, cm).
		Build()

	reconciler := &ZtapNetworkPolicyReconciler{Client: fakeClient, Scheme: scheme}

	ctx := context.Background()
	_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: "to-delete", Namespace: "default"}})
	if err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}

	var updated ztapv1alpha1.ZtapNetworkPolicy
	err = fakeClient.Get(ctx, types.NamespacedName{Name: "to-delete", Namespace: "default"}, &updated)
	if err == nil {
		if containsFinalizer(updated.Finalizers, ztapFinalizer) {
			t.Fatalf("expected finalizer to be removed")
		}
	}

	var deletedCM corev1.ConfigMap
	if err := fakeClient.Get(ctx, types.NamespacedName{Name: "ztap-policy-default-to-delete", Namespace: "default"}, &deletedCM); err == nil {
		t.Fatalf("expected configmap to be deleted")
	}
}

func containsFinalizer(finalizers []string, finalizer string) bool {
	for _, f := range finalizers {
		if f == finalizer {
			return true
		}
	}
	return false
}

func findCondition(conditions []metav1.Condition, conditionType string) *metav1.Condition {
	for i := range conditions {
		if conditions[i].Type == conditionType {
			return &conditions[i]
		}
	}
	return nil
}
