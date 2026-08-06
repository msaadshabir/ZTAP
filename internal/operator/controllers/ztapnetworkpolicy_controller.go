package controllers

import (
	"context"
	"fmt"
	"strconv"

	"gopkg.in/yaml.v3"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	ztapv1alpha1 "ztap/internal/operator/api/v1alpha1"
)

const (
	ztapFinalizer = "ztap.io/finalizer"
)

// ZtapNetworkPolicyReconciler reconciles a ZtapNetworkPolicy object
type ZtapNetworkPolicyReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=ztap.io,resources=ztapnetworkpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=ztap.io,resources=ztapnetworkpolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=ztap.io,resources=ztapnetworkpolicies/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch;create;update;patch;delete

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *ZtapNetworkPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	l := log.FromContext(ctx)

	// Fetch the ZtapNetworkPolicy instance
	var ztnp ztapv1alpha1.ZtapNetworkPolicy
	if err := r.Get(ctx, req.NamespacedName, &ztnp); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	l.Info("Reconciling ZtapNetworkPolicy", "name", ztnp.Name, "namespace", ztnp.Namespace)

	// Handle deletion
	if !ztnp.DeletionTimestamp.IsZero() {
		return r.reconcileDelete(ctx, &ztnp)
	}

	// Add finalizer if not present
	if !controllerutil.ContainsFinalizer(&ztnp, ztapFinalizer) {
		controllerutil.AddFinalizer(&ztnp, ztapFinalizer)
		if err := r.Update(ctx, &ztnp); err != nil {
			return ctrl.Result{}, err
		}
	}

	// 1. Convert to internal policy
	internalPolicy := ToInternalPolicy(&ztnp)

	// 2. Validate
	if err := internalPolicy.Validate(); err != nil {
		l.Error(err, "Validation failed for policy")
		return r.updateStatus(ctx, &ztnp, metav1.ConditionFalse, "ValidationFailed", fmt.Sprintf("Validation failed: %v", err))
	}

	// 3. Serialize to YAML
	policyYAML, err := yaml.Marshal(internalPolicy)
	if err != nil {
		l.Error(err, "Failed to marshal policy to YAML")
		return ctrl.Result{}, err
	}

	// 4. Publish to ConfigMap store
	if err := r.publishPolicy(ctx, &ztnp, policyYAML); err != nil {
		l.Error(err, "Failed to publish policy to ConfigMap store")
		return r.updateStatus(ctx, &ztnp, metav1.ConditionFalse, "PublishFailed", fmt.Sprintf("Publish failed: %v", err))
	}

	return r.updateStatus(ctx, &ztnp, metav1.ConditionTrue, "PolicyPublished", "Policy published successfully")
}

func (r *ZtapNetworkPolicyReconciler) reconcileDelete(ctx context.Context, ztnp *ztapv1alpha1.ZtapNetworkPolicy) (ctrl.Result, error) {
	l := log.FromContext(ctx)

	if controllerutil.ContainsFinalizer(ztnp, ztapFinalizer) {
		// Remove the ConfigMap
		cmName := fmt.Sprintf("ztap-policy-%s-%s", ztnp.Namespace, ztnp.Name)
		cm := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      cmName,
				Namespace: ztnp.Namespace,
			},
		}
		if err := r.Delete(ctx, cm); err != nil && client.IgnoreNotFound(err) != nil {
			l.Error(err, "Failed to delete policy ConfigMap")
			return ctrl.Result{}, err
		}

		controllerutil.RemoveFinalizer(ztnp, ztapFinalizer)
		if err := r.Update(ctx, ztnp); err != nil {
			return ctrl.Result{}, err
		}
	}

	return ctrl.Result{}, nil
}

func (r *ZtapNetworkPolicyReconciler) publishPolicy(ctx context.Context, ztnp *ztapv1alpha1.ZtapNetworkPolicy, policyYAML []byte) error {
	cmName := fmt.Sprintf("ztap-policy-%s-%s", ztnp.Namespace, ztnp.Name)

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cmName,
			Namespace: ztnp.Namespace,
			Labels: map[string]string{
				"app":       "ztap",
				"component": "policy-store",
			},
			Annotations: map[string]string{
				"ztap.io/policyName": fmt.Sprintf("%s/%s", ztnp.Namespace, ztnp.Name),
				"ztap.io/version":    strconv.FormatInt(ztnp.Generation, 10),
			},
		},
		Data: map[string]string{
			"policy.yaml": string(policyYAML),
		},
	}

	// Set owner reference
	if err := controllerutil.SetControllerReference(ztnp, cm, r.Scheme); err != nil {
		return err
	}

	existingCM := &corev1.ConfigMap{}
	err := r.Get(ctx, types.NamespacedName{Name: cmName, Namespace: ztnp.Namespace}, existingCM)
	if err != nil {
		if client.IgnoreNotFound(err) == nil {
			return r.Create(ctx, cm)
		}
		return err
	}

	if !equality.Semantic.DeepEqual(cm.Data, existingCM.Data) || !equality.Semantic.DeepEqual(cm.Labels, existingCM.Labels) || !equality.Semantic.DeepEqual(cm.Annotations, existingCM.Annotations) {
		existingCM.Data = cm.Data
		existingCM.Labels = cm.Labels
		existingCM.Annotations = cm.Annotations
		return r.Update(ctx, existingCM)
	}

	return nil
}

func (r *ZtapNetworkPolicyReconciler) updateStatus(ctx context.Context, ztnp *ztapv1alpha1.ZtapNetworkPolicy, status metav1.ConditionStatus, reason, message string) (ctrl.Result, error) {
	condition := metav1.Condition{
		Type:               "Validated",
		Status:             status,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: ztnp.Generation,
	}

	meta.SetStatusCondition(&ztnp.Status.Conditions, condition)
	ztnp.Status.ObservedGeneration = ztnp.Generation
	if status == metav1.ConditionTrue {
		ztnp.Status.LastPublishedVersion = ztnp.Generation
	}

	if err := r.Status().Update(ctx, ztnp); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *ZtapNetworkPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&ztapv1alpha1.ZtapNetworkPolicy{}).
		Owns(&corev1.ConfigMap{}).
		Complete(r)
}
