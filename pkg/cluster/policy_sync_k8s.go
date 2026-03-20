package cluster

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
)

var k8sPolicySyncLogger = ctrl.Log.WithName("K8sPolicySync")

// K8sPolicySync implements PolicySync by watching policy ConfigMaps created by the operator.
type K8sPolicySync struct {
	client      kubernetes.Interface
	namespaces  []string
	allNS       bool
	subscribers []chan PolicyUpdate
	mu          sync.RWMutex
	stopCh      chan struct{}
	running     bool
}

// NewK8sPolicySync creates a new Kubernetes-backed policy synchronization backend.
func NewK8sPolicySync(client kubernetes.Interface, namespace string) *K8sPolicySync {
	if strings.TrimSpace(namespace) == "" {
		namespace = DefaultTenant
	}
	return NewK8sPolicySyncNamespaces(client, []string{namespace})
}

// NewK8sPolicySyncNamespaces creates a policy sync backend watching a namespace allow-list.
func NewK8sPolicySyncNamespaces(client kubernetes.Interface, namespaces []string) *K8sPolicySync {
	namespaces = normalizeNamespaces(namespaces)
	if len(namespaces) == 0 {
		namespaces = []string{DefaultTenant}
	}
	return &K8sPolicySync{
		client:     client,
		namespaces: namespaces,
		stopCh:     make(chan struct{}),
	}
}

// NewK8sPolicySyncAllNamespaces creates a policy sync backend watching all namespaces.
func NewK8sPolicySyncAllNamespaces(client kubernetes.Interface) *K8sPolicySync {
	return &K8sPolicySync{
		client: client,
		allNS:  true,
		stopCh: make(chan struct{}),
	}
}

func normalizeNamespaces(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, ns := range in {
		ns = strings.TrimSpace(ns)
		if ns == "" {
			continue
		}
		if _, ok := seen[ns]; ok {
			continue
		}
		seen[ns] = struct{}{}
		out = append(out, ns)
	}
	return out
}

func removePolicySubscriberLocked(subscribers []chan PolicyUpdate, ch chan PolicyUpdate) ([]chan PolicyUpdate, bool) {
	for i, sub := range subscribers {
		if sub == ch {
			return append(subscribers[:i], subscribers[i+1:]...), true
		}
	}
	return subscribers, false
}

// Start begins watching policy ConfigMaps for updates.
func (s *K8sPolicySync) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return nil
	}
	s.stopCh = make(chan struct{})
	s.running = true
	s.mu.Unlock()

	if err := s.syncExisting(ctx); err != nil {
		k8sPolicySyncLogger.Error(err, "error listing existing policies")
		return err
	}

	go s.watchLoop(ctx)
	return nil
}

// Stop stops watching for updates and closes subscriber channels.
func (s *K8sPolicySync) Stop() error {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return nil
	}
	close(s.stopCh)
	for _, ch := range s.subscribers {
		close(ch)
	}
	s.subscribers = nil
	s.running = false
	s.mu.Unlock()
	return nil
}

// SyncPolicy is not supported for Kubernetes-backed sync since policies flow from the operator.
func (s *K8sPolicySync) SyncPolicy(ctx context.Context, policyName string, policyYAML []byte) error {
	return fmt.Errorf("SyncPolicy not supported in K8sPolicySync; use the ZtapNetworkPolicy CRD instead")
}

// GetPolicyVersion is not currently tracked for the Kubernetes backend.
func (s *K8sPolicySync) GetPolicyVersion(policyName string) (int64, error) {
	return 0, nil
}

// SubscribePolicies returns a channel that receives policy updates.
func (s *K8sPolicySync) SubscribePolicies(ctx context.Context) <-chan PolicyUpdate {
	ch := make(chan PolicyUpdate, 100)

	s.mu.Lock()
	s.subscribers = append(s.subscribers, ch)
	s.mu.Unlock()

	go func() {
		<-ctx.Done()
		s.mu.Lock()
		var removed bool
		s.subscribers, removed = removePolicySubscriberLocked(s.subscribers, ch)
		s.mu.Unlock()
		if removed {
			close(ch)
		}
	}()

	return ch
}

func (s *K8sPolicySync) watchLoop(ctx context.Context) {
	if s.allNS {
		go s.watchNamespace(ctx, metav1.NamespaceAll)
		return
	}

	for _, ns := range s.namespaces {
		ns := ns
		go s.watchNamespace(ctx, ns)
	}
}

func (s *K8sPolicySync) watchNamespace(ctx context.Context, namespace string) {
	watcher, err := s.client.CoreV1().ConfigMaps(namespace).Watch(ctx, metav1.ListOptions{
		LabelSelector: "app=ztap,component=policy-store",
	})
	if err != nil {
		k8sPolicySyncLogger.Error(err, "error watching ConfigMaps", "namespace", namespace)
		return
	}
	defer watcher.Stop()

	for {
		select {
		case event, ok := <-watcher.ResultChan():
			if !ok {
				return
			}
			if event.Type != watch.Added && event.Type != watch.Modified {
				continue
			}
			cm, ok := event.Object.(*corev1.ConfigMap)
			if !ok {
				continue
			}
			s.handleUpdate(cm)
		case <-ctx.Done():
			return
		case <-s.stopCh:
			return
		}
	}
}

func (s *K8sPolicySync) syncExisting(ctx context.Context) error {
	if s.allNS {
		return s.syncExistingNamespace(ctx, metav1.NamespaceAll)
	}
	for _, ns := range s.namespaces {
		if err := s.syncExistingNamespace(ctx, ns); err != nil {
			return err
		}
	}
	return nil
}

func (s *K8sPolicySync) syncExistingNamespace(ctx context.Context, namespace string) error {
	configMaps, err := s.client.CoreV1().ConfigMaps(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: "app=ztap,component=policy-store",
	})
	if err != nil {
		return err
	}
	for i := range configMaps.Items {
		s.handleUpdate(&configMaps.Items[i])
	}
	return nil
}

func (s *K8sPolicySync) handleUpdate(cm *corev1.ConfigMap) {
	policyYAML, ok := cm.Data["policy.yaml"]
	if !ok {
		return
	}
	policyName := strings.TrimSpace(cm.Annotations["ztap.io/policyName"])
	if policyName == "" {
		policyName = cm.Name
	}
	parsed, err := ParsePolicyKey(policyName)
	if err != nil {
		parsed = PolicyKey{Tenant: cm.Namespace, Name: cm.Name}
	}
	// The authoritative tenant for a ConfigMap-backed policy is the ConfigMap namespace.
	parsed.Tenant = cm.Namespace
	versionStr := cm.Annotations["ztap.io/version"]

	var version int64
	if versionStr != "" {
		if _, err := fmt.Sscanf(versionStr, "%d", &version); err != nil {
			k8sPolicySyncLogger.Info("invalid policy version annotation", "version", versionStr, "error", err)
			version = 0
		}
	}

	update := PolicyUpdate{
		Tenant:     parsed.Tenant,
		PolicyName: parsed.Name,
		YAML:       []byte(policyYAML),
		Version:    version,
		Source:     "kubernetes-operator",
		Timestamp:  time.Now(),
		Deleted:    false,
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, ch := range s.subscribers {
		select {
		case ch <- update:
		default:
			k8sPolicySyncLogger.Info("dropping policy update", "policyKey", update.PolicyKeyString(), "reason", "subscriber channel full")
		}
	}
}
