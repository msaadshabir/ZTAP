package cluster

import (
	"context"
	"fmt"
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
	namespace   string
	subscribers []chan PolicyUpdate
	mu          sync.RWMutex
	stopCh      chan struct{}
	running     bool
}

// NewK8sPolicySync creates a new Kubernetes-backed policy synchronization backend.
func NewK8sPolicySync(client kubernetes.Interface, namespace string) *K8sPolicySync {
	return &K8sPolicySync{
		client:    client,
		namespace: namespace,
		stopCh:    make(chan struct{}),
	}
}

// Start begins watching policy ConfigMaps for updates.
func (s *K8sPolicySync) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return nil
	}
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
		for i, sub := range s.subscribers {
			if sub == ch {
				s.subscribers = append(s.subscribers[:i], s.subscribers[i+1:]...)
				break
			}
		}
		close(ch)
		s.mu.Unlock()
	}()

	return ch
}

func (s *K8sPolicySync) watchLoop(ctx context.Context) {
	watcher, err := s.client.CoreV1().ConfigMaps(s.namespace).Watch(ctx, metav1.ListOptions{
		LabelSelector: "app=ztap,component=policy-store",
	})
	if err != nil {
		k8sPolicySyncLogger.Error(err, "error watching ConfigMaps")
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
	configMaps, err := s.client.CoreV1().ConfigMaps(s.namespace).List(ctx, metav1.ListOptions{
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
	policyName := cm.Annotations["ztap.io/policyName"]
	if policyName == "" {
		policyName = fmt.Sprintf("%s/%s", cm.Namespace, cm.Name)
	}
	versionStr := cm.Annotations["ztap.io/version"]

	var version int64
	if versionStr != "" {
		if _, err := fmt.Sscanf(versionStr, "%d", &version); err != nil {
			k8sPolicySyncLogger.Info("invalid policy version annotation", "version", versionStr, "error", err)
			version = 0
		}
	}

	update := PolicyUpdate{
		PolicyName: policyName,
		YAML:       []byte(policyYAML),
		Version:    version,
		Source:     "kubernetes-operator",
		Timestamp:  time.Now(),
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, ch := range s.subscribers {
		select {
		case ch <- update:
		default:
			k8sPolicySyncLogger.Info("dropping policy update", "policyName", policyName, "reason", "subscriber channel full")
		}
	}
}
