package discovery

import (
	"context"
	"fmt"
	"sync"

	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
)

// K8sDiscovery implements ServiceDiscovery using the Kubernetes API.
type K8sDiscovery struct {
	factory   informers.SharedInformerFactory
	podLister listers.PodLister
	podSynced cache.InformerSynced
	stopOnce  sync.Once
	mu        sync.RWMutex
}

// NewK8sDiscovery creates a new Kubernetes-based discovery service.
func NewK8sDiscovery(client kubernetes.Interface, namespace string) *K8sDiscovery {
	factory := informers.NewSharedInformerFactoryWithOptions(client, 0, informers.WithNamespace(namespace))
	podInformer := factory.Core().V1().Pods()

	return &K8sDiscovery{
		factory:   factory,
		podLister: podInformer.Lister(),
		podSynced: podInformer.Informer().HasSynced,
	}
}

func (d *K8sDiscovery) Start(ctx context.Context) error {
	d.factory.Start(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), d.podSynced) {
		return fmt.Errorf("failed to sync kubernetes cache")
	}
	return nil
}

// Stop shuts down the informer factory.
func (d *K8sDiscovery) Stop() error {
	d.stopOnce.Do(func() {
		d.factory.Shutdown()
	})
	return nil
}

func (d *K8sDiscovery) ResolveLabels(selector map[string]string) ([]string, error) {
	set := labels.Set(selector)
	pods, err := d.podLister.List(set.AsSelector())
	if err != nil {
		return nil, err
	}

	ips := make([]string, 0)
	for _, pod := range pods {
		if pod.Status.PodIP != "" {
			ips = append(ips, pod.Status.PodIP)
		}
	}

	if len(ips) == 0 {
		return nil, fmt.Errorf("no pods found matching labels: %v", selector)
	}

	return ips, nil
}

func (d *K8sDiscovery) RegisterService(name string, ip string, labels map[string]string) error {
	return fmt.Errorf("RegisterService not supported in K8sDiscovery")
}

func (d *K8sDiscovery) DeregisterService(name string) error {
	return fmt.Errorf("DeregisterService not supported in K8sDiscovery")
}

func (d *K8sDiscovery) Watch(ctx context.Context, selector map[string]string) (<-chan []string, error) {
	// For now, we don't implement a streaming watch here,
	// but the agent can poll or we can add a real watch later.
	return nil, fmt.Errorf("Watch not yet implemented in K8sDiscovery")
}
