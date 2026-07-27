package discovery

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"

	"ztap/pkg/policy"
)

// K8sDiscovery implements ServiceDiscovery using the Kubernetes API.
type K8sDiscovery struct {
	factory   informers.SharedInformerFactory
	podLister listers.PodLister
	podSynced cache.InformerSynced
	stopOnce  sync.Once
	mu        sync.RWMutex
	watchers  []*k8sWatcher
}

type k8sWatcher struct {
	selector labels.Selector
	ch       chan []string
	lastIPs  []string
}

// NewK8sDiscovery creates a new Kubernetes-based discovery service.
func NewK8sDiscovery(client kubernetes.Interface, namespace string) (*K8sDiscovery, error) {
	factory := informers.NewSharedInformerFactoryWithOptions(client, 0, informers.WithNamespace(namespace))
	podInformer := factory.Core().V1().Pods()

	d := &K8sDiscovery{
		factory:   factory,
		podLister: podInformer.Lister(),
		podSynced: podInformer.Informer().HasSynced,
		watchers:  make([]*k8sWatcher, 0),
	}

	_, err := podInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj any) {
			d.notifyWatchers()
		},
		UpdateFunc: func(oldObj, newObj any) {
			oldPod := oldObj.(*corev1.Pod)
			newPod := newObj.(*corev1.Pod)
			if oldPod.Status.PodIP != newPod.Status.PodIP || !labels.Equals(oldPod.Labels, newPod.Labels) {
				d.notifyWatchers()
			}
		},
		DeleteFunc: func(obj any) {
			d.notifyWatchers()
		},
	})
	if err != nil {
		return nil, fmt.Errorf("adding pod informer event handler: %w", err)
	}

	return d, nil
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
		return nil, &NoMatchesError{Resource: "pods", Labels: copyLabelMap(selector)}
	}

	slices.Sort(ips)
	return ips, nil
}

// ResolveSelector resolves pods using matchLabels + matchExpressions.
func (d *K8sDiscovery) ResolveSelector(selector policy.PodSelectorSpec) ([]string, error) {
	sel, err := selectorFromPolicy(selector)
	if err != nil {
		return nil, err
	}
	pods, err := d.podLister.List(sel)
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
		return nil, &NoMatchesError{Resource: "pods", Labels: copyLabelMap(selector.MatchLabels)}
	}

	slices.Sort(ips)
	return ips, nil
}

// ResolvePods resolves pods and their ports for a selector.
func (d *K8sDiscovery) ResolvePods(selector policy.PodSelectorSpec) ([]policy.PodInfo, error) {
	sel, err := selectorFromPolicy(selector)
	if err != nil {
		return nil, err
	}
	pods, err := d.podLister.List(sel)
	if err != nil {
		return nil, err
	}

	infos := make([]policy.PodInfo, 0)
	for _, pod := range pods {
		if pod.Status.PodIP == "" {
			continue
		}
		info := policy.PodInfo{
			IP:        pod.Status.PodIP,
			Namespace: pod.Namespace,
			Labels:    copyLabelMap(pod.Labels),
			Ports:     podPortsFromSpec(pod),
		}
		infos = append(infos, info)
	}

	if len(infos) == 0 {
		return nil, &NoMatchesError{Resource: "pods", Labels: copyLabelMap(selector.MatchLabels)}
	}

	return infos, nil
}

// ResolvePodsScoped ignores scope for namespace-scoped discovery.
func (d *K8sDiscovery) ResolvePodsScoped(scope string, selector policy.PodSelectorSpec) ([]policy.PodInfo, error) {
	return d.ResolvePods(selector)
}

// ResolveSelectorScoped ignores scope for namespace-scoped discovery.
func (d *K8sDiscovery) ResolveSelectorScoped(scope string, selector policy.PodSelectorSpec) ([]string, error) {
	return d.ResolveSelector(selector)
}

func (d *K8sDiscovery) RegisterService(name string, ip string, labels map[string]string) error {
	return fmt.Errorf("RegisterService not supported in K8sDiscovery")
}

func (d *K8sDiscovery) DeregisterService(name string) error {
	return fmt.Errorf("DeregisterService not supported in K8sDiscovery")
}

func (d *K8sDiscovery) Watch(ctx context.Context, selector map[string]string) (<-chan []string, error) {
	set := labels.Set(selector)
	sel := set.AsSelector()
	ch := make(chan []string, 10)

	watcher := &k8sWatcher{
		selector: sel,
		ch:       ch,
	}

	d.mu.Lock()
	d.watchers = append(d.watchers, watcher)
	d.mu.Unlock()

	// Send initial state
	ips, err := d.ResolveLabels(selector)
	if err != nil {
		// NoMatchesError is expected when no pods match yet; treat as empty
		if _, ok := errors.AsType[*NoMatchesError](err); !ok {
			d.mu.Lock()
			for i, w := range d.watchers {
				if w == watcher {
					d.watchers = append(d.watchers[:i], d.watchers[i+1:]...)
					break
				}
			}
			d.mu.Unlock()
			close(ch)
			return nil, fmt.Errorf("resolving initial watch state: %w", err)
		}
		ips = nil
	}
	watcher.lastIPs = ips
	ch <- ips

	go func() {
		<-ctx.Done()
		d.mu.Lock()
		defer d.mu.Unlock()
		for i, w := range d.watchers {
			if w == watcher {
				d.watchers = append(d.watchers[:i], d.watchers[i+1:]...)
				break
			}
		}
		close(ch)
	}()

	return ch, nil
}

// WatchSelector watches pods using matchLabels + matchExpressions.
func (d *K8sDiscovery) WatchSelector(ctx context.Context, selector policy.PodSelectorSpec) (<-chan []string, error) {
	sel, err := selectorFromPolicy(selector)
	if err != nil {
		return nil, err
	}
	ch := make(chan []string, 10)

	watcher := &k8sWatcher{
		selector: sel,
		ch:       ch,
	}

	d.mu.Lock()
	d.watchers = append(d.watchers, watcher)
	d.mu.Unlock()

	// Send initial state
	ips, err := d.ResolveSelector(selector)
	if err != nil {
		// NoMatchesError is expected when no pods match yet; treat as empty
		if _, ok := errors.AsType[*NoMatchesError](err); !ok {
			d.mu.Lock()
			for i, w := range d.watchers {
				if w == watcher {
					d.watchers = append(d.watchers[:i], d.watchers[i+1:]...)
					break
				}
			}
			d.mu.Unlock()
			close(ch)
			return nil, fmt.Errorf("resolving initial watch selector state: %w", err)
		}
		ips = nil
	}
	watcher.lastIPs = ips
	ch <- ips

	go func() {
		<-ctx.Done()
		d.mu.Lock()
		defer d.mu.Unlock()
		for i, w := range d.watchers {
			if w == watcher {
				d.watchers = append(d.watchers[:i], d.watchers[i+1:]...)
				break
			}
		}
		close(ch)
	}()

	return ch, nil
}

// WatchSelectorScoped ignores scope for namespace-scoped discovery.
func (d *K8sDiscovery) WatchSelectorScoped(ctx context.Context, scope string, selector policy.PodSelectorSpec) (<-chan []string, error) {
	return d.WatchSelector(ctx, selector)
}

func selectorFromPolicy(selector policy.PodSelectorSpec) (labels.Selector, error) {
	if len(selector.MatchExpressions) == 0 {
		return labels.Set(selector.MatchLabels).AsSelector(), nil
	}
	reqs := make([]metav1.LabelSelectorRequirement, 0, len(selector.MatchExpressions))
	for _, expr := range selector.MatchExpressions {
		reqs = append(reqs, metav1.LabelSelectorRequirement{
			Key:      expr.Key,
			Operator: metav1.LabelSelectorOperator(expr.Operator),
			Values:   expr.Values,
		})
	}
	labelSelector := &metav1.LabelSelector{MatchLabels: selector.MatchLabels, MatchExpressions: reqs}
	return metav1.LabelSelectorAsSelector(labelSelector)
}

func podPortsFromSpec(pod *corev1.Pod) []policy.PodPort {
	ports := make([]policy.PodPort, 0)
	for _, container := range pod.Spec.Containers {
		for _, port := range container.Ports {
			name := strings.TrimSpace(port.Name)
			if name == "" {
				continue
			}
			proto := strings.ToUpper(string(port.Protocol))
			if proto == "" {
				proto = "TCP"
			}
			ports = append(ports, policy.PodPort{
				Name:     name,
				Protocol: proto,
				Port:     int(port.ContainerPort),
			})
		}
	}
	return ports
}

func (d *K8sDiscovery) notifyWatchers() {
	d.mu.Lock()
	defer d.mu.Unlock()

	for _, w := range d.watchers {
		pods, err := d.podLister.List(w.selector)
		if err != nil {
			continue
		}

		ips := make([]string, 0)
		for _, pod := range pods {
			if pod.Status.PodIP != "" {
				ips = append(ips, pod.Status.PodIP)
			}
		}
		slices.Sort(ips)

		// Only send if changed
		if !equalStrings(ips, w.lastIPs) {
			w.lastIPs = ips
			select {
			case w.ch <- ips:
			default:
				// Skip if channel is full
			}
		}
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
