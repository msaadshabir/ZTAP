package discovery

import (
	"context"
	"fmt"
	"sort"
	"sync"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"

	"ztap/pkg/policy"
)

// K8sDiscoveryAllNamespaces implements tenant-scoped label resolution across all namespaces.
//
// It is intended for multi-tenant usage where the caller always provides a namespace scope.
// The unscoped ResolveLabels/Watch methods default to the "default" namespace for backward compatibility.
type K8sDiscoveryAllNamespaces struct {
	factory   informers.SharedInformerFactory
	podLister listers.PodLister
	podSynced cache.InformerSynced
	nsLister  listers.NamespaceLister
	nsSynced  cache.InformerSynced
	stopOnce  sync.Once

	mu       sync.RWMutex
	watchers []*k8sScopedWatcher
}

type k8sScopedWatcher struct {
	namespace string
	selector  labels.Selector
	ch        chan []string
	lastIPs   []string
}

func NewK8sDiscoveryAllNamespaces(client kubernetes.Interface) (*K8sDiscoveryAllNamespaces, error) {
	factory := informers.NewSharedInformerFactory(client, 0)
	podInformer := factory.Core().V1().Pods()
	namespaceInformer := factory.Core().V1().Namespaces()

	d := &K8sDiscoveryAllNamespaces{
		factory:   factory,
		podLister: podInformer.Lister(),
		podSynced: podInformer.Informer().HasSynced,
		nsLister:  namespaceInformer.Lister(),
		nsSynced:  namespaceInformer.Informer().HasSynced,
		watchers:  make([]*k8sScopedWatcher, 0),
	}

	_, err := podInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			if p, ok := obj.(*corev1.Pod); ok {
				d.notifyWatchersNamespace(p.Namespace)
				return
			}
			d.notifyWatchersAll()
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			oldPod, okOld := oldObj.(*corev1.Pod)
			newPod, okNew := newObj.(*corev1.Pod)
			if okOld && okNew {
				if oldPod.Status.PodIP != newPod.Status.PodIP || !labels.Equals(oldPod.Labels, newPod.Labels) {
					d.notifyWatchersNamespace(newPod.Namespace)
				}
				return
			}
			d.notifyWatchersAll()
		},
		DeleteFunc: func(obj interface{}) {
			// Delete events may arrive as a tombstone.
			pod, ok := obj.(*corev1.Pod)
			if !ok {
				if tombstone, ok := obj.(cache.DeletedFinalStateUnknown); ok {
					pod, _ = tombstone.Obj.(*corev1.Pod)
				}
			}
			if pod != nil {
				d.notifyWatchersNamespace(pod.Namespace)
				return
			}
			d.notifyWatchersAll()
		},
	})
	if err != nil {
		return nil, fmt.Errorf("adding pod informer event handler: %w", err)
	}

	_, err = namespaceInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			d.notifyWatchersAll()
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			oldNs, okOld := oldObj.(*corev1.Namespace)
			newNs, okNew := newObj.(*corev1.Namespace)
			if okOld && okNew {
				if !labels.Equals(oldNs.Labels, newNs.Labels) {
					d.notifyWatchersAll()
				}
				return
			}
			d.notifyWatchersAll()
		},
		DeleteFunc: func(obj interface{}) {
			d.notifyWatchersAll()
		},
	})
	if err != nil {
		return nil, fmt.Errorf("adding namespace informer event handler: %w", err)
	}

	return d, nil
}

func (d *K8sDiscoveryAllNamespaces) Start(ctx context.Context) error {
	d.factory.Start(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), d.podSynced) {
		return fmt.Errorf("failed to sync kubernetes cache")
	}
	if !cache.WaitForCacheSync(ctx.Done(), d.nsSynced) {
		return fmt.Errorf("failed to sync kubernetes namespace cache")
	}
	return nil
}

func (d *K8sDiscoveryAllNamespaces) Stop() error {
	d.stopOnce.Do(func() {
		d.factory.Shutdown()
	})
	return nil
}

// ResolveLabels is a backward-compatible unscoped lookup.
//
// In multi-tenant usage, prefer ResolveLabelsScoped().
func (d *K8sDiscoveryAllNamespaces) ResolveLabels(selector map[string]string) ([]string, error) {
	return d.ResolveLabelsScoped("default", selector)
}

func (d *K8sDiscoveryAllNamespaces) ResolveLabelsScoped(scope string, selector map[string]string) ([]string, error) {
	if scope == "" {
		scope = "default"
	}

	set := labels.Set(selector)
	pods, err := d.podLister.Pods(scope).List(set.AsSelector())
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
		return nil, &NoMatchesError{Resource: "pods", Scope: scope, Labels: copyLabelMap(selector)}
	}

	sort.Strings(ips)
	return ips, nil
}

// ResolvePods is a backward-compatible unscoped lookup for selector specs.
func (d *K8sDiscoveryAllNamespaces) ResolvePods(selector policy.PodSelectorSpec) ([]policy.PodInfo, error) {
	return d.ResolvePodsScoped("default", selector)
}

func (d *K8sDiscoveryAllNamespaces) ResolvePodsScoped(scope string, selector policy.PodSelectorSpec) ([]policy.PodInfo, error) {
	if scope == "" {
		scope = "default"
	}
	sel, err := selectorFromPolicy(selector)
	if err != nil {
		return nil, err
	}
	pods, err := d.podLister.Pods(scope).List(sel)
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
		return nil, &NoMatchesError{Resource: "pods", Scope: scope, Labels: copyLabelMap(selector.MatchLabels)}
	}

	return infos, nil
}

// ResolveSelector is a backward-compatible unscoped lookup for selector specs.
func (d *K8sDiscoveryAllNamespaces) ResolveSelector(selector policy.PodSelectorSpec) ([]string, error) {
	return d.ResolveSelectorScoped("default", selector)
}

func (d *K8sDiscoveryAllNamespaces) ResolveSelectorScoped(scope string, selector policy.PodSelectorSpec) ([]string, error) {
	if scope == "" {
		scope = "default"
	}
	sel, err := selectorFromPolicy(selector)
	if err != nil {
		return nil, err
	}
	pods, err := d.podLister.Pods(scope).List(sel)
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
		return nil, &NoMatchesError{Resource: "pods", Scope: scope, Labels: copyLabelMap(selector.MatchLabels)}
	}

	sort.Strings(ips)
	return ips, nil
}

// ResolveNamespaces returns namespaces matching the selector.
func (d *K8sDiscoveryAllNamespaces) ResolveNamespaces(selector policy.PodSelectorSpec) ([]string, error) {
	sel, err := selectorFromPolicy(selector)
	if err != nil {
		return nil, err
	}
	namespaces, err := d.nsLister.List(sel)
	if err != nil {
		return nil, err
	}
	if len(namespaces) == 0 {
		return nil, &NoMatchesError{Resource: "namespaces", Labels: copyLabelMap(selector.MatchLabels)}
	}

	out := make([]string, 0, len(namespaces))
	for _, ns := range namespaces {
		out = append(out, ns.Name)
	}
	sort.Strings(out)
	return out, nil
}

func (d *K8sDiscoveryAllNamespaces) RegisterService(name string, ip string, labels map[string]string) error {
	return fmt.Errorf("RegisterService not supported in K8sDiscoveryAllNamespaces")
}

func (d *K8sDiscoveryAllNamespaces) DeregisterService(name string) error {
	return fmt.Errorf("DeregisterService not supported in K8sDiscoveryAllNamespaces")
}

// Watch is a backward-compatible unscoped watch.
//
// In multi-tenant usage, prefer WatchScoped().
func (d *K8sDiscoveryAllNamespaces) Watch(ctx context.Context, selector map[string]string) (<-chan []string, error) {
	return d.WatchScoped(ctx, "default", selector)
}

func (d *K8sDiscoveryAllNamespaces) WatchScoped(ctx context.Context, scope string, selector map[string]string) (<-chan []string, error) {
	if scope == "" {
		scope = "default"
	}

	set := labels.Set(selector)
	sel := set.AsSelector()
	ch := make(chan []string, 10)

	watcher := &k8sScopedWatcher{
		namespace: scope,
		selector:  sel,
		ch:        ch,
	}

	d.mu.Lock()
	d.watchers = append(d.watchers, watcher)
	d.mu.Unlock()

	// Send initial state.
	ips, _ := d.ResolveLabelsScoped(scope, selector)
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

// WatchSelector is a backward-compatible unscoped watch for selector specs.
func (d *K8sDiscoveryAllNamespaces) WatchSelector(ctx context.Context, selector policy.PodSelectorSpec) (<-chan []string, error) {
	return d.WatchSelectorScoped(ctx, "default", selector)
}

func (d *K8sDiscoveryAllNamespaces) WatchSelectorScoped(ctx context.Context, scope string, selector policy.PodSelectorSpec) (<-chan []string, error) {
	if scope == "" {
		scope = "default"
	}
	sel, err := selectorFromPolicy(selector)
	if err != nil {
		return nil, err
	}
	ch := make(chan []string, 10)

	watcher := &k8sScopedWatcher{
		namespace: scope,
		selector:  sel,
		ch:        ch,
	}

	d.mu.Lock()
	d.watchers = append(d.watchers, watcher)
	d.mu.Unlock()

	// Send initial state.
	ips, _ := d.ResolveSelectorScoped(scope, selector)
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

func (d *K8sDiscoveryAllNamespaces) notifyWatchersAll() {
	d.mu.Lock()
	watchers := append([]*k8sScopedWatcher(nil), d.watchers...)
	d.mu.Unlock()

	for _, w := range watchers {
		d.notifyWatcher(w)
	}
}

func (d *K8sDiscoveryAllNamespaces) notifyWatchersNamespace(namespace string) {
	d.mu.Lock()
	watchers := make([]*k8sScopedWatcher, 0, len(d.watchers))
	for _, w := range d.watchers {
		if w.namespace == namespace {
			watchers = append(watchers, w)
		}
	}
	d.mu.Unlock()

	for _, w := range watchers {
		d.notifyWatcher(w)
	}
}

func (d *K8sDiscoveryAllNamespaces) notifyWatcher(w *k8sScopedWatcher) {
	pods, err := d.podLister.Pods(w.namespace).List(w.selector)
	if err != nil {
		return
	}

	ips := make([]string, 0)
	for _, pod := range pods {
		if pod.Status.PodIP != "" {
			ips = append(ips, pod.Status.PodIP)
		}
	}
	sort.Strings(ips)

	if !equalStrings(ips, w.lastIPs) {
		w.lastIPs = ips
		select {
		case w.ch <- ips:
		default:
		}
	}
}
