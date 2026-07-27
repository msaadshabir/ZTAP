package discovery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	"ztap/pkg/policy"
)

// ServiceDiscovery interface for different backends
type ServiceDiscovery interface {
	ResolveLabels(labels map[string]string) ([]string, error)
	RegisterService(name string, ip string, labels map[string]string) error
	DeregisterService(name string) error
	Watch(ctx context.Context, labels map[string]string) (<-chan []string, error)
	Stop() error
}

// Service represents a discovered service
type Service struct {
	Name      string            `json:"name"`
	IP        string            `json:"ip"`
	Labels    map[string]string `json:"labels"`
	UpdatedAt time.Time         `json:"updated_at"`
}

// InMemoryDiscovery is a simple in-memory service discovery for testing
type InMemoryDiscovery struct {
	services map[string]*Service
	mu       sync.RWMutex
	watchers []*inMemoryWatcher
}

type inMemoryWatcher struct {
	selector map[string]string
	ch       chan []string
	lastIPs  []string
	closed   bool
}

// NewInMemoryDiscovery creates a new in-memory discovery service
func NewInMemoryDiscovery() *InMemoryDiscovery {
	return &InMemoryDiscovery{
		services: make(map[string]*Service),
		watchers: make([]*inMemoryWatcher, 0),
	}
}

// ResolveLabels finds all IPs matching the given labels
func (d *InMemoryDiscovery) ResolveLabels(labels map[string]string) ([]string, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	// Pre-allocate with estimated capacity to reduce allocations
	ips := make([]string, 0, len(d.services))
	for _, service := range d.services {
		if matchLabels(service.Labels, labels) {
			ips = append(ips, service.IP)
		}
	}

	if len(ips) == 0 {
		return nil, &NoMatchesError{Resource: "services", Labels: copyLabelMap(labels)}
	}
	slices.Sort(ips)
	return ips, nil
}

// ResolvePods returns pod info for services matching selector.
func (d *InMemoryDiscovery) ResolvePods(selector policy.PodSelectorSpec) ([]policy.PodInfo, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	infos := make([]policy.PodInfo, 0, len(d.services))
	for _, service := range d.services {
		if policy.MatchesSelector(service.Labels, selector) {
			infos = append(infos, policy.PodInfo{
				IP:     service.IP,
				Labels: copyLabelMap(service.Labels),
			})
		}
	}

	if len(infos) == 0 {
		return nil, &NoMatchesError{Resource: "services", Labels: copyLabelMap(selector.MatchLabels)}
	}
	return infos, nil
}

// ResolvePodsScoped ignores scope for in-memory discovery.
func (d *InMemoryDiscovery) ResolvePodsScoped(scope string, selector policy.PodSelectorSpec) ([]policy.PodInfo, error) {
	return d.ResolvePods(selector)
}

// ResolveSelector finds all IPs matching the given selector (matchLabels + matchExpressions).
func (d *InMemoryDiscovery) ResolveSelector(selector policy.PodSelectorSpec) ([]string, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	ips := make([]string, 0, len(d.services))
	for _, service := range d.services {
		if policy.MatchesSelector(service.Labels, selector) {
			ips = append(ips, service.IP)
		}
	}

	if len(ips) == 0 {
		return nil, &NoMatchesError{Resource: "services", Labels: copyLabelMap(selector.MatchLabels)}
	}
	slices.Sort(ips)
	return ips, nil
}

// ResolveSelectorScoped ignores scope for in-memory discovery.
func (d *InMemoryDiscovery) ResolveSelectorScoped(scope string, selector policy.PodSelectorSpec) ([]string, error) {
	return d.ResolveSelector(selector)
}

// RegisterService adds a service to the discovery
func (d *InMemoryDiscovery) RegisterService(name string, ip string, labels map[string]string) error {
	// Validate IP
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}

	d.mu.Lock()

	d.services[name] = &Service{
		Name:      name,
		IP:        ip,
		Labels:    labels,
		UpdatedAt: time.Now(),
	}
	d.mu.Unlock()

	// Notify watchers
	d.notifyWatchers()
	return nil
}

// DeregisterService removes a service
func (d *InMemoryDiscovery) DeregisterService(name string) error {
	d.mu.Lock()
	delete(d.services, name)
	d.mu.Unlock()

	d.notifyWatchers()
	return nil
}

// Watch returns a channel that receives IP updates when services change
func (d *InMemoryDiscovery) Watch(ctx context.Context, labels map[string]string) (<-chan []string, error) {
	ch := make(chan []string, 10)
	// Compute initial state before registering watcher.
	// For no matches, emit an empty set (non-fatal for downstream consumers).
	ips, err := d.ResolveLabels(labels)
	if err != nil {
		if !isNoMatches(err) {
			return nil, err
		}
		ips = []string{}
	}
	watcher := &inMemoryWatcher{selector: copyLabelMap(labels), ch: ch, lastIPs: ips}

	d.mu.Lock()
	d.watchers = append(d.watchers, watcher)
	d.mu.Unlock()

	ch <- ips

	// Handle context cancellation
	context.AfterFunc(ctx, func() {
		d.mu.Lock()
		defer d.mu.Unlock()
		if watcher.closed {
			return
		}
		// Remove watcher efficiently without preserving order.
		for i, w := range d.watchers {
			if w == watcher {
				last := len(d.watchers) - 1
				d.watchers[i] = d.watchers[last]
				d.watchers = d.watchers[:last]
				break
			}
		}
		watcher.closed = true
		close(ch)
	})

	return ch, nil
}

// notifyWatchers sends updates to all watchers
func (d *InMemoryDiscovery) notifyWatchers() {
	d.mu.Lock()
	defer d.mu.Unlock()

	for _, w := range d.watchers {
		if w == nil || w.closed {
			continue
		}

		ips := make([]string, 0, len(d.services))
		for _, service := range d.services {
			if matchLabels(service.Labels, w.selector) {
				ips = append(ips, service.IP)
			}
		}
		slices.Sort(ips)

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

// ListServices returns all registered services
func (d *InMemoryDiscovery) ListServices() []*Service {
	d.mu.RLock()
	defer d.mu.RUnlock()

	services := make([]*Service, 0, len(d.services))
	for _, service := range d.services {
		services = append(services, service)
	}
	return services
}

// Stop shuts down watchers.
func (d *InMemoryDiscovery) Stop() error {
	d.mu.Lock()
	for _, w := range d.watchers {
		if w == nil || w.closed {
			continue
		}
		w.closed = true
		close(w.ch)
	}
	d.watchers = nil
	d.mu.Unlock()
	return nil
}

func copyLabelMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return map[string]string{}
	}
	out := make(map[string]string, len(in))
	maps.Copy(out, in)
	return out
}

func isNoMatches(err error) bool {
	type noMatches interface {
		NoMatches() bool
	}
	var nm noMatches
	if errors.As(err, &nm) {
		return nm.NoMatches()
	}
	return false
}

// matchLabels checks if service labels match the selector
func matchLabels(serviceLabels, selector map[string]string) bool {
	for key, value := range selector {
		if serviceLabels[key] != value {
			return false
		}
	}
	return true
}

// DNSDiscovery resolves services via DNS SRV records
type DNSDiscovery struct {
	domain string
}

// NewDNSDiscovery creates a DNS-based discovery service
func NewDNSDiscovery(domain string) *DNSDiscovery {
	return &DNSDiscovery{domain: domain}
}

// ResolveLabels converts labels to DNS query and resolves
func (d *DNSDiscovery) ResolveLabels(labels map[string]string) ([]string, error) {
	// Build DNS query from labels
	// Format: app-value.tier-value.domain
	// Pre-allocate capacity for efficiency
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, fmt.Sprintf("%s-%s", key, labels[key]))
	}

	hostname := strings.Join(parts, ".") + "." + d.domain

	// Resolve DNS
	ips, err := net.LookupHost(hostname)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return nil, &NoMatchesError{Resource: "dns records", Scope: hostname, Labels: copyLabelMap(labels)}
		}
		return nil, fmt.Errorf("DNS lookup failed for %s: %w", hostname, err)
	}
	if len(ips) == 0 {
		return nil, &NoMatchesError{Resource: "dns records", Scope: hostname, Labels: copyLabelMap(labels)}
	}

	return ips, nil
}

// RegisterService not supported for DNS discovery
func (d *DNSDiscovery) RegisterService(name string, ip string, labels map[string]string) error {
	return fmt.Errorf("DNS discovery does not support registration")
}

// DeregisterService not supported for DNS discovery
func (d *DNSDiscovery) DeregisterService(name string) error {
	return fmt.Errorf("DNS discovery does not support deregistration")
}

// Watch not supported for DNS discovery
func (d *DNSDiscovery) Watch(ctx context.Context, labels map[string]string) (<-chan []string, error) {
	return nil, fmt.Errorf("DNS discovery does not support watching")
}

// Stop is a no-op for DNS discovery.
func (d *DNSDiscovery) Stop() error {
	return nil
}

// ConsulDiscovery integrates with HashiCorp Consul
type ConsulDiscovery struct {
	address string
	// In production, use github.com/hashicorp/consul/api
}

// NewConsulDiscovery creates a Consul-based discovery service
func NewConsulDiscovery(address string) *ConsulDiscovery {
	return &ConsulDiscovery{address: address}
}

// ResolveLabels queries Consul for services with matching tags
func (c *ConsulDiscovery) ResolveLabels(labels map[string]string) ([]string, error) {
	// Placeholder: In production, use Consul API
	// consul, err := api.NewClient(&api.Config{Address: c.address})
	// services, _, err := consul.Health().Service(serviceName, "", true, nil)
	return nil, fmt.Errorf("consul discovery not yet implemented")
}

// RegisterService registers with Consul
func (c *ConsulDiscovery) RegisterService(name string, ip string, labels map[string]string) error {
	return fmt.Errorf("consul discovery not yet implemented")
}

// DeregisterService removes from Consul
func (c *ConsulDiscovery) DeregisterService(name string) error {
	return fmt.Errorf("consul discovery not yet implemented")
}

// Watch watches Consul for service changes
func (c *ConsulDiscovery) Watch(ctx context.Context, labels map[string]string) (<-chan []string, error) {
	return nil, fmt.Errorf("consul discovery not yet implemented")
}

// Stop is a no-op for the Consul discovery stub.
func (c *ConsulDiscovery) Stop() error {
	return nil
}

// CacheDiscovery wraps another discovery with caching
type CacheDiscovery struct {
	backend ServiceDiscovery
	cache   map[string]cacheEntry
	mu      sync.RWMutex
	ttl     time.Duration
}

type cacheEntry struct {
	ips       []string
	expiresAt time.Time
	noMatches bool
}

// NewCacheDiscovery creates a caching wrapper
func NewCacheDiscovery(backend ServiceDiscovery, ttl time.Duration) *CacheDiscovery {
	return &CacheDiscovery{
		backend: backend,
		cache:   make(map[string]cacheEntry),
		ttl:     ttl,
	}
}

// ResolveLabels resolves with caching
func (c *CacheDiscovery) ResolveLabels(labels map[string]string) ([]string, error) {
	// Create cache key from labels
	keyBytes, _ := json.Marshal(labels)
	key := string(keyBytes)

	c.mu.RLock()
	if entry, exists := c.cache[key]; exists {
		if time.Now().Before(entry.expiresAt) {
			c.mu.RUnlock()
			if entry.noMatches {
				return nil, &NoMatchesError{Labels: copyLabelMap(labels)}
			}
			return entry.ips, nil
		}
	}
	c.mu.RUnlock()

	// Cache miss or expired, fetch from backend
	ips, err := c.backend.ResolveLabels(labels)
	if err != nil {
		if isNoMatches(err) {
			c.mu.Lock()
			c.cache[key] = cacheEntry{expiresAt: time.Now().Add(c.ttl), noMatches: true}
			c.mu.Unlock()
		}
		return nil, err
	}

	// Update cache
	c.mu.Lock()
	c.cache[key] = cacheEntry{
		ips:       ips,
		expiresAt: time.Now().Add(c.ttl),
	}
	c.mu.Unlock()

	return ips, nil
}

// ResolveSelector delegates selector resolution when supported by backend.
func (c *CacheDiscovery) ResolveSelector(selector policy.PodSelectorSpec) ([]string, error) {
	if backend, ok := c.backend.(policy.SelectorResolver); ok {
		return backend.ResolveSelector(selector)
	}
	return nil, fmt.Errorf("selector resolution not supported by backend")
}

// ResolveSelectorScoped delegates scoped selector resolution when supported by backend.
func (c *CacheDiscovery) ResolveSelectorScoped(scope string, selector policy.PodSelectorSpec) ([]string, error) {
	if backend, ok := c.backend.(policy.SelectorResolver); ok {
		return backend.ResolveSelectorScoped(scope, selector)
	}
	return nil, fmt.Errorf("scoped selector resolution not supported by backend")
}

// ResolveNamespaces delegates namespace selector resolution when supported by backend.
func (c *CacheDiscovery) ResolveNamespaces(selector policy.PodSelectorSpec) ([]string, error) {
	if backend, ok := c.backend.(policy.NamespaceResolver); ok {
		return backend.ResolveNamespaces(selector)
	}
	return nil, fmt.Errorf("namespace selector resolution not supported by backend")
}

// ResolvePods delegates pod resolution when supported by backend.
func (c *CacheDiscovery) ResolvePods(selector policy.PodSelectorSpec) ([]policy.PodInfo, error) {
	if backend, ok := c.backend.(policy.PodResolver); ok {
		return backend.ResolvePods(selector)
	}
	return nil, fmt.Errorf("pod resolution not supported by backend")
}

// ResolvePodsScoped delegates scoped pod resolution when supported by backend.
func (c *CacheDiscovery) ResolvePodsScoped(scope string, selector policy.PodSelectorSpec) ([]policy.PodInfo, error) {
	if backend, ok := c.backend.(policy.PodResolver); ok {
		return backend.ResolvePodsScoped(scope, selector)
	}
	return nil, fmt.Errorf("scoped pod resolution not supported by backend")
}

// RegisterService delegates to backend
func (c *CacheDiscovery) RegisterService(name string, ip string, labels map[string]string) error {
	return c.backend.RegisterService(name, ip, labels)
}

// DeregisterService delegates to backend
func (c *CacheDiscovery) DeregisterService(name string) error {
	return c.backend.DeregisterService(name)
}

// Watch delegates to backend
func (c *CacheDiscovery) Watch(ctx context.Context, labels map[string]string) (<-chan []string, error) {
	ch, err := c.backend.Watch(ctx, labels)
	if err != nil {
		return nil, err
	}
	out := make(chan []string, 10)
	go func() {
		defer close(out)
		for {
			select {
			case <-ctx.Done():
				return
			case ips, ok := <-ch:
				if !ok {
					return
				}
				c.ClearCache()
				select {
				case out <- ips:
				default:
				}
			}
		}
	}()
	return out, nil
}

// ClearCache removes all cached entries
func (c *CacheDiscovery) ClearCache() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache = make(map[string]cacheEntry)
}

// Stop propagates shutdown to the backend if supported.
func (c *CacheDiscovery) Stop() error {
	if stopper, ok := c.backend.(interface{ Stop() error }); ok {
		return stopper.Stop()
	}
	return nil
}
