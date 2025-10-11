package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// ServiceDiscovery interface for different backends
type ServiceDiscovery interface {
	ResolveLabels(labels map[string]string) ([]string, error)
	RegisterService(name string, ip string, labels map[string]string) error
	DeregisterService(name string) error
	Watch(ctx context.Context, labels map[string]string) (<-chan []string, error)
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
	watchers []chan []string
}

// NewInMemoryDiscovery creates a new in-memory discovery service
func NewInMemoryDiscovery() *InMemoryDiscovery {
	return &InMemoryDiscovery{
		services: make(map[string]*Service),
		watchers: make([]chan []string, 0),
	}
}

// ResolveLabels finds all IPs matching the given labels
func (d *InMemoryDiscovery) ResolveLabels(labels map[string]string) ([]string, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	ips := make([]string, 0)
	for _, service := range d.services {
		if matchLabels(service.Labels, labels) {
			ips = append(ips, service.IP)
		}
	}

	if len(ips) == 0 {
		return nil, fmt.Errorf("no services found matching labels: %v", labels)
	}

	return ips, nil
}

// RegisterService adds a service to the discovery
func (d *InMemoryDiscovery) RegisterService(name string, ip string, labels map[string]string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Validate IP
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}

	d.services[name] = &Service{
		Name:      name,
		IP:        ip,
		Labels:    labels,
		UpdatedAt: time.Now(),
	}

	// Notify watchers
	d.notifyWatchers()

	return nil
}

// DeregisterService removes a service
func (d *InMemoryDiscovery) DeregisterService(name string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	delete(d.services, name)
	d.notifyWatchers()
	return nil
}

// Watch returns a channel that receives IP updates when services change
func (d *InMemoryDiscovery) Watch(ctx context.Context, labels map[string]string) (<-chan []string, error) {
	ch := make(chan []string, 10)

	d.mu.Lock()
	d.watchers = append(d.watchers, ch)
	d.mu.Unlock()

	// Send initial state
	ips, _ := d.ResolveLabels(labels)
	ch <- ips

	// Handle context cancellation
	go func() {
		<-ctx.Done()
		d.mu.Lock()
		defer d.mu.Unlock()

		// Remove watcher
		for i, w := range d.watchers {
			if w == ch {
				d.watchers = append(d.watchers[:i], d.watchers[i+1:]...)
				break
			}
		}
		close(ch)
	}()

	return ch, nil
}

// notifyWatchers sends updates to all watchers
func (d *InMemoryDiscovery) notifyWatchers() {
	for _, ch := range d.watchers {
		// Get all IPs
		ips := make([]string, 0, len(d.services))
		for _, service := range d.services {
			ips = append(ips, service.IP)
		}

		select {
		case ch <- ips:
		default:
			// Skip if channel is full
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
	parts := make([]string, 0, len(labels))
	for key, value := range labels {
		parts = append(parts, fmt.Sprintf("%s-%s", key, value))
	}

	hostname := strings.Join(parts, ".") + "." + d.domain

	// Resolve DNS
	ips, err := net.LookupHost(hostname)
	if err != nil {
		return nil, fmt.Errorf("DNS lookup failed for %s: %w", hostname, err)
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
	return nil, fmt.Errorf("Consul discovery not yet implemented")
}

// RegisterService registers with Consul
func (c *ConsulDiscovery) RegisterService(name string, ip string, labels map[string]string) error {
	return fmt.Errorf("Consul discovery not yet implemented")
}

// DeregisterService removes from Consul
func (c *ConsulDiscovery) DeregisterService(name string) error {
	return fmt.Errorf("Consul discovery not yet implemented")
}

// Watch watches Consul for service changes
func (c *ConsulDiscovery) Watch(ctx context.Context, labels map[string]string) (<-chan []string, error) {
	return nil, fmt.Errorf("Consul discovery not yet implemented")
}

// K8sDiscovery integrates with Kubernetes API
type K8sDiscovery struct {
	namespace string
	// In production, use k8s.io/client-go
}

// NewK8sDiscovery creates a Kubernetes-based discovery service
func NewK8sDiscovery(namespace string) *K8sDiscovery {
	return &K8sDiscovery{namespace: namespace}
}

// ResolveLabels queries Kubernetes for pods with matching labels
func (k *K8sDiscovery) ResolveLabels(labels map[string]string) ([]string, error) {
	// Placeholder: In production, use K8s client-go
	// clientset, err := kubernetes.NewForConfig(config)
	// pods, err := clientset.CoreV1().Pods(k.namespace).List(ctx, metav1.ListOptions{
	//     LabelSelector: labels.FormatSelector(labels),
	// })
	return nil, fmt.Errorf("Kubernetes discovery not yet implemented")
}

// RegisterService not applicable for K8s (managed by K8s)
func (k *K8sDiscovery) RegisterService(name string, ip string, labels map[string]string) error {
	return fmt.Errorf("Kubernetes discovery does not support manual registration")
}

// DeregisterService not applicable for K8s
func (k *K8sDiscovery) DeregisterService(name string) error {
	return fmt.Errorf("Kubernetes discovery does not support manual deregistration")
}

// Watch watches Kubernetes for pod changes
func (k *K8sDiscovery) Watch(ctx context.Context, labels map[string]string) (<-chan []string, error) {
	return nil, fmt.Errorf("Kubernetes discovery not yet implemented")
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
			return entry.ips, nil
		}
	}
	c.mu.RUnlock()

	// Cache miss or expired, fetch from backend
	ips, err := c.backend.ResolveLabels(labels)
	if err != nil {
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
	return c.backend.Watch(ctx, labels)
}

// ClearCache removes all cached entries
func (c *CacheDiscovery) ClearCache() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache = make(map[string]cacheEntry)
}
