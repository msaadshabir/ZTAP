package metrics

import (
	"fmt"
	"net/http"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Collector manages all ZTAP metrics
type Collector struct {
	policiesEnforced prometheus.Counter
	flowsAllowed     prometheus.Counter
	flowsBlocked     prometheus.Counter
	anomalyScore     prometheus.Gauge
	policyLoadTime   prometheus.Histogram
	mu               sync.Mutex
}

var (
	globalCollector *Collector
	once            sync.Once
)

// GetCollector returns the singleton metrics collector
func GetCollector() *Collector {
	once.Do(func() {
		globalCollector = &Collector{
			policiesEnforced: prometheus.NewCounter(prometheus.CounterOpts{
				Name: "ztap_policies_enforced_total",
				Help: "Total number of policies enforced",
			}),
			flowsAllowed: prometheus.NewCounter(prometheus.CounterOpts{
				Name: "ztap_flows_allowed_total",
				Help: "Total number of flows allowed",
			}),
			flowsBlocked: prometheus.NewCounter(prometheus.CounterOpts{
				Name: "ztap_flows_blocked_total",
				Help: "Total number of flows blocked",
			}),
			anomalyScore: prometheus.NewGauge(prometheus.GaugeOpts{
				Name: "ztap_anomaly_score",
				Help: "Current anomaly score (0-100)",
			}),
			policyLoadTime: prometheus.NewHistogram(prometheus.HistogramOpts{
				Name:    "ztap_policy_load_duration_seconds",
				Help:    "Time taken to load policies",
				Buckets: prometheus.DefBuckets,
			}),
		}

		// Register metrics with Prometheus
		prometheus.MustRegister(globalCollector.policiesEnforced)
		prometheus.MustRegister(globalCollector.flowsAllowed)
		prometheus.MustRegister(globalCollector.flowsBlocked)
		prometheus.MustRegister(globalCollector.anomalyScore)
		prometheus.MustRegister(globalCollector.policyLoadTime)
	})

	return globalCollector
}

// IncPoliciesEnforced increments the policies enforced counter
func (c *Collector) IncPoliciesEnforced() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.policiesEnforced.Inc()
}

// IncFlowsAllowed increments the flows allowed counter
func (c *Collector) IncFlowsAllowed() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.flowsAllowed.Inc()
}

// IncFlowsBlocked increments the flows blocked counter
func (c *Collector) IncFlowsBlocked() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.flowsBlocked.Inc()
}

// SetAnomalyScore sets the current anomaly score
func (c *Collector) SetAnomalyScore(score float64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.anomalyScore.Set(score)
}

// ObservePolicyLoadTime records a policy load duration
func (c *Collector) ObservePolicyLoadTime(seconds float64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.policyLoadTime.Observe(seconds)
}

// StartServer starts the Prometheus metrics HTTP server
func StartServer(port int) error {
	http.Handle("/metrics", promhttp.Handler())
	addr := fmt.Sprintf(":%d", port)
	fmt.Printf("Starting metrics server on http://localhost%s/metrics\n", addr)
	return http.ListenAndServe(addr, nil)
}
