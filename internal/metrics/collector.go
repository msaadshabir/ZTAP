package metrics

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Collector manages all ZTAP metrics
type Collector struct {
	flowsAllowed   prometheus.Counter
	flowsBlocked   prometheus.Counter
	anomalyScore   prometheus.Gauge
	policyLoadTime prometheus.Histogram
	flowsTotal     *prometheus.CounterVec
	mu             sync.Mutex
}

var (
	globalCollector *Collector
	once            sync.Once
)

// GetCollector returns the singleton metrics collector
func GetCollector() *Collector {
	once.Do(func() {
		globalCollector = &Collector{
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
			flowsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
				Name: "ztap_flows_total",
				Help: "Total number of network flows by action, protocol, and direction",
			}, []string{"action", "protocol", "direction"}),
		}

		// Register metrics with Prometheus
		prometheus.MustRegister(globalCollector.flowsAllowed)
		prometheus.MustRegister(globalCollector.flowsBlocked)
		prometheus.MustRegister(globalCollector.anomalyScore)
		prometheus.MustRegister(globalCollector.policyLoadTime)
		prometheus.MustRegister(globalCollector.flowsTotal)
	})

	return globalCollector
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

// RecordFlow records a flow event with labels for action, protocol, and direction.
func (c *Collector) RecordFlow(action, protocol, direction string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.flowsTotal.WithLabelValues(action, protocol, direction).Inc()

	// Also update legacy counters for backward compatibility
	if action == "allowed" {
		c.flowsAllowed.Inc()
	} else {
		c.flowsBlocked.Inc()
	}
}

// StartServer starts the Prometheus metrics HTTP server on the given listen
// address (host:port) and path.
func StartServer(listen, path string) error {
	if strings.TrimSpace(path) == "" {
		path = "/metrics"
	}

	mux := http.NewServeMux()
	mux.Handle(path, promhttp.Handler())

	srv := &http.Server{
		Addr:              listen,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	fmt.Printf("Starting metrics server on http://%s%s\n", listen, path)
	return srv.ListenAndServe()
}
