package ratelimit

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

type Config struct {
	Enabled           bool
	TrustProxyHeaders bool

	Unauthenticated BucketConfig
	PerIP           BucketConfig
	PerToken        BucketConfig

	ExemptPaths []string

	MaxKeys  int
	EntryTTL time.Duration
}

type BucketConfig struct {
	RPS   float64
	Burst int
}

type Decision struct {
	Allowed     bool
	Bucket      string
	RetryAfter  time.Duration
	Limit       float64
	Burst       int
	KeyMaterial string
}

type Store struct {
	cfg Config

	mu       sync.Mutex
	entries  map[string]*entry
	stopGC   chan struct{}
	stopped  chan struct{}
	gcEvery  time.Duration
	disabled bool
}

type KeyMode int

const (
	KeyIP KeyMode = iota
	KeyToken
	KeyUnauthenticated
)

type entry struct {
	lim      *rate.Limiter
	lastSeen time.Time
}

func DefaultConfig() Config {
	return Config{
		Enabled:           false,
		TrustProxyHeaders: false,
		Unauthenticated:   BucketConfig{RPS: 5, Burst: 10},
		PerIP:             BucketConfig{RPS: 20, Burst: 40},
		PerToken:          BucketConfig{RPS: 10, Burst: 20},
		ExemptPaths:       []string{"/healthz", "/readyz"},
		MaxKeys:           10000,
		EntryTTL:          15 * time.Minute,
	}
}

func NewStore(cfg Config) *Store {
	if cfg.MaxKeys <= 0 {
		cfg.MaxKeys = 10000
	}
	if cfg.EntryTTL <= 0 {
		cfg.EntryTTL = 15 * time.Minute
	}
	s := &Store{
		cfg:     cfg,
		entries: make(map[string]*entry),
		stopGC:  make(chan struct{}),
		stopped: make(chan struct{}),
		gcEvery: time.Minute,
	}
	if !cfg.Enabled {
		s.disabled = true
		close(s.stopped)
		return s
	}

	go s.gcLoop()
	return s
}

func (s *Store) Close() {
	if s.disabled {
		return
	}
	select {
	case <-s.stopGC:
		return
	default:
		close(s.stopGC)
	}
	<-s.stopped
}

func (s *Store) gcLoop() {
	defer close(s.stopped)

	t := time.NewTicker(s.gcEvery)
	defer t.Stop()

	for {
		select {
		case <-s.stopGC:
			return
		case <-t.C:
			s.evictExpired()
		}
	}
}

func (s *Store) evictExpired() {
	cutoff := time.Now().Add(-s.cfg.EntryTTL)

	s.mu.Lock()
	defer s.mu.Unlock()

	for k, e := range s.entries {
		if e.lastSeen.Before(cutoff) {
			delete(s.entries, k)
		}
	}
}

func (s *Store) DecisionForHTTPRequest(r *http.Request) (Decision, error) {
	if !s.cfg.Enabled {
		return Decision{Allowed: true, Bucket: "disabled"}, nil
	}

	path := r.URL.Path
	if isExemptPath(path, s.cfg.ExemptPaths) {
		return Decision{Allowed: true, Bucket: "exempt"}, nil
	}

	ip, _ := ClientIPFromRequest(r, s.cfg.TrustProxyHeaders)
	ipKey := "ip:" + ip

	authz := strings.TrimSpace(r.Header.Get("Authorization"))
	tok, ok := BearerTokenFromAuthHeader(authz)
	if ok {
		dec := s.DecisionForKey(KeyToken, "token:"+HashToken(tok))
		dec.Bucket = "per_token"
		dec.KeyMaterial = "token"
		if !dec.Allowed {
			return dec, nil
		}
		dec2 := s.DecisionForKey(KeyIP, ipKey)
		dec2.Bucket = "per_ip"
		dec2.KeyMaterial = "ip"
		return dec2, nil
	}

	dec := s.DecisionForKey(KeyUnauthenticated, ipKey)
	dec.Bucket = "unauthenticated"
	dec.KeyMaterial = "ip"
	return dec, nil
}

func (s *Store) DecisionForKey(mode KeyMode, key string) Decision {
	if !s.cfg.Enabled {
		return Decision{Allowed: true, Bucket: "disabled"}
	}

	var bc BucketConfig
	switch mode {
	case KeyToken:
		bc = s.cfg.PerToken
	case KeyIP:
		bc = s.cfg.PerIP
	case KeyUnauthenticated:
		bc = s.cfg.Unauthenticated
	default:
		bc = s.cfg.PerIP
	}

	dec := s.allow("", key, bc)
	dec.Bucket = ""
	return dec
}

func (s *Store) allow(bucket, key string, bc BucketConfig) Decision {
	if bc.RPS <= 0 || bc.Burst <= 0 {
		return Decision{Allowed: true, Bucket: bucket, Limit: bc.RPS, Burst: bc.Burst}
	}

	lim := s.getLimiter(key, bc)

	if lim.Allow() {
		return Decision{Allowed: true, Bucket: bucket, Limit: bc.RPS, Burst: bc.Burst}
	}

	res := lim.Reserve()
	if !res.OK() {
		return Decision{Allowed: false, Bucket: bucket, Limit: bc.RPS, Burst: bc.Burst}
	}
	defer res.Cancel()

	delay := max(res.Delay(), 0)

	return Decision{Allowed: false, Bucket: bucket, RetryAfter: delay, Limit: bc.RPS, Burst: bc.Burst}
}

func (s *Store) getLimiter(key string, bc BucketConfig) *rate.Limiter {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.entries) >= s.cfg.MaxKeys {
		s.evictOldestLocked()
	}

	if e, ok := s.entries[key]; ok {
		e.lastSeen = time.Now()
		return e.lim
	}

	l := rate.NewLimiter(rate.Limit(bc.RPS), bc.Burst)
	s.entries[key] = &entry{lim: l, lastSeen: time.Now()}
	return l
}

func (s *Store) evictOldestLocked() {
	var oldestKey string
	var oldestTime time.Time
	first := true

	for k, e := range s.entries {
		if first || e.lastSeen.Before(oldestTime) {
			oldestKey = k
			oldestTime = e.lastSeen
			first = false
		}
	}
	if !first {
		delete(s.entries, oldestKey)
	}
}

func isExemptPath(path string, exempt []string) bool {
	for _, p := range exempt {
		if p == path {
			return true
		}
		if before, ok := strings.CutSuffix(p, "*"); ok {
			prefix := before
			if strings.HasPrefix(path, prefix) {
				return true
			}
		}
	}
	return false
}

func ClientIPFromRequest(r *http.Request, trustProxy bool) (string, error) {
	if trustProxy {
		xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For"))
		if xff != "" {
			parts := strings.Split(xff, ",")
			ip := strings.TrimSpace(parts[0])
			if parsed := net.ParseIP(ip); parsed != nil {
				return parsed.String(), nil
			}
		}
		xri := strings.TrimSpace(r.Header.Get("X-Real-IP"))
		if xri != "" {
			if parsed := net.ParseIP(xri); parsed != nil {
				return parsed.String(), nil
			}
		}
	}

	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err == nil {
		if parsed := net.ParseIP(host); parsed != nil {
			return parsed.String(), nil
		}
	}

	parsed := net.ParseIP(strings.TrimSpace(r.RemoteAddr))
	if parsed != nil {
		return parsed.String(), nil
	}

	return "0.0.0.0", errors.New("unable to determine client ip")
}

func BearerTokenFromAuthHeader(h string) (string, bool) {
	if h == "" {
		return "", false
	}
	parts := strings.SplitN(h, " ", 2)
	if len(parts) != 2 {
		return "", false
	}
	if strings.ToLower(strings.TrimSpace(parts[0])) != "bearer" {
		return "", false
	}
	tok := strings.TrimSpace(parts[1])
	if tok == "" {
		return "", false
	}
	return tok, true
}

func HashToken(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	hexSum := hex.EncodeToString(sum[:])
	if len(hexSum) > 16 {
		return hexSum[:16]
	}
	return hexSum
}

func WriteHTTP429(w http.ResponseWriter, d Decision) {
	retrySeconds := 0
	if d.RetryAfter > 0 {
		retrySeconds = int(d.RetryAfter.Truncate(time.Second).Seconds())
		if retrySeconds <= 0 {
			retrySeconds = 1
		}
	}
	w.Header().Set("Retry-After", strconv.Itoa(retrySeconds))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusTooManyRequests)
	_, _ = w.Write([]byte("{\"error\":\"rate_limited\"}"))
}
