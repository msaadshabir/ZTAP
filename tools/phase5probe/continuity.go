package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"sync"
	"time"
)

type continuityReport struct {
	SchemaVersion      int    `json:"schema_version"`
	TimestampNS        int64  `json:"timestamp_ns"`
	StartedNS          int64  `json:"started_ns"`
	Allowed            uint64 `json:"allowed"`
	Prohibited         uint64 `json:"prohibited"`
	AllowedAttempts    uint64 `json:"allowed_attempts"`
	ProhibitedAttempts uint64 `json:"prohibited_attempts"`
	UnknownConnections uint64 `json:"-"`
}

// Both requests execute in this process's workload cgroup. The allowed stream
// reuses its TCP connection so returning responses also exercise reply state.
func runContinuityProbe(denied, allowed string, interval, requestTimeout, maxDuration time.Duration, stopFile string, output io.Writer) error {
	return runClassificationProbe(denied, allowed, interval, requestTimeout, maxDuration, stopFile, "", output)
}

// Before the release marker, even a TCP connection to the future allowed
// control is prohibited. The deployed guard gate creates the marker before
// restoring the controller, after observing a sustained unclassified outage.
func runClassificationProbe(denied, allowed string, interval, requestTimeout, maxDuration time.Duration, stopFile, releaseFile string, output io.Writer) error {
	for _, target := range []string{denied, allowed} {
		parsed, err := url.ParseRequestURI(target)
		if err != nil || parsed.Scheme != "http" || parsed.Host == "" {
			return errors.New("both continuity targets must be absolute HTTP URLs")
		}
	}
	if interval <= 0 || requestTimeout <= 0 || maxDuration <= 0 || output == nil {
		return errors.New("invalid continuity timing or output")
	}
	started := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), maxDuration)
	defer cancel()
	report := continuityReport{SchemaVersion: 2, StartedNS: started.UnixNano()}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for index, target := range []string{allowed, denied} {
		wg.Add(1)
		go func(index int, target string) {
			defer wg.Done()
			transport := &http.Transport{DisableKeepAlives: index == 1}
			if index == 1 || releaseFile != "" {
				transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
					connection, err := (&net.Dialer{}).DialContext(ctx, network, address)
					if err == nil {
						mu.Lock()
						if index == 1 {
							report.Prohibited++
						} else if _, statErr := os.Stat(releaseFile); statErr != nil {
							report.UnknownConnections++
						}
						mu.Unlock()
					}
					return connection, err
				}
			}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					requestCtx, stop := context.WithTimeout(ctx, requestTimeout)
					request, err := http.NewRequestWithContext(requestCtx, http.MethodGet, target, nil)
					if err != nil {
						stop()
						return
					}
					mu.Lock()
					if index == 0 {
						report.AllowedAttempts++
						request.Header.Set("X-ZTAP-Sequence", strconv.FormatUint(report.AllowedAttempts, 10))
					} else {
						report.ProhibitedAttempts++
						request.Header.Set("X-ZTAP-Sequence", strconv.FormatUint(report.ProhibitedAttempts, 10))
					}
					mu.Unlock()
					response, err := client.Do(request)
					success := false
					if err == nil {
						body, readErr := io.ReadAll(io.LimitReader(response.Body, 16))
						closeErr := response.Body.Close()
						success = readErr == nil && closeErr == nil && response.StatusCode == http.StatusOK && string(body) == "ok\n"
					}
					stop()
					if success && index == 0 {
						mu.Lock()
						report.Allowed++
						mu.Unlock()
					}
				}
			}
		}(index, target)
	}
	defer func() { cancel(); wg.Wait() }()
	encoder := json.NewEncoder(output)
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	emit := func() error {
		mu.Lock()
		snapshot := report
		mu.Unlock()
		snapshot.TimestampNS = time.Now().UnixNano()
		if releaseFile != "" {
			return encoder.Encode(struct {
				continuityReport
				UnknownConnections uint64 `json:"unknown_tcp_connections"`
			}{continuityReport: snapshot, UnknownConnections: snapshot.UnknownConnections})
		}
		return encoder.Encode(snapshot)
	}
	for {
		select {
		case <-ctx.Done():
			if err := emit(); err != nil {
				return err
			}
			return errors.New("continuity probe exceeded observation deadline before its stop file appeared")
		case <-ticker.C:
			mu.Lock()
			snapshot := report
			mu.Unlock()
			if err := emit(); err != nil {
				return err
			}
			if snapshot.Prohibited != 0 || snapshot.UnknownConnections != 0 {
				return errors.New("continuity probe received prohibited traffic")
			}
			if stopFile != "" {
				if _, err := os.Stat(stopFile); err == nil {
					cancel()
					wg.Wait()
					mu.Lock()
					snapshot = report
					mu.Unlock()
					if err := emit(); err != nil {
						return err
					}
					if snapshot.Prohibited != 0 || snapshot.UnknownConnections != 0 || snapshot.Allowed == 0 || snapshot.ProhibitedAttempts == 0 {
						return errors.New("continuity probe lacks a denied baseline or working controls")
					}
					return nil
				} else if !os.IsNotExist(err) {
					return fmt.Errorf("check continuity stop file: %w", err)
				}
			}
		}
	}
}
