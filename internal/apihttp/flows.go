package apihttp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"ztap/internal/flow"
)

func (s *Server) handleFlowsStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, errors.New("streaming not supported"))
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	monitor, err := s.acquireFlowMonitor()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	defer s.releaseFlowMonitor()

	eventCh := monitor.Subscribe(ctx)

	// Send a comment to establish the stream.
	_, _ = fmt.Fprint(w, ": ok\n\n")
	flusher.Flush()
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-eventCh:
			if !ok {
				return
			}
			b, err := json.Marshal(ev)
			if err != nil {
				return
			}
			_, _ = fmt.Fprintf(w, "data: %s\n\n", b)
			flusher.Flush()
		case <-ticker.C:
			// Keep-alive comment
			_, _ = fmt.Fprint(w, ": keep-alive\n\n")
			flusher.Flush()
		}
	}
}

func demoRawFlows() []flow.RawFlowEvent {
	nowNs := max(time.Now().UnixNano(), 0)
	now := uint64(nowNs) // #nosec G115 -- nowNs is clamped to >=0 above
	return []flow.RawFlowEvent{
		{
			TimestampNs: now,
			SrcIP:       [4]uint32{0x0A000101}, // 10.0.1.1
			DestIP:      [4]uint32{0x0A000201}, // 10.0.2.1
			SrcPort:     45678,
			DestPort:    5432,
			Protocol:    6, // TCP
			Direction:   0, // egress
			Action:      1, // allow
			Family:      4,
		},
		{
			TimestampNs: now,
			SrcIP:       [4]uint32{0xC0A86464}, // 192.168.100.100
			DestIP:      [4]uint32{0x0A000101}, // 10.0.1.1
			SrcPort:     52341,
			DestPort:    443,
			Protocol:    6,
			Direction:   1, // ingress
			Action:      1,
			Family:      4,
		},
		{
			TimestampNs: now,
			SrcIP:       [4]uint32{0x0A000101},
			DestIP:      [4]uint32{0x08080808}, // 8.8.8.8
			SrcPort:     54321,
			DestPort:    53,
			Protocol:    17, // UDP
			Direction:   0,
			Action:      0, // block
			Family:      4,
		},
	}
}
