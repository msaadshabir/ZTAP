package apihttp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"ztap/pkg/flow"
)

type gatedFlowReader struct {
	ready   chan struct{}
	proceed chan struct{}
	events  []flow.RawFlowEvent
}

func (r *gatedFlowReader) Start(ctx context.Context, ch chan<- flow.RawFlowEvent) error {
	close(r.ready)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-r.proceed:
	}
	for _, ev := range r.events {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case ch <- ev:
		}
	}
	return nil
}

func (r *gatedFlowReader) Stop() error { return nil }

func (r *gatedFlowReader) Available() bool { return true }

type blockingFlowReader struct {
	started chan struct{}
}

func (r *blockingFlowReader) Start(ctx context.Context, _ chan<- flow.RawFlowEvent) error {
	close(r.started)
	<-ctx.Done()
	return ctx.Err()
}

func (r *blockingFlowReader) Stop() error { return nil }

func (r *blockingFlowReader) Available() bool { return true }

type noFlusherWriter struct {
	header http.Header
	code   int
	buf    strings.Builder
}

func (w *noFlusherWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}

func (w *noFlusherWriter) Write(p []byte) (int, error) {
	if w.code == 0 {
		w.code = http.StatusOK
	}
	return w.buf.Write(p)
}

func (w *noFlusherWriter) WriteHeader(statusCode int) {
	w.code = statusCode
}

type badReader struct{}

func (r *badReader) Start(ctx context.Context, _ chan<- flow.RawFlowEvent) error {
	return context.DeadlineExceeded
}

func (r *badReader) Stop() error { return nil }

func (r *badReader) Available() bool { return false }

type responseStreamConn struct {
	readCh chan string
}

func (c *responseStreamConn) Write(p []byte) (int, error) {
	lines := strings.SplitSeq(string(p), "\n")
	for line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		select {
		case c.readCh <- line:
		default:
		}
	}
	return len(p), nil
}

type streamingResponseWriter struct {
	header http.Header
	conn   *responseStreamConn
	code   int
}

func (w *streamingResponseWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}

func (w *streamingResponseWriter) Write(p []byte) (int, error) {
	if w.code == 0 {
		w.code = http.StatusOK
	}
	return w.conn.Write(p)
}

func (w *streamingResponseWriter) WriteHeader(statusCode int) {
	w.code = statusCode
}

func (w *streamingResponseWriter) Flush() {}

func TestFlowsStream_MethodNotAllowed(t *testing.T) {
	srv, err := NewServer(ServerOptions{Config: Config{Listen: "127.0.0.1:0", AuthEnabled: false}})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/flows/stream", nil)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rr.Code)
	}
}

func TestFlowsStream_RequiresFlusher(t *testing.T) {
	srv, err := NewServer(ServerOptions{Config: Config{Listen: "127.0.0.1:0", AuthEnabled: false}})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	req := httptest.NewRequest(http.MethodGet, "/v1/flows/stream", nil).WithContext(ctx)
	rr := &noFlusherWriter{}

	done := make(chan struct{})
	go func() {
		srv.Handler().ServeHTTP(rr, req)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("handler did not return")
	}
	if rr.code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rr.code)
	}
}

func TestFlowsStream_EmitsEvents(t *testing.T) {
	reader := &gatedFlowReader{ready: make(chan struct{}), proceed: make(chan struct{}), events: demoRawFlows()}
	srv, err := NewServer(ServerOptions{Config: Config{Listen: "127.0.0.1:0", AuthEnabled: false}, FlowReaderFactory: func() flow.FlowReader {
		return reader
	}})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req := httptest.NewRequest(http.MethodGet, "/v1/flows/stream", nil).WithContext(ctx)

	conn := &responseStreamConn{readCh: make(chan string, 4)}
	resp := &streamingResponseWriter{
		header: make(http.Header),
		conn:   conn,
	}

	go srv.Handler().ServeHTTP(resp, req)

	deadline := time.Now().Add(1500 * time.Millisecond)
	ready := false
	found := false
	for time.Now().Before(deadline) {
		select {
		case line := <-conn.readCh:
			if line == ": ok" && !ready {
				ready = true
				close(reader.proceed)
				continue
			}
			if strings.HasPrefix(line, "data: ") {
				var ev flow.FlowEvent
				payload := strings.TrimPrefix(line, "data: ")
				if err := json.Unmarshal([]byte(payload), &ev); err != nil {
					t.Fatalf("expected JSON event, got error: %v", err)
				}
				found = true
			}
		default:
			time.Sleep(10 * time.Millisecond)
		}
		if found {
			break
		}
	}
	if !found {
		t.Fatalf("expected data event line in stream output")
	}
}

func TestFlowsStream_ReaderError(t *testing.T) {
	srv, err := NewServer(ServerOptions{Config: Config{Listen: "127.0.0.1:0", AuthEnabled: false}, FlowReaderFactory: func() flow.FlowReader {
		return &badReader{}
	}})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	req := httptest.NewRequest(http.MethodGet, "/v1/flows/stream", nil).WithContext(ctx)
	rr := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		srv.Handler().ServeHTTP(rr, req)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(700 * time.Millisecond):
		t.Fatalf("timeout waiting for stream to exit")
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestFlowsStream_KeepAlive(t *testing.T) {
	started := make(chan struct{})
	reader := &blockingFlowReader{started: started}

	srv, err := NewServer(ServerOptions{Config: Config{Listen: "127.0.0.1:0", AuthEnabled: false}, FlowReaderFactory: func() flow.FlowReader {
		return reader
	}})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 17*time.Second)
	defer cancel()
	req := httptest.NewRequest(http.MethodGet, "/v1/flows/stream", nil).WithContext(ctx)
	conn := &responseStreamConn{readCh: make(chan string, 16)}
	resp := &streamingResponseWriter{
		header: make(http.Header),
		conn:   conn,
	}
	done := make(chan struct{})
	go func() {
		srv.Handler().ServeHTTP(resp, req)
		close(done)
	}()

	select {
	case <-started:
	case <-time.After(1 * time.Second):
		t.Fatalf("reader did not start")
	}

	timeout := time.NewTimer(16 * time.Second)
	defer timeout.Stop()
	for {
		select {
		case line := <-conn.readCh:
			if line == ": keep-alive" {
				cancel()
				select {
				case <-done:
				case <-time.After(500 * time.Millisecond):
				}
				return
			}
		case <-timeout.C:
			t.Fatalf("expected keep-alive comment")
		}
	}
}
