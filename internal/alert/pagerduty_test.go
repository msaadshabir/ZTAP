package alert

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestPagerDutySinkSend(t *testing.T) {
	t.Parallel()

	var got map[string]any
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("method: %s", r.Method)
		}
		b, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()
		if err := json.Unmarshal(b, &got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer ts.Close()

	sink, err := NewPagerDutySink("rk", "ztap")
	if err != nil {
		t.Fatalf("NewPagerDutySink: %v", err)
	}
	sink.Client = ts.Client()
	sink.Endpoint = ts.URL

	a := Alert{Timestamp: time.Unix(0, 0), Severity: SeverityWarning, Title: "t", Message: "m", DedupKey: "k", Details: map[string]any{"x": "y"}}
	if err := sink.Send(t.Context(), a); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if got["routing_key"] != "rk" {
		t.Fatalf("routing_key: %v", got["routing_key"])
	}
	if got["event_action"] != "trigger" {
		t.Fatalf("event_action: %v", got["event_action"])
	}
}
