package alert

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSlackSinkSend(t *testing.T) {
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
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	sink, err := NewSlackSink(ts.URL)
	if err != nil {
		t.Fatalf("NewSlackSink: %v", err)
	}
	if err := sink.Send(t.Context(), Alert{Severity: SeverityError, Title: "t", Message: "m"}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if got["text"] == "" {
		t.Fatalf("expected text")
	}
}
