package logging

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/go-logr/logr"
)

type testLogValuer struct{}

func (testLogValuer) LogValue() slog.Value {
	return slog.StringValue("resolved")
}

func TestHandlerResolvesValuesAndErrors(t *testing.T) {
	var out strings.Builder
	logger, err := New(Config{Level: "info", Format: "json"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	logger.SetOutput(&out)

	logger.Info("values", Fields{
		"value": testLogValuer{},
		"err":   errors.New("boom"),
	})

	line := strings.TrimSpace(out.String())
	var entry map[string]any
	if err := json.Unmarshal([]byte(line), &entry); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}
	fields, ok := entry["fields"].(map[string]any)
	if !ok {
		t.Fatalf("expected fields object, got %#v", entry["fields"])
	}
	if got := fields["value"]; got != "resolved" {
		t.Fatalf("expected resolved LogValuer, got %#v", got)
	}
	if got := fields["err"]; got != "boom" {
		t.Fatalf("expected error string, got %#v", got)
	}
}

func TestLogrBridgeUsesCanonicalLevelsAndErrors(t *testing.T) {
	var out strings.Builder
	logger, err := New(Config{Level: "debug", Format: "json"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	logger.SetOutput(&out)

	operatorLog := logr.FromSlogHandler(logger.Handler())
	operatorLog.V(1).Info("verbose")
	operatorLog.Error(errors.New("operator failure"), "failed")

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected two log lines, got %d: %q", len(lines), out.String())
	}
	if !strings.Contains(lines[0], `"level":"debug"`) {
		t.Fatalf("expected canonical debug level, got %q", lines[0])
	}
	if strings.Contains(lines[0], "debug+") {
		t.Fatalf("unexpected noncanonical verbosity level, got %q", lines[0])
	}
	if !strings.Contains(lines[1], `"err":"operator failure"`) {
		t.Fatalf("expected operator error text, got %q", lines[1])
	}
}

func TestHandlerSerializesConcurrentWrites(t *testing.T) {
	var out bytes.Buffer
	logger, err := New(Config{Level: "info", Format: "json"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	logger.SetOutput(&out)

	const (
		workers     = 16
		entriesEach = 100
	)
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < entriesEach; j++ {
				logger.Info("concurrent", nil)
			}
		}()
	}
	wg.Wait()

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	expected := workers * entriesEach
	if len(lines) != expected {
		t.Fatalf("expected %d log lines, got %d", expected, len(lines))
	}
	for i, line := range lines {
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("line %d is invalid JSON: %v (%q)", i, err, line)
		}
	}
}
