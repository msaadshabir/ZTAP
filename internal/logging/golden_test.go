package logging

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

var (
	jsonTSRe = regexp.MustCompile(`"timestamp":"[^"]*"`)
	textTSRe = regexp.MustCompile(`(?m)^\S+ \[`)
)

// normalizeTimestamps replaces timestamps with a placeholder so the golden
// files only pin the stable parts of each entry.
func normalizeTimestamps(s string) string {
	s = jsonTSRe.ReplaceAllString(s, `"timestamp":"<ts>"`)
	return textTSRe.ReplaceAllString(s, "<ts> [")
}

// emitGoldenSequence writes the entries pinned by the .golden files through
// the public API.
func emitGoldenSequence(t *testing.T, logger *Logger) {
	t.Helper()
	if err := logger.SetLevel("debug"); err != nil {
		t.Fatalf("SetLevel(debug): %v", err)
	}
	logger.Debug("debug message", Fields{"component": "debugger", "count": 3})
	logger.Info("info message", Fields{"component": "test", "latency_ms": 42})
	logger.Warn("warn message", Fields{"component": "test", "warn": true})
	logger.Error("error message", nil)
	logger.Info("multi\nline message\r\n", Fields{"component": "test"})
	logger.Info("blank field keys", Fields{"": "dropped", "  kept key  ": "trimmed", "valid": "value"})
}

func readGolden(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatalf("reading golden file: %v", err)
	}
	return string(data)
}

func TestGoldenJSONOutput(t *testing.T) {
	var out strings.Builder
	logger, err := New(Config{Level: "info", Format: "json"})
	if err != nil {
		t.Fatalf("unexpected error creating logger: %v", err)
	}
	logger.SetOutput(&out)
	emitGoldenSequence(t, logger)

	got := normalizeTimestamps(out.String())
	want := readGolden(t, "json.golden")
	if got != want {
		t.Fatalf("JSON output mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

func TestGoldenTextOutput(t *testing.T) {
	var out strings.Builder
	logger, err := New(Config{Level: "info", Format: "text"})
	if err != nil {
		t.Fatalf("unexpected error creating logger: %v", err)
	}
	logger.SetOutput(&out)
	emitGoldenSequence(t, logger)

	got := normalizeTimestamps(out.String())
	want := readGolden(t, "text.golden")
	if got != want {
		t.Fatalf("text output mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}
