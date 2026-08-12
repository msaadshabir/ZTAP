package logging

import (
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoggerRespectsLevels(t *testing.T) {
	var out strings.Builder
	logger, err := New(Config{Level: "warn", Format: "json"})
	if err != nil {
		t.Fatalf("unexpected error creating logger: %v", err)
	}
	logger.SetOutput(&out)

	logger.Info("ignored", nil)
	logger.Warn("kept", nil)

	if strings.Contains(out.String(), "ignored") {
		t.Fatalf("expected info message to be filtered")
	}
	if !strings.Contains(out.String(), "kept") {
		t.Fatalf("expected warn message to be logged")
	}
}

func TestStdlibLogBridge(t *testing.T) {
	var out strings.Builder
	logger, err := New(Config{Level: "info", Format: "json"})
	if err != nil {
		t.Fatalf("unexpected error creating logger: %v", err)
	}
	logger.SetOutput(&out)

	log.Printf("etcd-style %s", "output")

	if !strings.Contains(out.String(), "etcd-style output") {
		t.Fatalf("expected stdlib log output to be bridged, got %q", out.String())
	}
}

func TestSlogDefaultBridge(t *testing.T) {
	var out strings.Builder
	logger, err := New(Config{Level: "info", Format: "json"})
	if err != nil {
		t.Fatalf("unexpected error creating logger: %v", err)
	}
	logger.SetOutput(&out)

	slog.Info("slog-style message", "component", "etcd")

	if !strings.Contains(out.String(), "slog-style message") {
		t.Fatalf("expected slog default to be bridged, got %q", out.String())
	}
	if !strings.Contains(out.String(), `"fields":{"component":"etcd"}`) {
		t.Fatalf("expected slog attrs in fields, got %q", out.String())
	}
}

func TestStdlibLogBridgeRespectsLevel(t *testing.T) {
	var out strings.Builder
	logger, err := New(Config{Level: "warn", Format: "json"})
	if err != nil {
		t.Fatalf("unexpected error creating logger: %v", err)
	}
	logger.SetOutput(&out)

	log.Printf("info-level stdlib output must be filtered")

	if out.String() != "" {
		t.Fatalf("expected stdlib info output to be filtered at warn level, got %q", out.String())
	}
}

func TestLoggerWritesToFile(t *testing.T) {
	tempDir := t.TempDir()
	logPath := filepath.Join(tempDir, "logs", "ztap.log")
	cfg := Config{Level: "info", Format: "json", File: logPath}
	logger, err := New(cfg)
	if err != nil {
		t.Fatalf("unexpected error creating logger: %v", err)
	}
	if file, ok := logger.Output().(*os.File); ok {
		defer func() { _ = file.Close() }()
	}

	logger.Info("hello", Fields{"component": "test"})
	logger.Info("world", nil)

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("expected log file to be created: %v", err)
	}
	if !strings.Contains(string(data), "hello") || !strings.Contains(string(data), "world") {
		t.Fatalf("expected log file to contain entries, got %s", string(data))
	}
}
