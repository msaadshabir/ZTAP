package logging

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoggerRespectsLevels(t *testing.T) {
	logger := &Logger{out: &strings.Builder{}, level: levelWarn, format: formatJSON}
	logger.Info("ignored", nil)
	logger.Warn("kept", nil)

	builder := logger.out.(*strings.Builder)
	if strings.Contains(builder.String(), "ignored") {
		t.Fatalf("expected info message to be filtered")
	}
	if !strings.Contains(builder.String(), "kept") {
		t.Fatalf("expected warn message to be logged")
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
