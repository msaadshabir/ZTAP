package logging

import (
	"fmt"
	"os"
	"sync"
)

var (
	defaultMu     sync.RWMutex
	defaultLogger *Logger
	exitFn        = os.Exit
)

// Configure initializes the default logger using the provided config.
func Configure(cfg Config) (*Logger, error) {
	logger, err := New(cfg)
	if err != nil {
		return nil, err
	}
	defaultMu.Lock()
	defaultLogger = logger
	defaultMu.Unlock()
	return logger, nil
}

// Default returns the configured logger or creates one with defaults.
func Default() *Logger {
	defaultMu.RLock()
	logger := defaultLogger
	defaultMu.RUnlock()
	if logger != nil {
		return logger
	}

	defaultMu.Lock()
	defer defaultMu.Unlock()
	if defaultLogger == nil {
		logger, _ = New(DefaultConfig())
		defaultLogger = logger
	}
	return defaultLogger
}

// Debug logs a debug entry.
func Debug(msg string, fields Fields) {
	Default().Debug(msg, fields)
}

// Info logs an info entry.
func Info(msg string, fields Fields) {
	Default().Info(msg, fields)
}

// Warn logs a warning entry.
func Warn(msg string, fields Fields) {
	Default().Warn(msg, fields)
}

// Error logs an error entry.
func Error(msg string, fields Fields) {
	Default().Error(msg, fields)
}

// Debugf logs a debug entry with formatting.
func Debugf(format string, args ...any) {
	Debug(fmt.Sprintf(format, args...), nil)
}

// Infof logs an info entry with formatting.
func Infof(format string, args ...any) {
	Info(fmt.Sprintf(format, args...), nil)
}

// Warnf logs a warning entry with formatting.
func Warnf(format string, args ...any) {
	Warn(fmt.Sprintf(format, args...), nil)
}

// Errorf logs an error entry with formatting.
func Errorf(format string, args ...any) {
	Error(fmt.Sprintf(format, args...), nil)
}

// Fatal logs an error entry and exits.
func Fatal(msg string, fields Fields) {
	Error(msg, fields)
	exitFn(1)
}

// Fatalf logs an error entry with formatting and exits.
func Fatalf(format string, args ...any) {
	Fatal(fmt.Sprintf(format, args...), nil)
}
