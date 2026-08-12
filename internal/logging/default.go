package logging

import (
	"fmt"
	"log/slog"
	"os"
)

// Configure builds a logger from cfg and installs it as the process-wide
// logging default: New bridges both the slog default and the stdlib log sink,
// so the package-level helpers below plus third-party stdlib-log writers
// (etcd, client-go, ...) all share the configured format and level.
func Configure(cfg Config) (*Logger, error) {
	return New(cfg)
}

// Info logs at info level through the process default logger.
func Info(msg string, fields Fields) {
	slog.Default().Info(msg, attrs(fields)...)
}

// Debug logs a debug entry.
func Debug(msg string, fields Fields) {
	slog.Default().Debug(msg, attrs(fields)...)
}

// Warn logs a warning entry.
func Warn(msg string, fields Fields) {
	slog.Default().Warn(msg, attrs(fields)...)
}

// Error logs an error entry.
func Error(msg string, fields Fields) {
	slog.Default().Error(msg, attrs(fields)...)
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

// Fatal logs an error entry through the process default logger and exits.
func Fatal(msg string, fields Fields) {
	slog.Default().Error(msg, attrs(fields)...)
	os.Exit(1)
}

// Fatalf logs an error entry with formatting and exits.
func Fatalf(format string, args ...any) {
	Fatal(fmt.Sprintf(format, args...), nil)
}
