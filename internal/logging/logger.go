package logging

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"ztap/internal/paths"
)

type level int

const (
	levelDebug level = iota
	levelInfo
	levelWarn
	levelError
)

const (
	formatJSON = "json"
	formatText = "text"
)

// Fields represents structured fields attached to log entries.
type Fields map[string]any

// Logger writes structured logs with basic filtering. Internals are
// implemented over log/slog; the public API is a thin shim so existing call
// sites are untouched.
type Logger struct {
	mu     sync.Mutex
	out    io.Writer
	format string
	lvl    slog.LevelVar
	slog   *slog.Logger
}

// New creates a logger with the given config.
func New(cfg Config) (*Logger, error) {
	out := io.Writer(os.Stdout)
	if strings.TrimSpace(cfg.File) != "" {
		clean := paths.Expand(cfg.File)
		dir := filepath.Dir(clean)
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, fmt.Errorf("creating log directory: %w", err)
		}
		file, err := os.OpenFile(clean, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			return nil, fmt.Errorf("opening log file: %w", err)
		}
		out = file
	}

	lvl, err := parseLevel(cfg.Level)
	if err != nil {
		return nil, err
	}

	logger := &Logger{
		out:    out,
		format: normalizeFormat(cfg.Format),
	}
	logger.lvl.Set(toSlogLevel(lvl))
	logger.rebuildLocked()

	return logger, nil
}

func normalizeFormat(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == formatText {
		return formatText
	}
	return formatJSON
}

func parseLevel(value string) (level, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "debug":
		return levelDebug, nil
	case "info", "":
		return levelInfo, nil
	case "warn", "warning":
		return levelWarn, nil
	case "error":
		return levelError, nil
	default:
		return levelInfo, fmt.Errorf("invalid log level %q", value)
	}
}

func toSlogLevel(lvl level) slog.Level {
	switch lvl {
	case levelDebug:
		return slog.LevelDebug
	case levelWarn:
		return slog.LevelWarn
	case levelError:
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// attrs converts a Fields map into the key/value pairs expected by slog.
func attrs(fields Fields) []any {
	if len(fields) == 0 {
		return nil
	}
	args := make([]any, 0, len(fields)*2)
	for key, value := range fields {
		args = append(args, key, value)
	}
	return args
}

// SetLevel overrides the logger level.
func (l *Logger) SetLevel(levelName string) error {
	lvl, err := parseLevel(levelName)
	if err != nil {
		return err
	}
	l.lvl.Set(toSlogLevel(lvl))
	return nil
}

// SetFormat overrides the log format.
func (l *Logger) SetFormat(format string) {
	l.mu.Lock()
	l.format = normalizeFormat(format)
	l.rebuildLocked()
	l.mu.Unlock()
}

// SetOutput overrides the output writer.
func (l *Logger) SetOutput(w io.Writer) {
	if w == nil {
		return
	}
	l.mu.Lock()
	l.out = w
	l.rebuildLocked()
	l.mu.Unlock()
}

// Output returns the logger output writer.
func (l *Logger) Output() io.Writer {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.out
}

// Handler returns the underlying slog handler, for embedding this logger in
// third-party logging stacks (e.g. the operator's logr bridge).
func (l *Logger) Handler() slog.Handler {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.slog.Handler()
}

// Debug logs a debug entry.
func (l *Logger) Debug(msg string, fields Fields) {
	l.log(levelDebug, msg, fields)
}

// Info logs an info entry.
func (l *Logger) Info(msg string, fields Fields) {
	l.log(levelInfo, msg, fields)
}

// Warn logs a warning entry.
func (l *Logger) Warn(msg string, fields Fields) {
	l.log(levelWarn, msg, fields)
}

// Error logs an error entry.
func (l *Logger) Error(msg string, fields Fields) {
	l.log(levelError, msg, fields)
}

// Printf is compatible with log.Printf by logging at info level.
func (l *Logger) Printf(format string, args ...any) {
	l.Info(fmt.Sprintf(format, args...), nil)
}

// Println is compatible with log.Println by logging at info level.
func (l *Logger) Println(args ...any) {
	l.Info(fmt.Sprintln(args...), nil)
}

// Write implements io.Writer for the standard log package.
func (l *Logger) Write(p []byte) (int, error) {
	msg := strings.TrimSpace(string(p))
	if msg == "" {
		return len(p), nil
	}
	l.log(levelInfo, msg, nil)
	return len(p), nil
}

func (l *Logger) log(entryLevel level, msg string, fields Fields) {
	l.mu.Lock()
	logger := l.slog
	l.mu.Unlock()

	logger.Log(context.Background(), toSlogLevel(entryLevel), sanitizeMessage(msg), attrs(fields)...)
}

// rebuildLocked rebuilds the underlying slog logger after output or format
// changes. Callers must hold l.mu.
func (l *Logger) rebuildLocked() {
	l.slog = slog.New(&ztapHandler{out: l.out, lvl: &l.lvl, mode: l.format})
	// slog.SetDefault links both the slog default and the stdlib log sink (via
	// an internal handlerWriter at SetLogLoggerLevel, default info) to this
	// logger, so third-party components (etcd, client-go, ...) share the
	// configured format and level.
	slog.SetDefault(l.slog)
}

func sanitizeMessage(value string) string {
	value = strings.ReplaceAll(value, "\n", " ")
	value = strings.ReplaceAll(value, "\r", " ")
	return strings.TrimSpace(value)
}
