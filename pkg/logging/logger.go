package logging

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
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

// Logger writes structured logs with basic filtering.
type Logger struct {
	mu     sync.Mutex
	out    io.Writer
	level  level
	format string
}

// New creates a logger with the given config.
func New(cfg Config) (*Logger, error) {
	out := io.Writer(os.Stdout)
	if strings.TrimSpace(cfg.File) != "" {
		clean := os.ExpandEnv(cfg.File)
		if strings.HasPrefix(clean, "~") {
			home, err := os.UserHomeDir()
			if err == nil {
				clean = filepath.Join(home, strings.TrimPrefix(clean, "~"))
			}
		}
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

	format := normalizeFormat(cfg.Format)
	logger := &Logger{
		out:    out,
		level:  lvl,
		format: format,
	}

	log.SetFlags(0)
	log.SetOutput(logger)

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

// SetLevel overrides the logger level.
func (l *Logger) SetLevel(levelName string) error {
	lvl, err := parseLevel(levelName)
	if err != nil {
		return err
	}
	l.mu.Lock()
	l.level = lvl
	l.mu.Unlock()
	return nil
}

// SetFormat overrides the log format.
func (l *Logger) SetFormat(format string) {
	l.mu.Lock()
	l.format = normalizeFormat(format)
	l.mu.Unlock()
}

// SetOutput overrides the output writer.
func (l *Logger) SetOutput(w io.Writer) {
	if w == nil {
		return
	}
	l.mu.Lock()
	l.out = w
	l.mu.Unlock()
	log.SetOutput(l)
}

// Output returns the logger output writer.
func (l *Logger) Output() io.Writer {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.out
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
	lvl := l.level
	format := l.format
	out := l.out
	l.mu.Unlock()

	if entryLevel < lvl {
		return
	}

	sanitized := sanitizeMessage(msg)
	if format == formatText {
		writeText(out, entryLevel, sanitized, fields)
		return
	}
	writeJSON(out, entryLevel, sanitized, fields)
}

func sanitizeMessage(value string) string {
	value = strings.ReplaceAll(value, "\n", " ")
	value = strings.ReplaceAll(value, "\r", " ")
	return strings.TrimSpace(value)
}

func levelString(lvl level) string {
	switch lvl {
	case levelDebug:
		return "debug"
	case levelInfo:
		return "info"
	case levelWarn:
		return "warn"
	case levelError:
		return "error"
	default:
		return "info"
	}
}

type jsonEntry struct {
	Timestamp string `json:"timestamp"`
	Level     string `json:"level"`
	Message   string `json:"message"`
	Fields    Fields `json:"fields,omitempty"`
}

func writeJSON(out io.Writer, lvl level, msg string, fields Fields) {
	entry := jsonEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Level:     levelString(lvl),
		Message:   msg,
		Fields:    sanitizeFields(fields),
	}
	data, err := json.Marshal(entry)
	if err != nil {
		fallback := fmt.Sprintf("{\"timestamp\":%q,\"level\":%q,\"message\":%q}", entry.Timestamp, entry.Level, entry.Message)
		_, _ = io.WriteString(out, fallback+"\n")
		return
	}
	_, _ = out.Write(data)
	_, _ = out.Write([]byte("\n"))
}

func writeText(out io.Writer, lvl level, msg string, fields Fields) {
	timestamp := time.Now().UTC().Format(time.RFC3339)
	line := fmt.Sprintf("%s [%s] %s", timestamp, strings.ToUpper(levelString(lvl)), msg)
	fields = sanitizeFields(fields)
	if len(fields) > 0 {
		line = fmt.Sprintf("%s %s", line, renderFields(fields))
	}
	_, _ = io.WriteString(out, line+"\n")
}

func sanitizeFields(fields Fields) Fields {
	if len(fields) == 0 {
		return nil
	}
	clean := make(Fields, len(fields))
	for key, value := range fields {
		cleanKey := strings.TrimSpace(key)
		if cleanKey == "" {
			continue
		}
		clean[cleanKey] = value
	}
	if len(clean) == 0 {
		return nil
	}
	return clean
}

func renderFields(fields Fields) string {
	parts := make([]string, 0, len(fields))
	for key, value := range fields {
		parts = append(parts, fmt.Sprintf("%s=%v", key, value))
	}
	return strings.Join(parts, " ")
}
