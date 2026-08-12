package logging

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"strings"
	"time"
)

// ztapHandler is a slog.Handler that writes ZTAP's historical log schema, so
// existing consumers (`ztap logs`, log shippers, the audit pipeline) keep
// working unchanged:
//
//	json: {"timestamp":"<RFC3339Nano>","level":"info","message":"...","fields":{...}}
//	text: 2026-01-02T15:04:05Z [INFO] message key=value
//
// The schema pins: UTC timestamps (RFC3339Nano for json, RFC3339 seconds for
// text), lowercase level names, newline/CR sanitization of messages, trimmed
// non-empty field keys, and alphabetically sorted field keys (matching
// encoding/json's map marshaling).
type ztapHandler struct {
	out   io.Writer
	lvl   slog.Leveler
	mode  string // formatJSON or formatText
	attrs []slog.Attr
	group string
}

// Enabled reports whether records at the given level should be handled.
func (h *ztapHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.lvl.Level()
}

// Handle writes one record in the configured format.
func (h *ztapHandler) Handle(_ context.Context, r slog.Record) error {
	fields := make(Fields)
	for _, a := range h.attrs {
		appendField(fields, h.group, a)
	}
	r.Attrs(func(a slog.Attr) bool {
		appendField(fields, h.group, a)
		return true
	})

	msg := sanitizeMessage(r.Message)
	ts := r.Time
	if ts.IsZero() {
		ts = time.Now()
	}
	if h.mode == formatText {
		writeText(h.out, r.Level, ts, msg, fields)
		return nil
	}
	writeJSON(h.out, r.Level, ts, msg, fields)
	return nil
}

// WithAttrs returns a handler with persistent attributes; per-record
// attributes with the same key override them.
func (h *ztapHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	merged := make([]slog.Attr, 0, len(h.attrs)+len(attrs))
	merged = append(merged, h.attrs...)
	merged = append(merged, attrs...)
	cp := *h
	cp.attrs = merged
	return &cp
}

// WithGroup returns a handler whose keys are prefixed with the group name
// (ZTAP's schema has no nesting, so groups are flattened with a dot).
func (h *ztapHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	cp := *h
	if cp.group != "" {
		cp.group += "." + name
	} else {
		cp.group = name
	}
	return &cp
}

func appendField(fields Fields, prefix string, a slog.Attr) {
	key := a.Key
	if prefix != "" {
		key = prefix + "." + key
	}
	if a.Value.Kind() == slog.KindGroup {
		for _, child := range a.Value.Group() {
			appendField(fields, key, child)
		}
		return
	}
	fields[key] = a.Value.Any()
}

func levelString(lvl slog.Level) string {
	return strings.ToLower(lvl.String())
}

type jsonEntry struct {
	Timestamp string `json:"timestamp"`
	Level     string `json:"level"`
	Message   string `json:"message"`
	Fields    Fields `json:"fields,omitempty"`
}

func writeJSON(out io.Writer, lvl slog.Level, ts time.Time, msg string, fields Fields) {
	entry := jsonEntry{
		Timestamp: ts.UTC().Format(time.RFC3339Nano),
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

func writeText(out io.Writer, lvl slog.Level, ts time.Time, msg string, fields Fields) {
	line := fmt.Sprintf("%s [%s] %s", ts.UTC().Format(time.RFC3339), strings.ToUpper(levelString(lvl)), msg)
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
	keys := make([]string, 0, len(fields))
	for key := range fields {
		keys = append(keys, key)
	}
	slices.Sort(keys)

	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, fmt.Sprintf("%s=%v", key, fields[key]))
	}
	return strings.Join(parts, " ")
}
