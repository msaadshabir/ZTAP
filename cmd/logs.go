package cmd

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"ztap/internal/logging"
	"ztap/internal/paths"

	"github.com/spf13/cobra"
)

type logsMinLevel int

const (
	logsLevelDebug logsMinLevel = iota
	logsLevelInfo
	logsLevelWarn
	logsLevelError
)

type logLine struct {
	Timestamp string         `json:"timestamp"`
	Level     string         `json:"level"`
	Message   string         `json:"message"`
	Fields    map[string]any `json:"fields"`

	// Legacy fields (older enforcement-log shape).
	PolicyName string `json:"policy_name"`
	Action     string `json:"action"`
	SourceIP   string `json:"source_ip"`
	DestIP     string `json:"dest_ip"`
	Port       int    `json:"port"`
	Protocol   string `json:"protocol"`
}

type logEntry struct {
	Timestamp time.Time
	Level     string
	Message   string
	Fields    map[string]any
	Raw       string
}

type logFilters struct {
	MinLevel logsMinLevel
	Contains string
	Policy   string
}

var logsCmd = &cobra.Command{
	Use:   "logs",
	Short: "View ZTAP logs",
	Long:  "Display ZTAP logs from the configured log file (JSON or text).",
	Run: func(cmd *cobra.Command, args []string) {
		policyFilter, _ := cmd.Flags().GetString("policy")
		contains, _ := cmd.Flags().GetString("contains")
		levelStr, _ := cmd.Flags().GetString("level")
		follow, _ := cmd.Flags().GetBool("follow")
		tail, _ := cmd.Flags().GetInt("tail")

		minLevel, err := parseMinLevel(levelStr)
		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}

		logFile := resolveLogFilePath()
		filters := logFilters{
			MinLevel: minLevel,
			Contains: strings.TrimSpace(contains),
			Policy:   strings.TrimSpace(policyFilter),
		}

		if follow {
			fmt.Println("Following logs (Ctrl+C to stop)...")
			followLogs(logFile, filters, tail)
			return
		}

		entries, err := readLogFile(logFile)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				fmt.Printf("No logs found at %s\n", logFile)
				return
			}
			fmt.Printf("Error: Failed to open log file: %v\n", err)
			return
		}

		entries = filterEntries(entries, filters)
		entries = tailEntries(entries, tail)
		printEntries(entries)
	},
}

func init() {
	logsCmd.Flags().StringP("policy", "p", "", "Filter by policy name (substring match)")
	logsCmd.Flags().StringP("level", "l", "", "Minimum level to show (debug, info, warn, error)")
	logsCmd.Flags().StringP("contains", "c", "", "Filter messages containing substring")
	logsCmd.Flags().BoolP("follow", "f", false, "Follow log output")
	logsCmd.Flags().IntP("tail", "n", 0, "Show last N entries (0 = all)")
	rootCmd.AddCommand(logsCmd)
}

func parseMinLevel(value string) (logsMinLevel, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return logsLevelDebug, nil
	}
	switch value {
	case "debug":
		return logsLevelDebug, nil
	case "info":
		return logsLevelInfo, nil
	case "warn", "warning":
		return logsLevelWarn, nil
	case "error":
		return logsLevelError, nil
	default:
		return logsLevelDebug, fmt.Errorf("invalid --level %q (expected debug, info, warn, error)", value)
	}
}

func levelToMinLevel(value string) logsMinLevel {
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case "error":
		return logsLevelError
	case "warn", "warning":
		return logsLevelWarn
	case "info":
		return logsLevelInfo
	case "debug":
		return logsLevelDebug
	default:
		return logsLevelInfo
	}
}

func resolveLogFilePath() string {
	if v := strings.TrimSpace(os.Getenv("ZTAP_LOG_FILE")); v != "" {
		return paths.Expand(v)
	}

	configPath := os.Getenv("ZTAP_CONFIG")
	if configPath == "" {
		configPath = "config.yaml"
	}
	cfg, err := logging.LoadConfig(configPath)
	if err == nil {
		if strings.TrimSpace(cfg.File) != "" {
			return paths.Expand(cfg.File)
		}
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "/tmp/ztap.log"
	}
	return filepath.Join(home, ".ztap", "ztap.log")
}

func readLogFile(path string) ([]logEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	return readEntries(f)
}

func readEntries(r io.Reader) ([]logEntry, error) {
	scanner := bufio.NewScanner(r)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	entries := make([]logEntry, 0, 256)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		entries = append(entries, parseLogLine(line))
	}
	if err := scanner.Err(); err != nil {
		return entries, err
	}
	return entries, nil
}

func parseLogLine(line string) logEntry {
	if strings.HasPrefix(line, "{") {
		var decoded logLine
		if err := json.Unmarshal([]byte(line), &decoded); err == nil {
			msg := strings.TrimSpace(decoded.Message)
			if msg == "" && decoded.PolicyName != "" {
				msg = fmt.Sprintf("policy=%s action=%s %s %s:%d -> %s:%d",
					decoded.PolicyName,
					decoded.Action,
					decoded.Protocol,
					decoded.SourceIP,
					decoded.Port,
					decoded.DestIP,
					decoded.Port,
				)
			}
			ts, _ := time.Parse(time.RFC3339Nano, strings.TrimSpace(decoded.Timestamp))
			return logEntry{
				Timestamp: ts,
				Level:     strings.TrimSpace(decoded.Level),
				Message:   msg,
				Fields:    decoded.Fields,
				Raw:       line,
			}
		}
	}

	return logEntry{Raw: line, Message: line}
}

func filterEntries(entries []logEntry, filters logFilters) []logEntry {
	contains := strings.ToLower(filters.Contains)
	policy := strings.ToLower(filters.Policy)

	filtered := make([]logEntry, 0, len(entries))
	for _, entry := range entries {
		lvl := levelToMinLevel(entry.Level)
		if lvl < filters.MinLevel {
			continue
		}
		if contains != "" {
			hay := strings.ToLower(entry.Message)
			if !strings.Contains(hay, contains) {
				continue
			}
		}
		if policy != "" {
			hay := strings.ToLower(entry.Message)
			if strings.Contains(hay, policy) {
				filtered = append(filtered, entry)
				continue
			}
			if entry.Fields != nil {
				if v, ok := entry.Fields["policy"]; ok {
					if strings.ToLower(fmt.Sprint(v)) == policy {
						filtered = append(filtered, entry)
						continue
					}
				}
				if v, ok := entry.Fields["policy_name"]; ok {
					if strings.ToLower(fmt.Sprint(v)) == policy {
						filtered = append(filtered, entry)
						continue
					}
				}
			}
			continue
		}

		filtered = append(filtered, entry)
	}
	return filtered
}

func tailEntries(entries []logEntry, n int) []logEntry {
	if n <= 0 {
		return entries
	}
	if len(entries) <= n {
		return entries
	}
	return entries[len(entries)-n:]
}

func printEntries(entries []logEntry) {
	if len(entries) == 0 {
		fmt.Println("No logs found")
		return
	}
	for _, entry := range entries {
		printEntry(entry)
	}
}

func printEntry(entry logEntry) {
	ts := "-"
	if !entry.Timestamp.IsZero() {
		ts = entry.Timestamp.UTC().Format(time.RFC3339)
	}
	lvl := strings.ToUpper(strings.TrimSpace(entry.Level))
	if lvl == "" {
		lvl = "INFO"
	}

	line := fmt.Sprintf("[%s] [%s] %s", ts, lvl, strings.TrimSpace(entry.Message))
	if len(entry.Fields) > 0 {
		line = line + " " + renderFields(entry.Fields)
	}
	fmt.Println(line)
}

func renderFields(fields map[string]any) string {
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	slices.Sort(keys)

	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%v", k, fields[k]))
	}
	return strings.Join(parts, " ")
}

func followLogs(path string, filters logFilters, tail int) {
	// If tail is set, print the last N entries first.
	if tail > 0 {
		entries, err := readLogFile(path)
		if err == nil {
			entries = tailEntries(filterEntries(entries, filters), tail)
			printEntries(entries)
		}
	}

	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			fmt.Printf("No logs found at %s\n", path)
			return
		}
		fmt.Printf("Error: Failed to open log file: %v\n", err)
		return
	}
	defer func() { _ = f.Close() }()

	// Follow from end of file.
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		fmt.Printf("Error: Failed to seek log file: %v\n", err)
		return
	}

	reader := bufio.NewReader(f)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if errors.Is(err, io.EOF) {
				time.Sleep(250 * time.Millisecond)
				continue
			}
			fmt.Printf("Error: Failed to read log file: %v\n", err)
			return
		}
		entry := parseLogLine(strings.TrimSpace(line))
		if len(filterEntries([]logEntry{entry}, filters)) == 0 {
			continue
		}
		printEntry(entry)
	}
}
