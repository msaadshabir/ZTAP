package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// LogEntry represents a single enforcement log entry
type LogEntry struct {
	Timestamp  time.Time         `json:"timestamp"`
	PolicyName string            `json:"policy_name"`
	Action     string            `json:"action"`
	SourceIP   string            `json:"source_ip"`
	DestIP     string            `json:"dest_ip"`
	Port       int               `json:"port"`
	Protocol   string            `json:"protocol"`
	Labels     map[string]string `json:"labels"`
}

var logsCmd = &cobra.Command{
	Use:   "logs [--policy policy-name]",
	Short: "View enforcement logs",
	Long:  `Display logs of policy enforcement actions (allowed/blocked flows)`,
	Run: func(cmd *cobra.Command, args []string) {
		policyFilter, _ := cmd.Flags().GetString("policy")
		follow, _ := cmd.Flags().GetBool("follow")
		tail, _ := cmd.Flags().GetInt("tail")

		logFile := getLogFilePath()

		if follow {
			fmt.Println("Following logs (Ctrl+C to stop)...")
			tailLogs(logFile, policyFilter, -1)
		} else {
			if tail > 0 {
				tailLogs(logFile, policyFilter, tail)
			} else {
				displayLogs(logFile, policyFilter)
			}
		}
	},
}

func init() {
	logsCmd.Flags().StringP("policy", "p", "", "Filter by policy name")
	logsCmd.Flags().BoolP("follow", "f", false, "Follow log output")
	logsCmd.Flags().IntP("tail", "n", 0, "Show last N entries (0 = all)")
	rootCmd.AddCommand(logsCmd)
}

func getLogFilePath() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "/tmp/ztap.log"
	}
	return filepath.Join(homeDir, ".ztap", "enforcement.log")
}

func displayLogs(logFile, policyFilter string) {
	file, err := os.Open(logFile)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("No logs found. Run 'ztap enforce' to generate logs.")
			return
		}
		fmt.Printf("Error: Failed to open log file: %v\n", err)
		return
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	count := 0

	for {
		var entry LogEntry
		if err := decoder.Decode(&entry); err != nil {
			if err == io.EOF {
				break
			}
			continue
		}

		if policyFilter != "" && entry.PolicyName != policyFilter {
			continue
		}

		printLogEntry(entry)
		count++
	}

	if count == 0 {
		if policyFilter != "" {
			fmt.Printf("No logs found for policy: %s\n", policyFilter)
		} else {
			fmt.Println("No logs found")
		}
	}
}

func tailLogs(logFile, policyFilter string, n int) {
	// For simplicity, this is a basic implementation
	// In production, use a proper tail implementation or library
	file, err := os.Open(logFile)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("No logs found. Run 'ztap enforce' to generate logs.")
			return
		}
		fmt.Printf("Error: Failed to open log file: %v\n", err)
		return
	}
	defer file.Close()

	var entries []LogEntry
	decoder := json.NewDecoder(file)

	for {
		var entry LogEntry
		if err := decoder.Decode(&entry); err != nil {
			if err == io.EOF {
				break
			}
			continue
		}

		if policyFilter == "" || entry.PolicyName == policyFilter {
			entries = append(entries, entry)
		}
	}

	// Show last n entries
	start := 0
	if n > 0 && len(entries) > n {
		start = len(entries) - n
	}

	for i := start; i < len(entries); i++ {
		printLogEntry(entries[i])
	}
}

func printLogEntry(entry LogEntry) {
	actionColor := ""
	if entry.Action == "ALLOWED" {
		actionColor = "[ALLOWED]"
	} else {
		actionColor = "[BLOCKED]"
	}

	labels := ""
	if len(entry.Labels) > 0 {
		var parts []string
		for k, v := range entry.Labels {
			parts = append(parts, fmt.Sprintf("%s=%s", k, v))
		}
		labels = " (" + strings.Join(parts, ", ") + ")"
	}

	fmt.Printf("[%s] %s Policy: %s | %s:%d -> %s:%d%s\n",
		entry.Timestamp.Format("2006-01-02 15:04:05"),
		actionColor,
		entry.PolicyName,
		entry.SourceIP,
		entry.Port,
		entry.DestIP,
		entry.Port,
		labels,
	)
}

// LogEnforcement writes an enforcement action to the log file
func LogEnforcement(policyName, action, sourceIP, destIP, protocol string, port int, labels map[string]string) error {
	logFile := getLogFilePath()

	// Ensure directory exists
	logDir := filepath.Dir(logFile)
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return err
	}

	entry := LogEntry{
		Timestamp:  time.Now(),
		PolicyName: policyName,
		Action:     action,
		SourceIP:   sourceIP,
		DestIP:     destIP,
		Port:       port,
		Protocol:   protocol,
		Labels:     labels,
	}

	file, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	return encoder.Encode(entry)
}
