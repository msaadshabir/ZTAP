package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"ztap/pkg/audit"

	"github.com/spf13/cobra"
)

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Audit log management",
	Long:  `View and verify tamper-proof audit logs for all policy and system changes.`,
}

var auditViewCmd = &cobra.Command{
	Use:   "view",
	Short: "View audit log entries",
	Long:  `Query and display audit log entries with optional filtering.`,
	RunE:  runAuditView,
}

var auditVerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify audit log integrity",
	Long:  `Verify the cryptographic integrity of the audit log to detect tampering.`,
	RunE:  runAuditVerify,
}

var auditStatsCmd = &cobra.Command{
	Use:   "stats",
	Short: "Display audit log statistics",
	Long:  `Show statistics about the audit log including size, entry count, and last modification.`,
	RunE:  runAuditStats,
}

var (
	auditEventType string
	auditActor     string
	auditResource  string
	auditLimit     int
	auditStartTime string
	auditEndTime   string
	auditFollow    bool
)

func init() {
	// View command flags
	auditViewCmd.Flags().StringVar(&auditEventType, "type", "", "Filter by event type (e.g., policy.created, user.login)")
	auditViewCmd.Flags().StringVar(&auditActor, "actor", "", "Filter by actor (username or system)")
	auditViewCmd.Flags().StringVar(&auditResource, "resource", "", "Filter by resource name")
	auditViewCmd.Flags().IntVar(&auditLimit, "limit", 50, "Maximum number of entries to display")
	auditViewCmd.Flags().StringVar(&auditStartTime, "start", "", "Start time (RFC3339 format)")
	auditViewCmd.Flags().StringVar(&auditEndTime, "end", "", "End time (RFC3339 format)")
	auditViewCmd.Flags().BoolVar(&auditFollow, "follow", false, "Follow audit log in real-time")

	auditCmd.AddCommand(auditViewCmd)
	auditCmd.AddCommand(auditVerifyCmd)
	auditCmd.AddCommand(auditStatsCmd)

	rootCmd.AddCommand(auditCmd)
}

func runAuditView(cmd *cobra.Command, args []string) error {
	logPath, err := getAuditLogPath()
	if err != nil {
		return err
	}

	logger, err := audit.NewAuditLogger(logPath)
	if err != nil {
		return fmt.Errorf("failed to open audit log: %w", err)
	}
	defer logger.Close()

	// Build query options
	opts := audit.QueryOptions{
		Limit: auditLimit,
	}

	if auditEventType != "" {
		eventType := audit.EventType(auditEventType)
		opts.EventType = &eventType
	}

	if auditActor != "" {
		opts.Actor = &auditActor
	}

	if auditResource != "" {
		opts.Resource = &auditResource
	}

	if auditStartTime != "" {
		t, err := time.Parse(time.RFC3339, auditStartTime)
		if err != nil {
			return fmt.Errorf("invalid start time format: %w", err)
		}
		opts.StartTime = &t
	}

	if auditEndTime != "" {
		t, err := time.Parse(time.RFC3339, auditEndTime)
		if err != nil {
			return fmt.Errorf("invalid end time format: %w", err)
		}
		opts.EndTime = &t
	}

	// Query entries
	entries, err := logger.Query(opts)
	if err != nil {
		return fmt.Errorf("failed to query audit log: %w", err)
	}

	if len(entries) == 0 {
		fmt.Println("No audit entries found matching the specified filters.")
		return nil
	}

	// Display entries
	fmt.Printf("Found %d audit entries:\n\n", len(entries))
	for i, entry := range entries {
		displayAuditEntry(entry, i+1)
		if i < len(entries)-1 {
			fmt.Println(strings.Repeat("-", 80))
		}
	}

	return nil
}

func runAuditVerify(cmd *cobra.Command, args []string) error {
	logPath, err := getAuditLogPath()
	if err != nil {
		return err
	}

	logger, err := audit.NewAuditLogger(logPath)
	if err != nil {
		return fmt.Errorf("failed to open audit log: %w", err)
	}
	defer logger.Close()

	fmt.Println("Verifying audit log integrity...")
	fmt.Printf("Log file: %s\n\n", logPath)

	valid, err := logger.VerifyIntegrity()
	if err != nil {
		fmt.Printf("[FAIL] Integrity verification failed: %v\n", err)
		return err
	}

	if valid {
		fmt.Println("[PASS] Audit log integrity verified successfully.")
		fmt.Println("       No tampering detected.")
		return nil
	}

	fmt.Println("[FAIL] Audit log integrity check failed.")
	fmt.Println("       TAMPERING DETECTED!")
	return fmt.Errorf("audit log has been tampered with")
}

func runAuditStats(cmd *cobra.Command, args []string) error {
	logPath, err := getAuditLogPath()
	if err != nil {
		return err
	}

	logger, err := audit.NewAuditLogger(logPath)
	if err != nil {
		return fmt.Errorf("failed to open audit log: %w", err)
	}
	defer logger.Close()

	stats, err := logger.GetStats()
	if err != nil {
		return fmt.Errorf("failed to get audit log stats: %w", err)
	}

	fmt.Println("Audit Log Statistics")
	fmt.Println("====================")
	fmt.Printf("Path:         %s\n", stats["path"])
	fmt.Printf("Size:         %d bytes (%.2f KB)\n", stats["size_bytes"], float64(stats["size_bytes"].(int64))/1024)
	fmt.Printf("Entry Count:  %d\n", stats["entry_count"])
	fmt.Printf("Last Hash:    %s\n", stats["last_hash"])
	fmt.Printf("Modified:     %s\n", stats["modified_at"].(time.Time).Format(time.RFC3339))

	return nil
}

func displayAuditEntry(entry audit.AuditEntry, index int) {
	fmt.Printf("[%d] %s\n", index, entry.Timestamp.Format(time.RFC3339))
	fmt.Printf("    Event:     %s\n", entry.EventType)
	fmt.Printf("    Actor:     %s\n", entry.Actor)
	fmt.Printf("    Resource:  %s\n", entry.Resource)
	fmt.Printf("    Action:    %s\n", entry.Action)
	fmt.Printf("    Outcome:   %s\n", entry.Outcome)

	if entry.ErrorMessage != "" {
		fmt.Printf("    Error:     %s\n", entry.ErrorMessage)
	}

	if entry.NodeID != "" {
		fmt.Printf("    Node:      %s\n", entry.NodeID)
	}

	if len(entry.Details) > 0 {
		fmt.Printf("    Details:   ")
		first := true
		for k, v := range entry.Details {
			if !first {
				fmt.Printf("               ")
			}
			fmt.Printf("%s=%v\n", k, v)
			first = false
		}
	}

	fmt.Printf("    Hash:      %s\n", entry.Hash[:16]+"...")
}

func getAuditLogPath() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get home directory: %w", err)
	}

	logPath := filepath.Join(homeDir, ".ztap", "audit.log")
	return logPath, nil
}
