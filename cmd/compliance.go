package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"ztap/pkg/compliance"
	"ztap/pkg/policy"

	"github.com/spf13/cobra"
)

var complianceCmd = &cobra.Command{
	Use:   "compliance",
	Short: "Generate compliance mapping exports and reports",
}

type complianceInputs struct {
	policyFiles []string
	policyStdin bool
	policyName  string
	mappingFile string
	frameworks  []string
	auditLog    string
	window      string
	strict      bool
	format      string
	out         string
	outDir      string
}

func (in complianceInputs) loadPolicies() ([]policy.NetworkPolicy, error) {
	all := make([]policy.NetworkPolicy, 0)
	for _, p := range in.policyFiles {
		pols, err := policy.LoadFromFile(p)
		if err != nil {
			return nil, err
		}
		all = append(all, pols...)
	}

	if in.policyStdin {
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			return nil, fmt.Errorf("read policy yaml from stdin: %w", err)
		}
		pols, err := policy.LoadFromBytes(b)
		if err != nil {
			return nil, err
		}
		all = append(all, pols...)
	}

	if len(in.policyFiles) == 0 && !in.policyStdin {
		return nil, errors.New("provide --policy-file or --policy-yaml-stdin")
	}
	if len(all) == 0 {
		return nil, errors.New("no NetworkPolicy objects found")
	}
	for _, p := range all {
		if err := p.Validate(); err != nil {
			return nil, err
		}
	}
	return all, nil
}

func (in complianceInputs) buildFrameworks() ([]compliance.FrameworkID, error) {
	if len(in.frameworks) == 0 {
		return nil, nil
	}
	out := make([]compliance.FrameworkID, 0, len(in.frameworks))
	for _, fw := range in.frameworks {
		id, ok := compliance.ParseFrameworkID(fw)
		if !ok {
			return nil, fmt.Errorf("unknown framework %q", fw)
		}
		out = append(out, id)
	}
	return out, nil
}

func (in complianceInputs) loadMappingFile() ([]byte, error) {
	if strings.TrimSpace(in.mappingFile) == "" {
		return nil, nil
	}
	return os.ReadFile(in.mappingFile)
}

func (in complianceInputs) evidenceWindow() (time.Duration, error) {
	if strings.TrimSpace(in.window) == "" {
		return 90 * 24 * time.Hour, nil
	}
	// Support simple Go duration; also accept "90d" style.
	if strings.HasSuffix(in.window, "d") {
		n := strings.TrimSpace(strings.TrimSuffix(in.window, "d"))
		if n == "" {
			return 0, errors.New("invalid evidence-window")
		}
		v, err := strconv.ParseFloat(n, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid evidence-window %q: %w", in.window, err)
		}
		return time.Duration(v * float64(24*time.Hour)), nil
	}
	return time.ParseDuration(in.window)
}

func openOut(path string) (io.WriteCloser, error) {
	if strings.TrimSpace(path) == "" || path == "-" {
		return nopWriteCloser{Writer: os.Stdout}, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	return os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
}

type nopWriteCloser struct{ io.Writer }

func (n nopWriteCloser) Close() error { return nil }

var complianceExportCmd = &cobra.Command{
	Use:          "export",
	Short:        "Export control mappings (json/csv)",
	Example:      "  ztap compliance export -f policy.yaml --format json\n  ztap compliance export -f policy.yaml --format csv --out mappings.csv\n  cat policy.yaml | ztap compliance export --policy-yaml-stdin",
	SilenceUsage: true,
	Args:         cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		var in complianceInputs
		in.policyFiles, _ = cmd.Flags().GetStringArray("policy-file")
		in.policyStdin, _ = cmd.Flags().GetBool("policy-yaml-stdin")
		in.policyName, _ = cmd.Flags().GetString("policy-name")
		in.mappingFile, _ = cmd.Flags().GetString("mapping-file")
		in.frameworks, _ = cmd.Flags().GetStringArray("framework")
		in.auditLog, _ = cmd.Flags().GetString("audit-log")
		in.window, _ = cmd.Flags().GetString("evidence-window")
		in.strict, _ = cmd.Flags().GetBool("strict")
		in.format, _ = cmd.Flags().GetString("format")
		in.out, _ = cmd.Flags().GetString("out")

		policies, err := in.loadPolicies()
		if err != nil {
			return err
		}
		frameworks, err := in.buildFrameworks()
		if err != nil {
			return err
		}
		mappingYAML, err := in.loadMappingFile()
		if err != nil {
			return err
		}
		window, err := in.evidenceWindow()
		if err != nil {
			return err
		}

		report, err := compliance.BuildReport(cmd.Context(), policies, compliance.BuildOptions{
			PolicyName:      in.policyName,
			Frameworks:      frameworks,
			MappingFileYAML: mappingYAML,
			Strict:          in.strict,
			AuditLogPath:    in.auditLog,
			EvidenceWindow:  window,
		})
		if err != nil {
			return err
		}

		w, err := openOut(in.out)
		if err != nil {
			return err
		}
		defer w.Close()

		switch strings.ToLower(strings.TrimSpace(in.format)) {
		case "", "json":
			return compliance.WriteJSON(w, report)
		case "csv":
			return compliance.WriteCSV(w, report)
		default:
			return fmt.Errorf("unsupported format %q", in.format)
		}
	},
}

var complianceReportCmd = &cobra.Command{
	Use:          "report",
	Short:        "Generate a human-readable compliance report (md/json)",
	Example:      "  ztap compliance report -f policy.yaml --format md\n  ztap compliance report -f policy.yaml --out-dir out/compliance\n  cat policy.yaml | ztap compliance report --policy-yaml-stdin",
	SilenceUsage: true,
	Args:         cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		var in complianceInputs
		in.policyFiles, _ = cmd.Flags().GetStringArray("policy-file")
		in.policyStdin, _ = cmd.Flags().GetBool("policy-yaml-stdin")
		in.policyName, _ = cmd.Flags().GetString("policy-name")
		in.mappingFile, _ = cmd.Flags().GetString("mapping-file")
		in.frameworks, _ = cmd.Flags().GetStringArray("framework")
		in.auditLog, _ = cmd.Flags().GetString("audit-log")
		in.window, _ = cmd.Flags().GetString("evidence-window")
		in.strict, _ = cmd.Flags().GetBool("strict")
		in.format, _ = cmd.Flags().GetString("format")
		in.out, _ = cmd.Flags().GetString("out")
		in.outDir, _ = cmd.Flags().GetString("out-dir")

		policies, err := in.loadPolicies()
		if err != nil {
			return err
		}
		frameworks, err := in.buildFrameworks()
		if err != nil {
			return err
		}
		mappingYAML, err := in.loadMappingFile()
		if err != nil {
			return err
		}
		window, err := in.evidenceWindow()
		if err != nil {
			return err
		}

		report, err := compliance.BuildReport(cmd.Context(), policies, compliance.BuildOptions{
			PolicyName:      in.policyName,
			Frameworks:      frameworks,
			MappingFileYAML: mappingYAML,
			Strict:          in.strict,
			AuditLogPath:    in.auditLog,
			EvidenceWindow:  window,
		})
		if err != nil {
			return err
		}

		format := strings.ToLower(strings.TrimSpace(in.format))
		if format == "" {
			format = "md"
		}

		// Optional bundle output.
		if strings.TrimSpace(in.outDir) != "" {
			if err := os.MkdirAll(in.outDir, 0o750); err != nil {
				return err
			}
			md, err := compliance.RenderMarkdown(report)
			if err != nil {
				return err
			}
			if err := os.WriteFile(filepath.Join(in.outDir, "report.md"), []byte(md), 0o600); err != nil {
				return err
			}
			jf, err := os.OpenFile(filepath.Join(in.outDir, "report.json"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
			if err != nil {
				return err
			}
			_ = compliance.WriteJSON(jf, report)
			_ = jf.Close()
			return nil
		}

		w, err := openOut(in.out)
		if err != nil {
			return err
		}
		defer func() {
			if cerr := w.Close(); err == nil && cerr != nil {
				err = cerr
			}
		}()

		switch format {
		case "md", "markdown":
			md, err := compliance.RenderMarkdown(report)
			if err != nil {
				return err
			}
			_, err = w.Write([]byte(md))
			return err
		case "json":
			return compliance.WriteJSON(w, report)
		default:
			return fmt.Errorf("unsupported format %q", in.format)
		}
	},
}

func init() {
	complianceExportCmd.Flags().StringArrayP("policy-file", "f", nil, "Path to policy YAML file (repeatable)")
	complianceExportCmd.Flags().Bool("policy-yaml-stdin", false, "Read additional policy YAML from stdin")
	complianceExportCmd.Flags().String("policy-name", "", "Policy key for audit correlation (matches audit resource; accepts tenant/name)")
	complianceExportCmd.Flags().String("mapping-file", "", "Path to compliance mapping YAML")
	complianceExportCmd.Flags().StringArray("framework", nil, "Framework IDs to include (pci-dss,soc2,hipaa)")
	complianceExportCmd.Flags().String("audit-log", "", "Path to audit log (defaults to ~/.ztap/audit.log if present)")
	complianceExportCmd.Flags().String("evidence-window", "90d", "Lookback window for enforcement evidence (e.g. 90d, 2160h, 30m)")
	complianceExportCmd.Flags().Bool("strict", false, "Fail on unknown frameworks or invalid control IDs")
	complianceExportCmd.Flags().String("format", "json", "Output format: json|csv")
	complianceExportCmd.Flags().String("out", "-", "Output path ('-' for stdout)")

	complianceReportCmd.Flags().StringArrayP("policy-file", "f", nil, "Path to policy YAML file (repeatable)")
	complianceReportCmd.Flags().Bool("policy-yaml-stdin", false, "Read additional policy YAML from stdin")
	complianceReportCmd.Flags().String("policy-name", "", "Policy key for audit correlation (matches audit resource; accepts tenant/name)")
	complianceReportCmd.Flags().String("mapping-file", "", "Path to compliance mapping YAML")
	complianceReportCmd.Flags().StringArray("framework", nil, "Framework IDs to include (pci-dss,soc2,hipaa)")
	complianceReportCmd.Flags().String("audit-log", "", "Path to audit log (defaults to ~/.ztap/audit.log if present)")
	complianceReportCmd.Flags().String("evidence-window", "90d", "Lookback window for enforcement evidence (e.g. 90d, 2160h, 30m)")
	complianceReportCmd.Flags().Bool("strict", false, "Fail on unknown frameworks or invalid control IDs")
	complianceReportCmd.Flags().String("format", "md", "Output format: md|json")
	complianceReportCmd.Flags().String("out", "-", "Output path ('-' for stdout)")
	complianceReportCmd.Flags().String("out-dir", "", "Write bundle to a directory (report.md + report.json)")

	complianceCmd.AddCommand(complianceExportCmd)
	complianceCmd.AddCommand(complianceReportCmd)
	rootCmd.AddCommand(complianceCmd)
}
