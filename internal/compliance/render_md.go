package compliance

import (
	"bytes"
	"sort"
	"text/template"
	"time"
)

type mdControlGroup struct {
	Framework FrameworkID
	Controls  []ControlMapping
}

type mdView struct {
	Metadata      ReportMetadata
	Audit         AuditEvidence
	ControlGroups []mdControlGroup
	Policies      []PolicyMapping
	Warnings      []string
}

const mdTemplate = `# Compliance Report

Generated: {{ fmtTime .Metadata.GeneratedAt }}
Host: {{ .Metadata.HostOS }}/{{ .Metadata.HostArch }}
Policy Key: {{ if .Metadata.PolicyKey }}{{ .Metadata.PolicyKey }}{{ else }}(unknown){{ end }}
Mapping Source: {{ if .Metadata.MappingSource }}{{ .Metadata.MappingSource }}{{ else }}(unknown){{ end }}
Audit Log: {{ if .Metadata.AuditLogPath }}{{ .Metadata.AuditLogPath }}{{ else }}(not provided){{ end }}

## Audit Evidence

- Integrity: {{ .Audit.IntegrityStatus }}{{ if .Audit.IntegrityError }} ({{ .Audit.IntegrityError }}){{ end }}
- Entry Count: {{ .Audit.EntryCount }}
- Last Hash: {{ if .Audit.LastHash }}{{ .Audit.LastHash }}{{ else }}(unknown){{ end }}

## Control Coverage

{{- range .ControlGroups }}

### {{ .Framework }}

{{- range .Controls }}

#### {{ .ControlID }}

- Evidence: {{ .Evidence.Status }}
- Policies:
{{- range .Policies }}
  - {{ .PolicyKey }} (object: {{ .PolicyObjectName }})
{{- end }}
{{- end }}
{{- end }}

## Policy Index

{{- range .Policies }}

### {{ .Policy.PolicyKey }} (object: {{ .Policy.PolicyObjectName }})

- Enforcement Evidence: {{ .Evidence.Enforced }} (events: {{ .Evidence.EnforcedCount }})
{{- if .Owner }}
- Owner: {{ .Owner }}
{{- end }}
{{- if .Rationale }}
- Rationale: {{ .Rationale }}
{{- end }}
- Controls:
{{- range .Controls }}
  - {{ .Framework }} {{ .ControlID }}
{{- end }}
{{- end }}

{{ if .Warnings }}
## Warnings
{{ range .Warnings }}
- {{ . }}
{{ end }}
{{ end }}`

func RenderMarkdown(report Report) (string, error) {
	view := mdView{
		Metadata: report.Metadata,
		Audit:    report.Audit,
		Policies: append([]PolicyMapping(nil), report.Policies...),
		Warnings: append([]string(nil), report.Warnings...),
	}

	controls := append([]ControlMapping(nil), report.Controls...)
	sort.Slice(controls, func(i, j int) bool {
		if controls[i].Framework == controls[j].Framework {
			return controls[i].ControlID < controls[j].ControlID
		}
		return controls[i].Framework < controls[j].Framework
	})

	for _, c := range controls {
		if len(view.ControlGroups) == 0 || view.ControlGroups[len(view.ControlGroups)-1].Framework != c.Framework {
			view.ControlGroups = append(view.ControlGroups, mdControlGroup{Framework: c.Framework})
		}
		idx := len(view.ControlGroups) - 1
		view.ControlGroups[idx].Controls = append(view.ControlGroups[idx].Controls, c)
	}

	funcs := template.FuncMap{
		"fmtTime": func(t time.Time) string {
			if t.IsZero() {
				return "(unknown)"
			}
			return t.UTC().Format(time.RFC3339)
		},
	}

	t, err := template.New("report").Funcs(funcs).Parse(mdTemplate)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, view); err != nil {
		return "", err
	}
	return buf.String(), nil
}
