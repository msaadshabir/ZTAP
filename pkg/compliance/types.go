package compliance

import "time"

type FrameworkID string

const (
	FrameworkPCIDSS FrameworkID = "pci-dss"
	FrameworkSOC2   FrameworkID = "soc2"
	FrameworkHIPAA  FrameworkID = "hipaa"
)

type EvidenceStatus string

const (
	EvidencePresent EvidenceStatus = "present"
	EvidenceMissing EvidenceStatus = "missing"
	EvidenceUnknown EvidenceStatus = "unknown"
)

type ReportMetadata struct {
	GeneratedAt time.Time `json:"generated_at"`
	HostOS      string    `json:"host_os"`
	HostArch    string    `json:"host_arch"`

	PolicyName string `json:"policy_name,omitempty"`
	PolicyKey  string `json:"policy_key,omitempty"`

	MappingSource string `json:"mapping_source,omitempty"`
	AuditLogPath  string `json:"audit_log_path,omitempty"`
}

type PolicyRef struct {
	Tenant           string `json:"tenant"`
	PolicyKey        string `json:"policy_key"`
	PolicyObjectName string `json:"policy_object_name"`
}

type ControlRef struct {
	Framework FrameworkID `json:"framework"`
	ControlID string      `json:"control_id"`
	Version   string      `json:"version,omitempty"`
}

type MappingEntry struct {
	Policy    PolicyRef                `json:"policy"`
	Controls  map[FrameworkID][]string `json:"controls"`
	Rationale string                   `json:"rationale,omitempty"`
	Owner     string                   `json:"owner,omitempty"`
}

type AuditEvidence struct {
	IntegrityStatus EvidenceStatus `json:"integrity_status"`
	IntegrityError  string         `json:"integrity_error,omitempty"`

	EntryCount int64  `json:"entry_count,omitempty"`
	LastHash   string `json:"last_hash,omitempty"`
}

type PolicyEvidence struct {
	Policy        PolicyRef      `json:"policy"`
	Enforced      EvidenceStatus `json:"enforced"`
	EnforcedCount int            `json:"enforced_count,omitempty"`
}

type ControlEvidence struct {
	Framework FrameworkID    `json:"framework"`
	ControlID string         `json:"control_id"`
	Status    EvidenceStatus `json:"status"`
}

type ControlMapping struct {
	Framework FrameworkID     `json:"framework"`
	ControlID string          `json:"control_id"`
	Policies  []PolicyRef     `json:"policies"`
	Evidence  ControlEvidence `json:"evidence"`
}

type PolicyMapping struct {
	Policy    PolicyRef      `json:"policy"`
	Controls  []ControlRef   `json:"controls"`
	Evidence  PolicyEvidence `json:"evidence"`
	Rationale string         `json:"rationale,omitempty"`
	Owner     string         `json:"owner,omitempty"`
}

type Report struct {
	Metadata ReportMetadata   `json:"metadata"`
	Audit    AuditEvidence    `json:"audit"`
	Controls []ControlMapping `json:"controls"`
	Policies []PolicyMapping  `json:"policies"`
	Warnings []string         `json:"warnings,omitempty"`
}
