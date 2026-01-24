# Compliance Reporting

ZTAP can generate compliance mapping exports and reports for:

- PCI-DSS (`pci-dss`)
- SOC2 (`soc2`)
- HIPAA (`hipaa`)

The output is intended to support audits by showing:

- which policies map to which controls
- whether there is enforcement evidence in the audit log

## Policy Annotations (Recommended)

Add one or more compliance annotations under `metadata.annotations`:

```yaml
metadata:
  name: payment-egress
  annotations:
    ztap.io/compliance.pci-dss: "10.2.1,10.2.2"
    ztap.io/compliance.soc2: "CC7.2"
    ztap.io/compliance.hipaa: "164.312(b)"
```

Notes:

- Values are comma-separated control IDs.
- Use `--strict` to fail on unknown frameworks or invalid control IDs.

## Mapping File (Optional)

If you prefer to keep mapping data out of policy YAML, you can supply a mapping file:

```yaml
apiVersion: ztap.io/v1alpha1
kind: ComplianceMapping
spec:
  mappings:
    - policyObjectName: payment-egress
      policyKey: prod/payment-stack
      controls:
        pci-dss: ["10.2.1", "10.2.2"]
        soc2: ["CC7.2"]
        hipaa: ["164.312(b)"]
      rationale: "Egress restricted to approved destinations"
      owner: "security@example.com"
```

Mapping file entries override annotation mappings for the same `policyObjectName`.

## CLI

```bash
# JSON export (canonical)
ztap compliance export -f policy.yaml --format json

# CSV export
ztap compliance export -f policy.yaml --format csv --out compliance.csv

# Markdown report
ztap compliance report -f policy.yaml --format md
```

## REST API

Endpoints:

- `POST /v1/compliance/report` (requires `view_compliance`)
- `POST /v1/compliance/export` (requires `view_compliance`)

Example request body (report):

```json
{
  "policy_yaml": "...",
  "policy_name": "default/payment-egress",
  "frameworks": ["pci-dss", "soc2"],
  "mapping_yaml": "...",
  "evidence_window": "90d",
  "strict": false
}
```

`/v1/compliance/export` accepts `format: "json"|"csv"`.

## Evidence Rules (v1)

- Audit integrity must verify (hash chain) for enforcement evidence to be trusted.
- Enforcement evidence is derived from `policy.enforced` audit events whose `resource` matches the policy key.
