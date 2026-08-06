# Compliance Report

Generated: 2026-01-02T03:04:05Z
Host: darwin/arm64
Policy Key: default/p1
Mapping Source: annotations
Audit Log: /tmp/audit.log

## Audit Evidence

- Integrity: present
- Entry Count: 2
- Last Hash: abc

## Control Coverage

### pci-dss

#### 10.2.1

- Evidence: present
- Policies:
  - default/p1 (object: p1)

### soc2

#### CC7.2

- Evidence: missing
- Policies:
  - default/p2 (object: p2)

## Policy Index

### default/p1 (object: p1)

- Enforcement Evidence: present (events: 1)
- Controls:
  - pci-dss 10.2.1

### default/p2 (object: p2)

- Enforcement Evidence: missing (events: 0)
- Controls:
  - soc2 CC7.2


## Warnings

- w1
