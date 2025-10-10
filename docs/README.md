# ZTAP: Zero Trust Access Platform

An open-source platform implementing zero-trust microsegmentation across hybrid environments (on-prem + cloud) using policy-as-code and OS-native enforcement.

## Features

- Unified policy language (YAML, Kubernetes-style)
- eBPF enforcement on Linux (cloud-native)
- pf (packet filter) fallback on macOS (local dev)
- Hybrid-ready: Extendable to AWS/Azure
- Standards-compliant: Implements NIST SP 800-207

## Quick Start (macOS)

```bash
go run . enforce -f examples/web-to-db.yaml
```
