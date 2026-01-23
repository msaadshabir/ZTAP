# Windows Flow Monitoring (WFP) - Manual Validation Runbook

This runbook validates Windows flow monitoring end-to-end using the ZTAP CLI.

Scope:
- Uses the Windows flow reader (`WFP NetEvents`, default `mode=ztap-only`).
- Confirms ZTAP-owned WFP filters generate `allowed`/`blocked` flow events.

## Prerequisites

- Windows host.
- Run commands in an **elevated** PowerShell (Administrator).
- The **Base Filtering Engine** (BFE) service is running.
  - Check: `sc query bfe`
- Go toolchain available (for building / integration tests).

Optional for more logs:
- `setx ZTAP_LOG_LEVEL debug` (new shell required) or pass `--log-level debug`.

## Build ZTAP

From the repo root:

```powershell
go build -o ztap.exe .
```

## Validate Allowed Egress (ZTAP-only)

This path uses `ztap enforce` to install a ZTAP-owned **permit** filter and then confirms `ztap flows` emits an `allowed` event.

### 1) Pick a non-loopback IPv4 and port

Pick a non-loopback IPv4 assigned to the host (do not use `127.0.0.1`). Example helper:

```powershell
$ip = (Get-NetIPAddress -AddressFamily IPv4 |
  Where-Object { $_.IPAddress -ne '127.0.0.1' -and $_.IPAddress -notlike '169.254*' } |
  Select-Object -First 1 -ExpandProperty IPAddress)
$port = 31337
"IP=$ip PORT=$port"
```

### 2) Start a local TCP listener

In one PowerShell window:

```powershell
powershell -NoProfile -Command "
  $ip='$ip'; $port=$port;
  $listener=[System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Parse($ip),$port);
  $listener.Start();
  Write-Host ('Listening on ' + $ip + ':' + $port);
  $client=$listener.AcceptTcpClient();
  $client.Close();
  $listener.Stop();
"
```

### 3) Create a Windows-compatible policy

Create a policy YAML that matches Windows WFP translation constraints:
- `ipBlock.cidr` must be a **/32** today
- `protocol` must be `TCP`/`UDP`/`ICMP`

Example (`policy-windows-local-egress.yaml`):

```yaml
apiVersion: ztap/v1
kind: NetworkPolicy
metadata:
  name: windows-local-egress-allow
spec:
  podSelector:
    matchLabels:
      app: local
  egress:
    - to:
        ipBlock:
          cidr: "REPLACE_WITH_HOST_IPV4/32"
      ports:
        - protocol: TCP
          port: 31337
```

Replace `REPLACE_WITH_HOST_IPV4` with the `$ip` you selected.

### 4) Apply enforcement (installs WFP filters)

In PowerShell window A (Admin):

```powershell
./ztap.exe enforce -f .\policy-windows-local-egress.yaml
```

Leave it running (Ctrl+C later to remove filters).

### 5) Stream flows

In PowerShell window B (Admin):

```powershell
./ztap.exe flows --follow --output json
```

### 6) Generate matching traffic

In PowerShell window C:

```powershell
Test-NetConnection -ComputerName $ip -Port $port
```

Expected result:
- `ztap flows` prints an `allowed` `egress` `TCP` flow where destination is `$ip:$port`.

### 7) Cleanup

- Stop `ztap enforce` with Ctrl+C (it removes ZTAP-managed WFP filters).
- Stop `ztap flows` with Ctrl+C.

## Validate Blocked Egress (Recommended via integration tests)

The current `TranslatePolicyToWFP` path primarily installs **permit** filters; to validate blocked events reliably, run the WFP integration tests which install a ZTAP-owned **block** filter.

From an elevated PowerShell in repo root:

```powershell
go test ./pkg/flow -tags=integration -run TestWFPFlowIntegration -v
```

Expected result:
- `TestWFPFlowIntegration_AllowedEgress` passes.
- `TestWFPFlowIntegration_BlockedEgress` passes.

## Troubleshooting

- `access denied` / no events:
  - Ensure PowerShell is **Run as Administrator**.
  - Ensure BFE is running: `sc query bfe`.
- Only drops, no allows:
  - ZTAP will warn if drops are seen but allows are not observed.
  - Some environments require additional WFP auditing/logging to surface allow events.
- No events in `ztap-only` mode:
  - Ensure `ztap enforce` is active so ZTAP-owned WFP filters exist.
  - If you only want system-wide drops, ztap-only will intentionally filter them out.
