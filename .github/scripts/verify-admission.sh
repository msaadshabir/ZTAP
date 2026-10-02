#!/usr/bin/env bash
# Run against the disposable kind cluster after installing the full manifest.
set -euo pipefail

deny_create() {
  local output
  if output="$(kubectl -n ztap-system run ztap-guard-check --image=busybox:1.36.1 \
    --restart=Never --dry-run=server --overrides="$1" 2>&1)"; then
    printf 'unsafe Pod was admitted: %s\n' "$1" >&2
    exit 1
  fi
  if [[ "$output" != *"ZTAP requires"* ]]; then
    printf 'Pod failed for a reason other than the ZTAP guard: %s\n' "$output" >&2
    exit 1
  fi
}

deny_create '{}'
deny_create '{"spec":{"containers":[{"name":"ztap-guard-check","image":"busybox:1.36.1","securityContext":{"allowPrivilegeEscalation":false,"capabilities":{"drop":["NET_RAW"],"add":["NET_RAW"]}}}]}}'
deny_create '{"spec":{"containers":[{"name":"ztap-guard-check","image":"busybox:1.36.1","securityContext":{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]}}}],"initContainers":[{"name":"unsafe-init","image":"busybox:1.36.1"}]}}'

safe='{"spec":{"containers":[{"name":"ztap-guard-check","image":"busybox:1.36.1","command":["sleep","3600"],"securityContext":{"allowPrivilegeEscalation":false,"capabilities":{"drop":["NET_RAW"]}}}]}}'
kubectl -n ztap-system run ztap-guard-check --image=busybox:1.36.1 --restart=Never --overrides="$safe"
admission_tmp="$(mktemp -d)"
trap 'kubectl -n ztap-system delete pod ztap-guard-check --ignore-not-found --wait=false; rm -rf "$admission_tmp"' EXIT
kubectl -n ztap-system wait --for=condition=Ready pod/ztap-guard-check --timeout=90s
process_status="$(kubectl -n ztap-system exec ztap-guard-check -- cat /proc/self/status)"
for cap_field in CapEff CapPrm CapBnd; do
  caps_value="$(awk -v key="$cap_field:" '$1 == key { print $2 }' <<< "$process_status")"
  test -n "$caps_value"
  if (( (16#$caps_value & 0x2000) != 0 )); then
    printf '%s still includes CAP_NET_RAW: %s\n' "$cap_field" "$caps_value" >&2
    exit 1
  fi
done
test "$(awk '$1 == "NoNewPrivs:" { print $2 }' <<< "$process_status")" = 1
kubectl -n ztap-system get pod ztap-guard-check -o json | jq '
  .spec.ephemeralContainers = [{name:"debug", image:"busybox:1.36.1",
    securityContext:{allowPrivilegeEscalation:false, capabilities:{drop:["NET_RAW"], add:["NET_RAW"]}}}]
' > "$admission_tmp/debug.json"
if output="$(kubectl replace --raw /api/v1/namespaces/ztap-system/pods/ztap-guard-check/ephemeralcontainers \
  -f "$admission_tmp/debug.json" 2>&1)"; then
  printf 'unsafe ephemeral container was admitted\n' >&2
  exit 1
fi
if [[ "$output" != *"ZTAP requires"* ]]; then
  printf 'debug update failed for a reason other than the ZTAP guard: %s\n' "$output" >&2
  exit 1
fi
jq 'del(.spec.ephemeralContainers[0].securityContext.capabilities.add)' \
  "$admission_tmp/debug.json" > "$admission_tmp/safe-debug.json"
kubectl replace --raw /api/v1/namespaces/ztap-system/pods/ztap-guard-check/ephemeralcontainers \
  -f "$admission_tmp/safe-debug.json" >/dev/null
printf '%s\n' 'admission guard rejected unsafe regular, init, and ephemeral containers and accepted safe workloads'
