#!/usr/bin/env bash
# Final lifecycle gate; run only after all traffic/resource checks in kind.
set -euo pipefail
kind_node="${ZTAP_KIND_NODE:-ztap-control-plane}"
test "$(docker inspect "$kind_node" | jq -r '.[0].Config.Labels["io.x-k8s.kind.role"]')" = control-plane
CGO_ENABLED=0 GOOS=linux GOARCH="${ZTAP_TEST_ARCH:-amd64}" go build -o "$RUNNER_TEMP/ztap-cleanup" ./cmd/ztap
docker cp "$RUNNER_TEMP/ztap-cleanup" "$kind_node:/usr/local/bin/ztap-cleanup"
if output="$(docker exec "$kind_node" /usr/local/bin/ztap-cleanup cleanup --bpffs-root=/sys/fs/bpf --run-dir=/run/ztap 2>&1)"; then
  printf 'cleanup removed enforcement while the node agent held its lock\n' >&2
  exit 1
fi
grep -q 'already holds' <<< "$output"
server_ip="$(kubectl -n ztap-smoke get pod smoke-server -o jsonpath='{.status.podIP}')"
client_ip="$(kubectl -n ztap-smoke get pod smoke-client -o jsonpath='{.status.podIP}')"
service_ip="$(kubectl -n ztap-smoke get service smoke-server -o jsonpath='{.spec.clusterIP}')"
kubectl -n ztap-system delete daemonset ztap-agent ztap-node-init --wait=true
kubectl -n ztap-system wait --for=delete pod -l app=ztap-agent --timeout=90s
kubectl -n ztap-system wait --for=delete pod -l app=ztap-node-init --timeout=90s
# No userspace owner remains, yet the committed policy still protects both
# directions and its allowed control continues to receive replies.
if kubectl -n ztap-smoke exec smoke-client -- wget -qO- -T 1 "http://$server_ip:8080/"; then exit 1; fi
if kubectl -n ztap-smoke exec smoke-control -- wget -qO- -T 1 "http://$client_ip:8091/"; then exit 1; fi
kubectl -n ztap-smoke exec smoke-client -- wget -qO- -T 3 "http://$service_ip:8080/" | grep -qx ok
docker exec "$kind_node" /usr/local/bin/ztap-cleanup cleanup --bpffs-root=/sys/fs/bpf --run-dir=/run/ztap
# Retrying completed cleanup is harmless.
docker exec "$kind_node" /usr/local/bin/ztap-cleanup cleanup --bpffs-root=/sys/fs/bpf --run-dir=/run/ztap
kubectl -n ztap-smoke exec smoke-client -- wget -qO- -T 3 "http://$server_ip:8080/" | grep -qx ok
kubectl -n ztap-smoke exec smoke-control -- wget -qO- -T 3 "http://$client_ip:8091/" | grep -qx ok
jq -n --arg kernel "$(docker exec "$kind_node" uname -r)" --arg runtime "$(docker exec "$kind_node" containerd --version)" \
  '{schema_version:2,kernel:$kernel,containerd:$runtime,competing_agent_refused:true,daemonset_deletion_preserved_both_directions:true,explicit_cleanup_removed_enforcement:true,cleanup_retry_passed:true}' > explicit-uninstall-evidence.json
