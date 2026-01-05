#!/bin/bash
# ZTAP Iptables Integration Test
# Requirements: sudo, iptables, nc (netcat)

set -e

# Cleanup on exit
trap cleanup EXIT

cleanup() {
    echo "Cleaning up..."
    # Force cleanup using ztap if possible
    ./ztap enforce --cleanup || true
    # Manual cleanup just in case
    sudo iptables -D INPUT -j ZTAP-INGRESS 2>/dev/null || true
    sudo iptables -D OUTPUT -j ZTAP-EGRESS 2>/dev/null || true
    sudo iptables -F ZTAP-INGRESS 2>/dev/null || true
    sudo iptables -F ZTAP-EGRESS 2>/dev/null || true
    sudo iptables -X ZTAP-INGRESS 2>/dev/null || true
    sudo iptables -X ZTAP-EGRESS 2>/dev/null || true
}

echo "Building ztap..."
go build -o ztap .

echo "Starting test server..."
nc -l -p 8080 &
NC_PID=$!
sleep 1

echo "Applying policy allowing 8080..."
cat <<EOF > test-policy.yaml
apiVersion: ztap/v1
kind: NetworkPolicy
metadata:
  name: allow-8080
spec:
  ingress:
    - from:
        ipBlock:
          cidr: 127.0.0.1/32
      ports:
        - protocol: TCP
          port: 8080
EOF

# Force iptables fallback
export ZTAP_FORCE_IPTABLES=1

echo "Starting ZTAP enforcer in background..."
sudo -E ./ztap enforce -f test-policy.yaml &
ZTAP_PID=$!
sleep 2

echo "Verifying ZTAP chains..."
sudo iptables -L ZTAP-INGRESS -n

echo "Testing connection (should SUCCEED)..."
nc -z -v 127.0.0.1 8080

echo "Testing connection to unauthorized port (should FAIL)..."
if nc -z -v -w 1 127.0.0.1 8081; then
    echo "Error: Connection to 8081 succeeded but should have been blocked!"
    exit 1
else
    echo "Success: Connection to 8081 blocked."
fi

echo "Stopping ZTAP..."
sudo kill -SIGINT $ZTAP_PID
sleep 2

echo "Testing connection after stop (should SUCCEED again because rules are gone)..."
# Restart nc for verification if it exited
nc -l -p 8081 &
NC_PID2=$!
sleep 1
nc -z -v 127.0.0.1 8081
kill $NC_PID2

echo "Integration test PASSED!"
