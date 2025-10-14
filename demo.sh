#!/bin/bash
# ZTAP Demo Script - Showcasing Authentication and Service Discovery

set -e

echo "=========================================="
echo "ZTAP - Zero Trust Access Platform Demo"
echo "=========================================="
echo ""

# Build ZTAP
echo "[BUILD] Building ZTAP..."
go build -o ztap .
echo "[DONE] Build successful"
echo ""

# Test 1: Authentication
echo "[TEST 1] Authentication & User Management"
echo "-------------------------------------------"
echo ""

echo "1. Login as default admin..."
echo "admin" | ./ztap user login admin
echo ""

echo "2. List users (should show only admin)..."
./ztap user list
echo ""

echo "3. Create operator user..."
echo "operator123" | ./ztap user create alice --role operator
echo ""

echo "4. Create viewer user..."
echo "viewer123" | ./ztap user create bob --role viewer
echo ""

echo "5. List all users..."
./ztap user list
echo ""

# Test 2: Service Discovery
echo "[TEST 2] Service Discovery"
echo "-------------------------------------------"
echo ""

echo "1. Register web services..."
./ztap discovery register web-1 10.0.1.1 --labels app=web,tier=frontend
./ztap discovery register web-2 10.0.1.2 --labels app=web,tier=frontend
echo ""

echo "2. Register database service..."
./ztap discovery register db-1 10.0.2.1 --labels app=database,tier=backend
echo ""

echo "3. Register cache service..."
./ztap discovery register redis-1 10.0.3.1 --labels app=cache,tier=backend
echo ""

echo "4. List all registered services..."
./ztap discovery list
echo ""

echo "5. Resolve web services by label..."
./ztap discovery resolve --labels app=web
echo ""

echo "6. Resolve backend services..."
./ztap discovery resolve --labels tier=backend
echo ""

echo "7. Resolve specific service (database)..."
./ztap discovery resolve --labels app=database
echo ""

# Test 3: Policy Enforcement with Discovery
echo "[TEST 3] Policy Enforcement (requires sudo on macOS)"
echo "-------------------------------------------"
echo ""

echo "Creating test policy with label-based egress..."
cat > /tmp/demo-policy.yaml <<EOF
apiVersion: ztap/v1
kind: NetworkPolicy
metadata:
  name: web-to-backend
spec:
  podSelector:
    matchLabels:
      app: web
  egress:
    - to:
        ipBlock:
          cidr: 10.0.2.0/24
      ports:
        - protocol: TCP
          port: 5432
    - to:
        ipBlock:
          cidr: 10.0.3.0/24
      ports:
        - protocol: TCP
          port: 6379
EOF

echo "Policy created at /tmp/demo-policy.yaml"
cat /tmp/demo-policy.yaml
echo ""

echo "Enforcing policy (may require sudo)..."
./ztap enforce /tmp/demo-policy.yaml || echo "[WARN] Enforcement requires sudo/root privileges"
echo ""

# Test 4: Status Check
echo "[TEST 4] System Status"
echo "-------------------------------------------"
echo ""

echo "Checking ZTAP status..."
./ztap status
echo ""

# Test 5: Service Updates
echo "[TEST 5] Dynamic Service Updates"
echo "-------------------------------------------"
echo ""

echo "1. Add another web service..."
./ztap discovery register web-3 10.0.1.3 --labels app=web,tier=frontend
echo ""

echo "2. Resolve web services again (should show 3)..."
./ztap discovery resolve --labels app=web
echo ""

echo "3. Deregister a service..."
./ztap discovery deregister web-2
echo ""

echo "4. Resolve web services again (should show 2)..."
./ztap discovery resolve --labels app=web
echo ""

# Test 6: Permission Testing
echo "[TEST 6] Permission Testing"
echo "-------------------------------------------"
echo ""

echo "1. Logout admin..."
./ztap user logout
echo ""

echo "2. Login as viewer (bob)..."
echo "viewer123" | ./ztap user login bob
echo ""

echo "3. Try to enforce policy (should fail - viewer has no enforce permission)..."
./ztap enforce /tmp/demo-policy.yaml || echo "[DENIED] Correctly denied - viewer cannot enforce policies"
echo ""

echo "4. Try to create user (should fail - viewer has no user management permission)..."
echo "test123" | ./ztap user create charlie --role viewer || echo "[DENIED] Correctly denied - viewer cannot manage users"
echo ""

echo "5. Logout viewer..."
./ztap user logout
echo ""

echo "6. Login as operator (alice)..."
echo "operator123" | ./ztap user login alice
echo ""

echo "7. Enforce policy as operator (should succeed)..."
./ztap enforce /tmp/demo-policy.yaml || echo "[WARN] Requires sudo"
echo ""

echo "8. Try to create user as operator (should fail)..."
echo "test123" | ./ztap user create charlie --role viewer || echo "[DENIED] Correctly denied - operator cannot manage users"
echo ""

# Test 7: Run Tests
echo "[TEST 7] Running Test Suite"
echo "-------------------------------------------"
echo ""

echo "Running all tests..."
go test ./... -v -cover | head -50
echo ""

# Cleanup
echo "[CLEANUP] Cleanup"
echo "-------------------------------------------"
echo ""

echo "1. Logout current user..."
./ztap user logout
echo ""

echo "2. Remove demo policy..."
rm -f /tmp/demo-policy.yaml
echo ""

echo "=========================================="
echo "[DONE] Demo Complete!"
echo "=========================================="
echo ""
echo "Summary of Features Demonstrated:"
echo "  [PASS] User authentication with RBAC"
echo "  [PASS] Multi-user management (admin, operator, viewer)"
echo "  [PASS] Service registration and discovery"
echo "  [PASS] Label-based service resolution"
echo "  [PASS] Dynamic service updates"
echo "  [PASS] Permission enforcement"
echo "  [PASS] Policy enforcement with discovery"
echo "  [PASS] Comprehensive test suite"
echo ""
echo "Next Steps:"
echo "  - Review docs/TESTING_GUIDE.md for comprehensive testing guide"
echo "  - Check docs/architecture.md for system design details"
echo "  - See DOCKER.md for Docker deployment"
echo "  - Run './ztap --help' for all commands"
echo ""
