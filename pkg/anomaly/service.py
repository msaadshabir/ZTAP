#!/usr/bin/env python3
"""
ZTAP Anomaly Detection Microservice
Uses Isolation Forest for detecting anomalous network flows
"""

from flask import Flask, request, jsonify
from sklearn.ensemble import IsolationForest
import numpy as np
import json
from datetime import datetime

app = Flask(__name__)

# Global model (in production, use persistent storage)
model = None
training_data = []

def extract_features(flow):
    """Extract numeric features from flow record"""
    # Convert IP addresses to numeric (simple hash for demo)
    source_hash = hash(flow.get('source_ip', '0.0.0.0')) % 10000
    dest_hash = hash(flow.get('dest_ip', '0.0.0.0')) % 10000
    
    # Protocol to numeric
    protocol_map = {'TCP': 1, 'UDP': 2, 'ICMP': 3}
    protocol_num = protocol_map.get(flow.get('protocol', 'TCP'), 0)
    
    # Features: [source_hash, dest_hash, port, protocol, bytes, hour_of_day]
    timestamp = flow.get('timestamp', datetime.now().isoformat())
    hour = datetime.fromisoformat(timestamp).hour if timestamp else 0
    
    return [
        source_hash,
        dest_hash,
        flow.get('port', 0),
        protocol_num,
        flow.get('bytes', 0),
        hour
    ]

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'model_trained': model is not None})

@app.route('/train', methods=['POST'])
def train():
    """Train the Isolation Forest model on normal traffic"""
    global model, training_data
    
    flows = request.json
    if not flows or not isinstance(flows, list):
        return jsonify({'error': 'Expected list of flows'}), 400
    
    # Extract features
    features = [extract_features(flow) for flow in flows]
    X = np.array(features)
    
    # Train model
    model = IsolationForest(
        contamination=0.1,  # Expect 10% anomalies
        random_state=42,
        n_estimators=100
    )
    model.fit(X)
    
    training_data = flows
    
    return jsonify({
        'status': 'trained',
        'samples': len(flows),
        'features': X.shape[1]
    })

@app.route('/detect', methods=['POST'])
def detect():
    """Detect if a flow is anomalous"""
    global model
    
    if model is None:
        # Use simple heuristic if not trained
        return simple_detect(request.json)
    
    flow = request.json
    if not flow:
        return jsonify({'error': 'Expected flow object'}), 400
    
    # Extract features
    features = extract_features(flow)
    X = np.array([features])
    
    # Predict (-1 = anomaly, 1 = normal)
    prediction = model.predict(X)[0]
    anomaly_score = model.decision_function(X)[0]
    
    # Convert to 0-100 scale (lower anomaly_score = more anomalous)
    # Typical range is [-0.5, 0.5], normalize to [0, 100]
    score = max(0, min(100, (1 - anomaly_score) * 100))
    
    is_anomaly = prediction == -1
    reason = "ML-based detection: "
    if is_anomaly:
        reason += "flow deviates from normal patterns"
    else:
        reason += "flow matches normal patterns"
    
    return jsonify({
        'score': float(score),
        'is_anomaly': bool(is_anomaly),
        'reason': reason
    })

def simple_detect(flow):
    """Simple rule-based detection (fallback when model not trained)"""
    score = 0.0
    reasons = []
    
    # Check suspicious ports
    suspicious_ports = [22, 23, 3389, 1433, 3306, 5432]
    if flow.get('port') in suspicious_ports:
        score += 30
        reasons.append(f"suspicious port {flow.get('port')}")
    
    # Check high data volume
    if flow.get('bytes', 0) > 100 * 1024 * 1024:
        score += 20
        reasons.append("high data transfer volume")
    
    # Check unusual hour (outside business hours)
    timestamp = flow.get('timestamp', datetime.now().isoformat())
    hour = datetime.fromisoformat(timestamp).hour if timestamp else 12
    if hour < 6 or hour > 20:
        score += 10
        reasons.append("traffic outside business hours")
    
    reason = "rule-based detection: " + (", ".join(reasons) if reasons else "normal traffic")
    
    return jsonify({
        'score': float(score),
        'is_anomaly': score > 50,
        'reason': reason
    })

if __name__ == '__main__':
    print("Starting ZTAP Anomaly Detection Service")
    print("Endpoints:")
    print("  POST /train   - Train model on normal traffic")
    print("  POST /detect  - Detect anomalous flows")
    print("  GET  /health  - Health check")
    app.run(host='0.0.0.0', port=5000, debug=True)
