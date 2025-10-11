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
    
    # Protocol to numeric (default to 0 for unknown)
    protocol_map = {'TCP': 1, 'UDP': 2, 'ICMP': 3}
    protocol_num = protocol_map.get(flow.get('protocol', ''), 0)
    
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
    
    data = request.json
    if not data:
        return jsonify({'error': 'Expected JSON data'}), 400
    
    # Handle both formats: direct list or {'flows': [...]}
    flows = data.get('flows', data) if isinstance(data, dict) else data
    
    if not flows or not isinstance(flows, list):
        return jsonify({'error': 'Expected list of flows'}), 400
    
    # Require minimum samples for training
    if len(flows) < 2:
        return jsonify({'error': 'Insufficient training data (minimum 2 samples required)'}), 400
    
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

@app.route('/predict', methods=['POST'])
def predict():
    """Predict if a single flow is anomalous (requires trained model)"""
    global model
    
    if model is None:
        return jsonify({'error': 'Model not trained. Call /train first.'}), 400
    
    flow = request.json
    if not flow:
        return jsonify({'error': 'Expected flow object'}), 400
    
    # Extract features
    features = extract_features(flow)
    X = np.array([features])
    
    # Predict (-1 = anomaly, 1 = normal)
    prediction = model.predict(X)[0]
    anomaly_score = model.decision_function(X)[0]
    
    # Convert to 0-100 scale
    score = max(0, min(100, (1 - anomaly_score) * 100))
    
    is_anomaly = prediction == -1
    
    return jsonify({
        'is_anomaly': bool(is_anomaly),
        'anomaly': bool(is_anomaly),
        'score': float(score),
        'confidence': float(abs(anomaly_score))
    })

@app.route('/batch_predict', methods=['POST'])
def batch_predict():
    """Predict anomalies for multiple flows at once"""
    global model
    
    if model is None:
        return jsonify({'error': 'Model not trained. Call /train first.'}), 400
    
    data = request.json
    if not data:
        return jsonify({'error': 'Expected JSON data'}), 400
    
    # Handle both formats: direct list or {'flows': [...]}
    flows = data.get('flows', data) if isinstance(data, dict) else data
    
    if not flows or not isinstance(flows, list):
        return jsonify({'error': 'Expected list of flows'}), 400
    
    # Extract features for all flows
    features = [extract_features(flow) for flow in flows]
    X = np.array(features)
    
    # Predict for all flows
    predictions = model.predict(X)
    scores = model.decision_function(X)
    
    # Format results
    results = []
    for i, (pred, score) in enumerate(zip(predictions, scores)):
        is_anomaly = pred == -1
        normalized_score = max(0, min(100, (1 - score) * 100))
        
        results.append({
            'index': i,
            'is_anomaly': bool(is_anomaly),
            'anomaly': bool(is_anomaly),
            'score': float(normalized_score),
            'confidence': float(abs(score))
        })
    
    return jsonify({
        'predictions': results,
        'total': len(results),
        'anomalies': sum(1 for r in results if r['is_anomaly'])
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
    print("  POST /train         - Train model on normal traffic")
    print("  POST /predict       - Predict single flow (requires trained model)")
    print("  POST /batch_predict - Predict multiple flows (requires trained model)")
    print("  POST /detect        - Detect anomalous flows (with fallback)")
    print("  GET  /health        - Health check")
    app.run(host='0.0.0.0', port=5000, debug=False)
    app.run(host='0.0.0.0', port=5000, debug=True)
