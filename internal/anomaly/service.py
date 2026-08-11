#!/usr/bin/env python3
"""
ZTAP Anomaly Detection Microservice
Uses Isolation Forest for detecting anomalous network flows

Configuration (environment variables):
  ZTAP_ANOMALY_TOKEN   shared secret; when set, all data endpoints require
                       "Authorization: Bearer <token>"
  ZTAP_ANOMALY_HOST    bind address for `python service.py` dev runs
                       (default 127.0.0.1; the container image binds 0.0.0.0)
  ZTAP_ANOMALY_PORT    bind port (default 5000)
  MODEL_PATH           directory for the persisted joblib model (default
                       ./models); the model is loaded on start and saved
                       after every /train
"""

import functools
import hmac
import ipaddress
import os
import tempfile
from datetime import datetime
from pathlib import Path

import joblib
import numpy as np
from flask import Flask, jsonify, request
from sklearn.ensemble import IsolationForest

app = Flask(__name__)

# Loaded on start (if a previously trained model exists) and saved after
# /train, so training survives service restarts.
MODEL_PATH = Path(os.environ.get("MODEL_PATH", "models")) / "model.joblib"
TOKEN = os.environ.get("ZTAP_ANOMALY_TOKEN", "")

# The model is process-local and persisted to MODEL_PATH. The container runs
# one worker so training and detection observe the same in-memory model.
model = None
training_data = []


def require_token(fn):
    """Reject requests that do not present the configured bearer token.

    When ZTAP_ANOMALY_TOKEN is unset the decorator is a no-op so host-local
    dev runs work without configuration.
    """

    @functools.wraps(fn)
    def wrapped(*args, **kwargs):
        if TOKEN:
            auth = request.headers.get("Authorization", "")
            provided = auth[len("Bearer "):] if auth.startswith("Bearer ") else ""
            if not hmac.compare_digest(provided, TOKEN):
                return jsonify({"error": "unauthorized"}), 401
        return fn(*args, **kwargs)

    return wrapped


def load_model():
    """Load a previously persisted model, if any."""
    global model
    if MODEL_PATH.exists():
        try:
            model = joblib.load(MODEL_PATH)
            app.logger.info("loaded model from %s", MODEL_PATH)
        except Exception:
            app.logger.warning("failed to load model from %s; starting untrained", MODEL_PATH)
            model = None


def save_model():
    """Persist the current model so training survives restarts.

    Write to a file in the model directory and replace the previous model
    atomically. A worker that starts while a model is being saved must never
    observe a partially written joblib file.
    """
    global model
    temp_path = None
    try:
        MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            dir=MODEL_PATH.parent,
            prefix=f".{MODEL_PATH.name}.",
            suffix=".tmp",
            delete=False,
        ) as temp_file:
            temp_path = Path(temp_file.name)
        joblib.dump(model, temp_path)
        os.replace(temp_path, MODEL_PATH)
        app.logger.info("saved model to %s", MODEL_PATH)
    except (OSError, ValueError):
        app.logger.warning("failed to save model to %s", MODEL_PATH)
    finally:
        if temp_path is not None:
            try:
                temp_path.unlink(missing_ok=True)
            except OSError:
                pass


def _ip_feature(ip_str):
    """Deterministic numeric feature for an IP address.

    Python's built-in hash() is randomized per process (PYTHONHASHSEED), which
    made features non-reproducible across restarts. Converting the address to
    its integer form is stable and unique.
    """
    try:
        return int(ipaddress.ip_address(ip_str)) % 10000
    except ValueError:
        return 0


def _hour_of(timestamp):
    """Extract the hour of day from an ISO-8601 timestamp, 12 when missing."""
    if not timestamp:
        return 12
    try:
        return datetime.fromisoformat(timestamp).hour
    except ValueError:
        return 12


def extract_features(flow):
    """Extract numeric features from flow record"""
    source_ip = _ip_feature(flow.get('source_ip', '0.0.0.0'))
    dest_ip = _ip_feature(flow.get('dest_ip', '0.0.0.0'))

    # Protocol to numeric (default to 0 for unknown)
    protocol_map = {'TCP': 1, 'UDP': 2, 'ICMP': 3}
    protocol_num = protocol_map.get(flow.get('protocol', ''), 0)

    # Features: [source_ip, dest_ip, port, protocol, bytes, hour_of_day]
    return [
        source_ip,
        dest_ip,
        flow.get('port', 0),
        protocol_num,
        flow.get('bytes', 0),
        _hour_of(flow.get('timestamp', datetime.now().isoformat()))
    ]


def simple_score(flow):
    """Rule-based score used when no model is trained (fallback)."""
    score = 0.0
    reasons = []

    # Check suspicious ports
    suspicious_ports = (22, 23, 3389, 1433, 3306, 5432)
    port = flow.get('port')
    if port in suspicious_ports:
        score += 30
        reasons.append(f"suspicious port {port}")

    # Check high data volume
    if flow.get('bytes', 0) > 100 * 1024 * 1024:
        score += 20
        reasons.append("high data transfer volume")

    # Check unusual hour (outside business hours)
    hour = _hour_of(flow.get('timestamp', datetime.now().isoformat()))
    if hour < 6 or hour > 20:
        score += 10
        reasons.append("traffic outside business hours")

    reason = "rule-based detection: " + (", ".join(reasons) if reasons else "normal traffic")

    return {
        'score': float(score),
        'is_anomaly': score > 50,
        'reason': reason
    }


def _normalize_ml_score(anomaly_score):
    """Map Isolation Forest's decision function to the shared 0-100 scale.

    Isolation Forest returns positive values for normal samples and negative
    values for anomalies. Mapping zero to 50 makes the Go threshold contract
    agree with the model's decision boundary: normal traffic is at or below
    50 and anomalous traffic is above 50.
    """
    return float(np.clip(50.0 - float(anomaly_score) * 100.0, 0.0, 100.0))


def _ml_score(flow, model):
    """Isolation-Forest score for a single flow (assumes a trained model)."""
    features = extract_features(flow)
    X = np.array([features])

    # Predict (-1 = anomaly, 1 = normal)
    prediction = model.predict(X)[0]
    anomaly_score = model.decision_function(X)[0]
    score = _normalize_ml_score(anomaly_score)
    is_anomaly = prediction == -1
    reason = "ML-based detection: "
    reason += "flow deviates from normal patterns" if is_anomaly else "flow matches normal patterns"

    return {
        'score': float(score),
        'is_anomaly': bool(is_anomaly),
        'reason': reason
    }


def _flows_from_request(data):
    """Extract a non-empty list of flow objects, or None when invalid.

    Handles both formats: direct list or {'flows': [...]}.
    """
    if not data:
        return None
    flows = data.get('flows', data) if isinstance(data, dict) else data
    if not flows or not isinstance(flows, list):
        return None
    if any(not isinstance(flow, dict) for flow in flows):
        return None
    return flows


@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'model_trained': model is not None})


@app.route('/train', methods=['POST'])
@require_token
def train():
    """Train the Isolation Forest model on normal traffic"""
    global model, training_data

    flows = _flows_from_request(request.json)
    if flows is None:
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
    save_model()

    return jsonify({
        'status': 'trained',
        'samples': len(flows),
        'features': X.shape[1]
    })


@app.route('/detect', methods=['POST'])
@require_token
def detect():
    """Detect if a flow is anomalous"""
    global model

    flow = request.json
    if not flow or not isinstance(flow, dict):
        return jsonify({'error': 'Expected flow object'}), 400

    # Use simple heuristic if not trained
    if model is None:
        return jsonify(simple_score(flow))

    return jsonify(_ml_score(flow, model))


@app.route('/batch', methods=['POST'])
@require_token
def batch():
    """Detect anomalies for multiple flows at once.

    Response shape (matches /detect per prediction):
      {"predictions": [{"index": 0, "score": 73.2, "is_anomaly": true,
                        "reason": "..."}, ...],
       "total": 2, "anomalies": 1}
    """
    global model

    flows = _flows_from_request(request.json)
    if flows is None:
        return jsonify({'error': 'Expected list of flows'}), 400

    if model is None:
        results = []
        for i, flow in enumerate(flows):
            score = simple_score(flow)
            results.append({'index': i, **score})
    else:
        features = np.array([extract_features(flow) for flow in flows])
        predictions = model.predict(features)
        scores = model.decision_function(features)
        results = []
        for i, (pred, score) in enumerate(zip(predictions, scores, strict=False)):
            is_anomaly = pred == -1
            normalized = _normalize_ml_score(score)
            reason = "ML-based detection: "
            reason += "flow deviates from normal patterns" if is_anomaly else "flow matches normal patterns"
            results.append({
                'index': i,
                'score': float(normalized),
                'is_anomaly': bool(is_anomaly),
                'reason': reason
            })

    return jsonify({
        'predictions': results,
        'total': len(results),
        'anomalies': sum(1 for r in results if r['is_anomaly'])
    })


@app.route('/predict', methods=['POST'])
@require_token
def predict():
    """Predict if a single flow is anomalous (requires trained model)"""
    global model

    if model is None:
        return jsonify({'error': 'Model not trained. Call /train first.'}), 400

    flow = request.json
    if not flow or not isinstance(flow, dict):
        return jsonify({'error': 'Expected flow object'}), 400

    features = np.array([extract_features(flow)])
    prediction = model.predict(features)[0]
    raw = model.decision_function(features)[0]

    is_anomaly = prediction == -1
    normalized = _normalize_ml_score(raw)

    return jsonify({
        'is_anomaly': bool(is_anomaly),
        'anomaly': bool(is_anomaly),
        'score': float(normalized),
        'confidence': float(abs(raw))
    })


@app.route('/batch_predict', methods=['POST'])
@require_token
def batch_predict():
    """Predict anomalies for multiple flows at once (legacy endpoint)"""
    global model

    if model is None:
        return jsonify({'error': 'Model not trained. Call /train first.'}), 400

    flows = _flows_from_request(request.json)
    if flows is None:
        return jsonify({'error': 'Expected list of flows'}), 400

    # Extract features for all flows
    features = np.array([extract_features(flow) for flow in flows])
    X = np.array(features)

    # Predict for all flows
    predictions = model.predict(X)
    scores = model.decision_function(X)

    # Format results
    results = []
    for i, (pred, score) in enumerate(zip(predictions, scores, strict=False)):
        is_anomaly = pred == -1
        normalized_score = _normalize_ml_score(score)

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


load_model()

if __name__ == '__main__':
    print("Starting ZTAP Anomaly Detection Service")
    print("Endpoints:")
    print("  POST /train         - Train model on normal traffic")
    print("  POST /predict       - Predict single flow (requires trained model)")
    print("  POST /batch_predict - Predict multiple flows (requires trained model)")
    print("  POST /batch         - Detect anomalies in a batch of flows")
    print("  POST /detect        - Detect anomalous flows (with fallback)")
    print("  GET  /health        - Health check")
    host = os.environ.get('ZTAP_ANOMALY_HOST', '127.0.0.1')
    port = int(os.environ.get('ZTAP_ANOMALY_PORT', '5000'))
    app.run(host=host, port=port, debug=False)
