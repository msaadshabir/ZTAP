import json
import sys
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

sys.path.insert(0, '.')

import service


class TestAnomalyDetectionService(unittest.TestCase):
    """Test suite for anomaly detection microservice"""

    def setUp(self):
        """Set up test client"""
        self.app = service.app
        self.client = self.app.test_client()
        self.app.testing = True

        # Reset global state in the service module. Point model persistence
        # at a scratch directory so tests never write into the repo.
        service.model = None
        service.training_data = []
        service.TOKEN = ""
        self._tmpdir = tempfile.TemporaryDirectory()
        service.MODEL_PATH = Path(self._tmpdir.name) / "model.joblib"

    def tearDown(self):
        self._tmpdir.cleanup()

    def test_health_endpoint(self):
        """Test health check endpoint"""
        response = self.client.get('/health')
        self.assertEqual(response.status_code, 200)

        data = json.loads(response.data)
        self.assertIn('status', data)
        self.assertEqual(data['status'], 'healthy')
        self.assertIn('model_trained', data)

    def test_feature_extraction(self):
        """Test feature extraction from flow records"""
        flow = {
            'source_ip': '192.168.1.100',
            'dest_ip': '10.0.0.50',
            'protocol': 'TCP',
            'port': 443,
            'bytes': 1024,
            'timestamp': datetime.now().isoformat()
        }

        features = service.extract_features(flow)

        # Should return 6 features
        self.assertEqual(len(features), 6)

        # All features should be numeric
        for feature in features:
            self.assertIsInstance(feature, (int, float))

        # Port should match
        self.assertEqual(features[2], 443)

        # Protocol mapping: TCP = 1
        self.assertEqual(features[3], 1)

        # Bytes should match
        self.assertEqual(features[4], 1024)

    def test_feature_extraction_deterministic(self):
        """IP features must be reproducible across restarts.

        The old implementation used built-in hash(), which is randomized per
        process (PYTHONHASHSEED); features are now derived from the integer
        form of the address, so the same IP always yields the same feature.
        """
        flow = {
            'source_ip': '192.168.1.100',
            'dest_ip': '10.0.0.50',
            'protocol': 'TCP',
            'port': 443,
            'bytes': 1024,
            'timestamp': datetime.now().isoformat()
        }

        self.assertEqual(service.extract_features(flow), service.extract_features(flow))

        # Known values: int(ipaddress.ip_address(...)) % 10000
        self.assertEqual(service.extract_features(flow)[0], 5876)  # 192.168.1.100
        self.assertEqual(service.extract_features(flow)[1], 2210)  # 10.0.0.50

    def test_feature_extraction_invalid_ip(self):
        """Malformed IPs must degrade to a stable zero feature, not raise."""
        flow = {'source_ip': 'not-an-ip', 'dest_ip': '10.0.0.1', 'protocol': 'TCP', 'port': 80, 'bytes': 1}
        features = service.extract_features(flow)
        self.assertEqual(features[0], 0)
        self.assertEqual(features[1], 2161)  # int(ipaddress.ip_address('10.0.0.1')) % 10000

    def test_feature_extraction_udp(self):
        """Test feature extraction for UDP protocol"""
        flow = {
            'source_ip': '10.0.1.1',
            'dest_ip': '10.0.1.2',
            'protocol': 'UDP',
            'port': 53,
            'bytes': 512,
            'timestamp': datetime.now().isoformat()
        }

        features = service.extract_features(flow)

        # Protocol mapping: UDP = 2
        self.assertEqual(features[3], 2)
        self.assertEqual(features[2], 53)

    def test_feature_extraction_defaults(self):
        """Test feature extraction with missing fields"""
        flow = {}  # Empty flow

        features = service.extract_features(flow)

        # Should still return 6 features with defaults
        self.assertEqual(len(features), 6)

        # Default port should be 0
        self.assertEqual(features[2], 0)

        # Default protocol should be 0 (unknown)
        self.assertEqual(features[3], 0)

        # Default bytes should be 0
        self.assertEqual(features[4], 0)

    def test_train_endpoint(self):
        """Test model training endpoint"""
        training_flows = [
            {
                'source_ip': '192.168.1.10',
                'dest_ip': '10.0.0.1',
                'protocol': 'TCP',
                'port': 80,
                'bytes': 500,
                'timestamp': datetime.now().isoformat()
            },
            {
                'source_ip': '192.168.1.11',
                'dest_ip': '10.0.0.2',
                'protocol': 'TCP',
                'port': 443,
                'bytes': 1000,
                'timestamp': datetime.now().isoformat()
            },
            {
                'source_ip': '192.168.1.12',
                'dest_ip': '10.0.0.3',
                'protocol': 'UDP',
                'port': 53,
                'bytes': 200,
                'timestamp': datetime.now().isoformat()
            }
        ]

        response = self.client.post('/train',
                                    data=json.dumps({'flows': training_flows}),
                                    content_type='application/json')

        self.assertEqual(response.status_code, 200)

        data = json.loads(response.data)
        self.assertIn('status', data)
        self.assertEqual(data['status'], 'trained')
        self.assertIn('samples', data)
        self.assertEqual(data['samples'], 3)

    def test_train_endpoint_insufficient_data(self):
        """Test training with insufficient data"""
        training_flows = [
            {
                'source_ip': '192.168.1.10',
                'dest_ip': '10.0.0.1',
                'protocol': 'TCP',
                'port': 80,
                'bytes': 500,
                'timestamp': datetime.now().isoformat()
            }
        ]

        response = self.client.post('/train',
                                    data=json.dumps({'flows': training_flows}),
                                    content_type='application/json')

        # Should fail with insufficient data
        self.assertEqual(response.status_code, 400)

        data = json.loads(response.data)
        self.assertIn('error', data)

    def test_model_persistence(self):
        """Training must persist the model so it survives restarts."""
        training_flows = []
        for i in range(10):
            training_flows.append({
                'source_ip': f'192.168.1.{i}',
                'dest_ip': '10.0.0.1',
                'protocol': 'TCP',
                'port': 80,
                'bytes': 500 + i * 10,
                'timestamp': datetime.now().isoformat()
            })

        response = self.client.post('/train',
                                    data=json.dumps({'flows': training_flows}),
                                    content_type='application/json')
        self.assertEqual(response.status_code, 200)
        self.assertTrue(service.MODEL_PATH.exists(), "model file was not written")

        # Simulate a restart: drop the in-memory model and reload from disk.
        service.model = None
        service.load_model()
        self.assertIsNotNone(service.model, "model did not reload from disk")

    def test_ml_score_calibration(self):
        """Normal trained traffic must remain at or below the default threshold."""
        normal_flow = {
            'source_ip': '10.0.0.1',
            'dest_ip': '10.0.0.2',
            'protocol': 'TCP',
            'port': 443,
            'bytes': 1000,
            'timestamp': '2025-01-01T12:00:00',
        }
        training_flows = [normal_flow.copy() for _ in range(20)]

        response = self.client.post(
            '/train',
            data=json.dumps({'flows': training_flows}),
            content_type='application/json',
        )
        self.assertEqual(response.status_code, 200)

        response = self.client.post(
            '/detect',
            data=json.dumps(normal_flow),
            content_type='application/json',
        )
        self.assertEqual(response.status_code, 200)
        result = response.get_json()
        self.assertFalse(result['is_anomaly'])
        self.assertLessEqual(result['score'], 50.0)

    def test_batch_rejects_non_object_flow(self):
        """Batch endpoints must return 400 instead of raising on malformed items."""
        response = self.client.post(
            '/batch',
            data=json.dumps({'flows': [{}, 'not-a-flow']}),
            content_type='application/json',
        )
        self.assertEqual(response.status_code, 400)

    def test_predict_endpoint_no_model(self):
        """Test prediction without training first"""
        flow = {
            'source_ip': '192.168.1.100',
            'dest_ip': '10.0.0.50',
            'protocol': 'TCP',
            'port': 443,
            'bytes': 1024,
            'timestamp': datetime.now().isoformat()
        }

        response = self.client.post('/predict',
                                    data=json.dumps(flow),
                                    content_type='application/json')

        # Should fail without trained model
        self.assertEqual(response.status_code, 400)

        data = json.loads(response.data)
        self.assertIn('error', data)

    def test_full_workflow(self):
        """Test complete train -> predict workflow"""
        # Step 1: Train the model
        training_flows = []
        for i in range(10):
            training_flows.append({
                'source_ip': f'192.168.1.{i}',
                'dest_ip': '10.0.0.1',
                'protocol': 'TCP',
                'port': 80,
                'bytes': 500 + i * 10,
                'timestamp': datetime.now().isoformat()
            })

        response = self.client.post('/train',
                                    data=json.dumps({'flows': training_flows}),
                                    content_type='application/json')

        self.assertEqual(response.status_code, 200)

        # Step 2: Predict on normal flow (should be normal)
        normal_flow = {
            'source_ip': '192.168.1.50',
            'dest_ip': '10.0.0.1',
            'protocol': 'TCP',
            'port': 80,
            'bytes': 550,
            'timestamp': datetime.now().isoformat()
        }

        response = self.client.post('/predict',
                                    data=json.dumps(normal_flow),
                                    content_type='application/json')

        self.assertEqual(response.status_code, 200)

        data = json.loads(response.data)
        self.assertIn('anomaly', data)
        self.assertIn('score', data)

        # Step 3: Predict on anomalous flow
        anomalous_flow = {
            'source_ip': '1.2.3.4',
            'dest_ip': '5.6.7.8',
            'protocol': 'ICMP',
            'port': 9999,
            'bytes': 999999,
            'timestamp': datetime.now().isoformat()
        }

        response = self.client.post('/predict',
                                    data=json.dumps(anomalous_flow),
                                    content_type='application/json')

        self.assertEqual(response.status_code, 200)

        data = json.loads(response.data)
        self.assertIn('anomaly', data)
        self.assertIn('score', data)

    def test_batch_predict_endpoint(self):
        """Test legacy batch prediction endpoint"""
        # First train
        training_flows = []
        for i in range(10):
            training_flows.append({
                'source_ip': f'192.168.1.{i}',
                'dest_ip': '10.0.0.1',
                'protocol': 'TCP',
                'port': 443,
                'bytes': 1000,
                'timestamp': datetime.now().isoformat()
            })

        self.client.post('/train',
                         data=json.dumps({'flows': training_flows}),
                         content_type='application/json')

        # Test batch prediction
        test_flows = [
            {
                'source_ip': '192.168.1.100',
                'dest_ip': '10.0.0.1',
                'protocol': 'TCP',
                'port': 443,
                'bytes': 1000,
                'timestamp': datetime.now().isoformat()
            },
            {
                'source_ip': '192.168.1.101',
                'dest_ip': '10.0.0.1',
                'protocol': 'TCP',
                'port': 443,
                'bytes': 1000,
                'timestamp': datetime.now().isoformat()
            }
        ]

        response = self.client.post('/batch_predict',
                                    data=json.dumps({'flows': test_flows}),
                                    content_type='application/json')

        self.assertEqual(response.status_code, 200)

        data = json.loads(response.data)
        self.assertIn('predictions', data)
        self.assertEqual(len(data['predictions']), 2)

        # Each prediction should have anomaly and score
        for pred in data['predictions']:
            self.assertIn('anomaly', pred)
            self.assertIn('score', pred)

    def test_batch_endpoint(self):
        """Test the /batch endpoint consumed by the Go pipeline"""
        # Train first so the ML path is exercised.
        training_flows = []
        for i in range(10):
            training_flows.append({
                'source_ip': f'192.168.1.{i}',
                'dest_ip': '10.0.0.1',
                'protocol': 'TCP',
                'port': 443,
                'bytes': 1000,
                'timestamp': datetime.now().isoformat()
            })
        self.client.post('/train',
                         data=json.dumps({'flows': training_flows}),
                         content_type='application/json')

        test_flows = [
            {'source_ip': '192.168.1.100', 'dest_ip': '10.0.0.1', 'protocol': 'TCP', 'port': 443, 'bytes': 1000},
            {'source_ip': '1.2.3.4', 'dest_ip': '5.6.7.8', 'protocol': 'ICMP', 'port': 9999, 'bytes': 999999},
        ]
        response = self.client.post('/batch',
                                    data=json.dumps({'flows': test_flows}),
                                    content_type='application/json')

        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data['total'], 2)
        self.assertIn('anomalies', data)
        self.assertEqual(len(data['predictions']), 2)

        # Every prediction carries the /detect schema with a matching index.
        for i, pred in enumerate(data['predictions']):
            self.assertEqual(pred['index'], i)
            self.assertIn('score', pred)
            self.assertIn('is_anomaly', pred)
            self.assertIn('reason', pred)
            self.assertTrue(0 <= pred['score'] <= 100)

    def test_batch_endpoint_untrained(self):
        """/batch must fall back to rule-based scoring before training."""
        test_flows = [
            {'source_ip': '10.0.0.1', 'dest_ip': '10.0.0.2', 'protocol': 'TCP', 'port': 22, 'bytes': 1000},
            {'source_ip': '10.0.0.1', 'dest_ip': '10.0.0.3', 'protocol': 'TCP', 'port': 443, 'bytes': 1000},
        ]
        response = self.client.post('/batch',
                                    data=json.dumps({'flows': test_flows}),
                                    content_type='application/json')

        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data['total'], 2)
        # Suspicious port 22 scores 30 via the rule fallback (below the 50
        # anomaly threshold but clearly flagged in the reason).
        self.assertGreaterEqual(data['predictions'][0]['score'], 30)
        self.assertIn('suspicious port', data['predictions'][0]['reason'])
        self.assertFalse(data['predictions'][1]['is_anomaly'])

    def test_invalid_json(self):
        """Test handling of invalid JSON"""
        response = self.client.post('/train',
                                    data='invalid json{',
                                    content_type='application/json')

        self.assertEqual(response.status_code, 400)

    def test_missing_fields(self):
        """Test handling of missing required fields"""
        response = self.client.post('/train',
                                    data=json.dumps({}),
                                    content_type='application/json')

        self.assertEqual(response.status_code, 400)


class TestAnomalyServiceAuth(unittest.TestCase):
    """Token authentication (ZTAP_ANOMALY_TOKEN)"""

    TOKEN = "test-secret-token"

    def setUp(self):
        self.app = service.app
        self.client = self.app.test_client()
        self.app.testing = True
        service.model = None
        service.training_data = []
        service.TOKEN = self.TOKEN
        self._tmpdir = tempfile.TemporaryDirectory()
        service.MODEL_PATH = Path(self._tmpdir.name) / "model.joblib"

    def tearDown(self):
        service.TOKEN = ""
        self._tmpdir.cleanup()

    def _flow(self):
        return {'source_ip': '10.0.0.1', 'dest_ip': '10.0.0.2', 'protocol': 'TCP',
                'port': 443, 'bytes': 10, 'timestamp': datetime.now().isoformat()}

    def test_detect_requires_token(self):
        response = self.client.post('/detect', data=json.dumps(self._flow()), content_type='application/json')
        self.assertEqual(response.status_code, 401)

    def test_detect_accepts_token(self):
        response = self.client.post(
            '/detect',
            data=json.dumps(self._flow()),
            content_type='application/json',
            headers={'Authorization': f'Bearer {self.TOKEN}'})
        self.assertEqual(response.status_code, 200)

    def test_detect_rejects_wrong_token(self):
        response = self.client.post(
            '/detect',
            data=json.dumps(self._flow()),
            content_type='application/json',
            headers={'Authorization': 'Bearer wrong-token'})
        self.assertEqual(response.status_code, 401)

    def test_train_requires_token(self):
        flows = [self._flow(), self._flow()]
        response = self.client.post('/train', data=json.dumps({'flows': flows}), content_type='application/json')
        self.assertEqual(response.status_code, 401)

    def test_batch_requires_token(self):
        flows = [self._flow(), self._flow()]
        response = self.client.post('/batch', data=json.dumps({'flows': flows}), content_type='application/json')
        self.assertEqual(response.status_code, 401)

    def test_health_is_open(self):
        """The container HEALTHCHECK must work without a token."""
        response = self.client.get('/health')
        self.assertEqual(response.status_code, 200)


if __name__ == '__main__':
    unittest.main()
