import unittest
import json
import sys
from datetime import datetime
sys.path.insert(0, '.')

import service
from service import app, extract_features


class TestAnomalyDetectionService(unittest.TestCase):
    """Test suite for anomaly detection microservice"""
    
    def setUp(self):
        """Set up test client"""
        self.app = app
        self.client = self.app.test_client()
        self.app.testing = True
        
        # Reset global state in the service module
        service.model = None
        service.training_data = []
    
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
        
        features = extract_features(flow)
        
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
        
        features = extract_features(flow)
        
        # Protocol mapping: UDP = 2
        self.assertEqual(features[3], 2)
        self.assertEqual(features[2], 53)
    
    def test_feature_extraction_defaults(self):
        """Test feature extraction with missing fields"""
        flow = {}  # Empty flow
        
        features = extract_features(flow)
        
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
        """Test batch prediction endpoint"""
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


if __name__ == '__main__':
    unittest.main()
