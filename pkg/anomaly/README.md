# ZTAP Anomaly Detection Service

## Setup

```bash
pip install flask scikit-learn numpy
```

## Run

```bash
python3 service.py
```

## API

### Train Model

```bash
curl -X POST http://localhost:5000/train \
  -H "Content-Type: application/json" \
  -d '[{"source_ip":"10.0.0.1","dest_ip":"10.0.0.2","port":443,"protocol":"TCP","bytes":1024,"timestamp":"2025-10-09T10:00:00"}]'
```

### Detect Anomaly

```bash
curl -X POST http://localhost:5000/detect \
  -H "Content-Type: application/json" \
  -d '{"source_ip":"192.168.1.100","dest_ip":"1.2.3.4","port":22,"protocol":"TCP","bytes":5000000,"timestamp":"2025-10-09T03:00:00"}'
```

### Health Check

```bash
curl http://localhost:5000/health
```
