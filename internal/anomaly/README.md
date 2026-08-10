# ZTAP Anomaly Detection Service

Isolation-Forest-based anomaly detection microservice for ZTAP. The Go agent
(`ztap agent` / `ztap enforce` with `anomaly.enabled: true`) buffers flow
events and scores them in batches against this service.

## Setup

```bash
python3 -m pip install .
python3 -m pip install -e ".[dev]"   # for tests + lint
```

Dependencies are pinned in `pyproject.toml`; `ruff` and `pytest` ship in the
`dev` extra.

## Run (host-local dev)

```bash
python3 service.py
```

Binds `127.0.0.1:5000` by default. Override with `ZTAP_ANOMALY_HOST` /
`ZTAP_ANOMALY_PORT`. In the container image the service runs under gunicorn
and binds `0.0.0.0` so the agent can reach it from another container on the
compose network (`docker-compose.yml`).

## Authentication

Set `ZTAP_ANOMALY_TOKEN` to require `Authorization: Bearer <token>` on every
data endpoint (`/train`, `/detect`, `/batch`, `/predict`, `/batch_predict`).
`/health` stays open for container health checks. The Go agent sends the
token configured as `anomaly.auth_token` in `config.yaml`.

## Model persistence

Training data is fit into an Isolation Forest; the model is saved with
`joblib` to `$MODEL_PATH/model.joblib` (default `./models`) after every
`/train` and loaded on start, so training survives restarts. The compose
service mounts `anomaly-models` at `/app/models`.

## API

All data endpoints require the bearer token when `ZTAP_ANOMALY_TOKEN` is set.

### Train Model

```bash
curl -X POST http://localhost:5000/train \
  -H "Authorization: Bearer $ZTAP_ANOMALY_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"flows":[{"source_ip":"10.0.0.1","dest_ip":"10.0.0.2","port":443,"protocol":"TCP","bytes":1024,"timestamp":"2025-10-09T10:00:00"}]}'
```

### Detect Anomaly (single flow)

```bash
curl -X POST http://localhost:5000/detect \
  -H "Authorization: Bearer $ZTAP_ANOMALY_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"source_ip":"192.168.1.100","dest_ip":"1.2.3.4","port":22,"protocol":"TCP","bytes":5000000,"timestamp":"2025-10-09T03:00:00"}'
```

### Detect Anomalies (batch — used by the Go pipeline)

```bash
curl -X POST http://localhost:5000/batch \
  -H "Authorization: Bearer $ZTAP_ANOMALY_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"flows":[{"source_ip":"10.0.0.1","dest_ip":"10.0.0.2","port":443,"protocol":"TCP","bytes":1024,"timestamp":"2025-10-09T10:00:00"}]}'
```

```json
{"predictions": [{"index": 0, "score": 73.2, "is_anomaly": true, "reason": "..."}], "total": 1, "anomalies": 1}
```

### Health Check

```bash
curl http://localhost:5000/health
```

## Tests & lint

```bash
pytest
ruff check .
```
