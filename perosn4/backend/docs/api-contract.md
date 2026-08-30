# Person 4 Backend REST API Contract

Documentation provided by **Person 4 (Backend Engineer)** for **Person 5 & 6 (React Dashboard Division)**.

---

## Base URL
```
http://localhost:4000/api
```

---

## Endpoints

### 1. List Alerts (Paginated)
- **Method**: `GET`
- **Path**: `/alerts`
- **Query Parameters**:
  - `page` (optional integer, default: `1`)
  - `limit` (optional integer, default: `20`)

**Response (`200 OK`)**:
```json
{
  "status": "success",
  "data": {
    "total": 45,
    "page": 1,
    "limit": 20,
    "totalPages": 3,
    "alerts": [
      {
        "timestamp": "2026-08-30T06:42:11.318Z",
        "flow_id": "9c1f2a3e-77b4-4e2d-9c6a-1d3f8b0a55e2",
        "five_tuple": {
          "src_ip": "10.44.12.15",
          "dst_ip": "198.51.100.23",
          "src_port": 51322,
          "dst_port": 443,
          "protocol": "TCP/TLS"
        },
        "threat_class": "BOTNET_C2_BEACONING",
        "confidence_score": 0.93,
        "severity": "HIGH",
        "model_source": {
          "supervised_score": 0.41,
          "anomaly_score": 0.88,
          "fired_models": ["lstm_beacon_v2"]
        },
        "evidence": {
          "beacon_interval_seconds": 59.8
        }
      }
    ]
  }
}
```

---

### 2. Search Historical Alerts
- **Method**: `GET`
- **Path**: `/alerts/search`
- **Query Parameters**:
  - `threat_class` (string, e.g. `BOTNET_C2_BEACONING`, `MALWARE_EXFILTRATION`)
  - `severity` (string: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`)
  - `from` (ISO-8601 string date)
  - `to` (ISO-8601 string date)
  - `page` (integer, default `1`)
  - `limit` (integer, default `20`)

**Response (`200 OK`)**:
```json
{
  "status": "success",
  "data": {
    "total": 1,
    "page": 1,
    "limit": 20,
    "totalPages": 1,
    "alerts": [ /* array of matching alert objects */ ]
  }
}
```

---

### 3. Fetch Single Alert Details
- **Method**: `GET`
- **Path**: `/alerts/:flow_id`

**Response (`200 OK`)**:
```json
{
  "status": "success",
  "data": {
    "timestamp": "2026-08-30T06:42:11.318Z",
    "flow_id": "9c1f2a3e-77b4-4e2d-9c6a-1d3f8b0a55e2",
    "five_tuple": { /* five_tuple object */ },
    "threat_class": "BOTNET_C2_BEACONING",
    "confidence_score": 0.93,
    "severity": "HIGH",
    "model_source": { /* model scores */ },
    "evidence": { /* threat evidence */ },
    "ingestion_meta": { /* sensor details */ }
  }
}
```

**Response (`404 Not Found`)**:
```json
{
  "status": "error",
  "message": "Alert with flow_id '9c1f2a3e-...' not found"
}
```

---

### 4. Pipeline & System Health Check
- **Method**: `GET`
- **Path**: `/health`

**Response (`200 OK`)**:
```json
{
  "status": "healthy",
  "service": "SIH26145-Backend-Person4",
  "uptime_seconds": 1240,
  "timestamp": "2026-08-30T10:30:00.000Z",
  "components": {
    "database": { "isConnected": true, "type": "memory" },
    "redis_subscriber": { "isConnected": true, "channel": "alert.new" },
    "websocket_broadcaster": { "active_connections": 2 },
    "alert_store": { "total_alerts": 142 }
  }
}
```
