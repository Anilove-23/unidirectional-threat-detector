# Person 4 WebSocket Contract

Real-time streaming event contract provided by **Person 4 (Backend Engineer)** for **Person 5 & 6 (React Dashboard Division)**.

---

## Connection URL
```
ws://localhost:4000/ws
```

---

## Connection Lifecycle

1. **Initial Connection**:
   Upon connecting, the server immediately sends a connection confirmation event:
   ```json
   {
     "event": "connection_established",
     "message": "Connected to SIH26145 Real-Time Threat Stream",
     "timestamp": "2026-08-30T10:00:00.000Z"
   }
   ```

2. **Real-Time Alert Event (`alert`)**:
   Emitted in real time whenever an AI/ML threat alert is received over Redis channel `alert.new`:
   ```json
   {
     "event": "alert",
     "data": {
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
       },
       "ingestion_meta": {
         "sensor_id": "diode-sensor-04",
         "capture_interface": "eth1-rx-only",
         "pipeline_version": "1.3.0"
       }
     },
     "timestamp": "2026-08-30T10:00:05.120Z"
   }
   ```

3. **Client Reconnection Strategy**:
   - The React dashboard client should implement exponential backoff reconnects (e.g. initial delay 1s, max delay 10s).
   - If disconnected, the dashboard does not lose missed historical alerts; upon reconnect, query `/api/alerts/search` via REST for historical backfill.
