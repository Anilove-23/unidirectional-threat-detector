# Person 4 — Context Brief for Project Scaffolding
### SIH26145 — AI-Based Detection of Cyber Threats in Unidirectional IP Traffic
### Role: Express API & Real-Time Streaming Engineer (Backend Division)

> This document is written to be handed to a coding agent (e.g. Antigravity) so it can scaffold
> the folder/file structure and starter code for Person 4's portion of the system. It also lists
> every file this work assumes exists elsewhere in the repo, produced by teammates, along with
> what that file is expected to contain. **Those files are ASSUMPTIONS based on team task
> allocation — confirm exact filenames/paths/shapes with the actual owners before finalizing.**

---

## 1. Project Context (short version)

The team is building a passive, real-time network threat-detection system for NTRO
(Smart India Hackathon 2026, Problem Statement SIH26145). Traffic is mirrored through a
data-diode/optical-splitter simulation, so the ingestion side is strictly **read-only** —
no packet, probe, or command is ever sent back across that boundary.

The system is a 5-stage streaming pipeline:

```
Data diode (one-way) 
  -> Person 3: Ingestion (Zeek/Scapy/tshark) -> publishes to Redis channel "flow.raw"
  -> Feature extraction + Person 1 & 2: AI/ML inference -> publishes to Redis channel "alert.new"
  -> Person 4 (YOU): subscribe to "alert.new" -> persist to DB, broadcast via WebSocket, serve REST API
  -> Person 5 & 6: React dashboard consumes your WebSocket feed + REST API
```

Redis here is used in **pub/sub mode**, not as a key-value cache. `flow.raw` and `alert.new`
are just channel *names* (arbitrary strings agreed by the team) — the payload on each channel
is a JSON string, by convention, not by any Redis requirement.

---

## 2. Your Scope of Work (Person 4)

1. **Redis subscriber** — a long-running process that subscribes to `alert.new` (and optionally
   `flow.raw` if raw-flow archival/debugging is wanted) and never blocks the publishers.
2. **Persistence layer** — write every alert (and optionally its source flow) to
   PostgreSQL and/or MongoDB.
3. **WebSocket / SSE broadcaster** — push every new alert to connected dashboard clients in
   real time.
4. **Express REST API** — historical alert search/filter, dashboard config, health checks.

You do **not** build the ML models, the packet capture, or the React UI. You are the
integration and delivery layer between the analytics pipeline and the dashboard.

---

## 3. Files Assumed to Exist From Other Team Members

These are referenced throughout this brief and throughout your planned code, but **you do not
own or create them**. They are listed here so the scaffolding can stub them out if they don't
exist yet, and so you know exactly what to ask your teammates for.

### 3.1 `ingestion/flow_schema.json` — owned by **Person 3**
Defines the shape of the JSON Flow Object published to Redis channel `flow.raw`.
You need this if you archive raw flows or expose a debug view of pre-inference data.

Assumed shape (confirm with Person 3):
```json
{
  "flow_id": "uuid",
  "timestamp": "ISO-8601 string",
  "five_tuple": { "src_ip": "string", "dst_ip": "string", "src_port": "number", "dst_port": "number", "protocol": "string" },
  "packet_size_sequence": ["number", "..."],
  "inter_arrival_times": ["number", "..."],
  "tcp_flags_observed": ["string", "..."],
  "tls_client_hello": { "ja3": "string", "ja4": "string", "cipher_suites": ["string"] }
}
```

### 3.2 `ml/alert_schema.json` — owned by **Person 1 & Person 2**
Defines the final, standardized alert object published to Redis channel `alert.new`. This is
the single most important upstream contract for your work — it is what you persist, broadcast,
and expose via REST. This matches Section 6 of the team's System Architecture Specification
document.

Assumed shape (confirm with Person 1 & 2 if it drifts from this):
```json
{
  "timestamp": "2026-08-28T06:42:11.318Z",
  "flow_id": "9c1f2a3e-77b4-4e2d-9c6a-1d3f8b0a55e2",
  "five_tuple": { "src_ip": "10.44.host.masked", "dst_ip": "198.51.100.23", "src_port": 51322, "dst_port": 443, "protocol": "TCP/TLS" },
  "threat_class": "BOTNET_C2_BEACONING",
  "confidence_score": 0.93,
  "severity": "HIGH",
  "model_source": { "supervised_score": 0.41, "anomaly_score": 0.88, "sequence_score": 0.95, "fired_models": ["lstm_beacon_v2", "isolation_forest_v3"] },
  "evidence": { "ja3_fingerprint": "string", "beacon_interval_seconds": 59.8, "src_ip_entropy": 0.11 },
  "ingestion_meta": { "sensor_id": "diode-sensor-04", "capture_interface": "eth1-rx-only", "pipeline_version": "1.3.0" }
}
```
`threat_class` and `severity` are closed enums — confirm the full list of valid values with
Person 1 & 2 before hardcoding validation or DB constraints.

### 3.3 `docs/redis-channels-contract.md` — **jointly owned by Person 3 & Person 4**
Should document: exact channel names, message envelope (raw JSON string vs. wrapped object),
and backpressure/retry behavior if your consumer falls behind. If this file doesn't exist yet,
you and Person 3 should write it together before wiring the real subscriber — this determines
whether plain Redis pub/sub is enough or a more durable queue is needed.

---

## 4. Files/Folders You Own (to be scaffolded)

```
backend/
├── package.json
├── .env.example
├── src/
│   ├── server.js                  # Express app entry point
│   ├── config/
│   │   └── index.js                # loads env vars: PORT, REDIS_URL, DB_URL, etc.
│   ├── redis/
│   │   ├── subscriber.js           # subscribes to "alert.new" (and optionally "flow.raw")
│   │   └── mockPublisher.js        # publishes fake alerts on a timer, for local dev
│   ├── websocket/
│   │   └── broadcaster.js          # fan-out layer: pushes alerts to connected clients
│   ├── routes/
│   │   ├── alerts.js               # GET /api/alerts, /api/alerts/:id, /api/alerts/search
│   │   └── health.js               # GET /api/health
│   ├── db/
│   │   ├── connection.js           # PostgreSQL/MongoDB connection setup
│   │   └── models/
│   │       └── Alert.js            # DB schema/model mirroring alert_schema.json
│   └── schemas/
│       └── alertSchema.json        # local copy of the agreed schema, used for validation
├── tests/
│   └── alerts.test.js
└── docs/
    ├── api-contract.md             # REST contract you hand to Person 5
    └── websocket-contract.md       # WebSocket event contract you hand to Person 5
```

---

## 5. REST API Contract (to publish for Person 5)

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/api/alerts` | List alerts, paginated, newest first |
| GET | `/api/alerts/:flow_id` | Fetch a single alert by flow_id |
| GET | `/api/alerts/search?threat_class=&severity=&from=&to=` | Filtered historical search |
| GET | `/api/health` | Pipeline/service health check |

## 6. WebSocket Contract (to publish for Person 5)

- Event name: `alert`
- Payload: the exact alert JSON object as defined in `ml/alert_schema.json` (Section 3.2 above)
- Client should implement reconnect-with-backoff; server does not queue missed messages during
  a disconnect (that's what the REST search endpoint is for, on reconnect).

---

## 7. Environment Variables Needed

```
PORT=4000
REDIS_URL=redis://localhost:6379
DATABASE_URL=postgres://user:pass@localhost:5432/sih_alerts   # or MongoDB URI
NODE_ENV=development
```

---

## 8. Suggested Build Order

1. Scaffold the folder structure above.
2. Build `mockPublisher.js` that publishes fake alerts (matching `alert_schema.json`) onto
   `alert.new` on an interval — lets you build everything else without waiting on
   Person 1/2/3.
3. Build `redis/subscriber.js` + `websocket/broadcaster.js` against the mock publisher.
4. Build the REST routes and DB persistence.
5. Publish `docs/api-contract.md` and `docs/websocket-contract.md` early so Person 5 can start
   in parallel.
6. Swap `mockPublisher.js` for the real Redis connection once Person 1/2/3's channels are live —
   ideally zero code changes needed if the schema hasn't drifted.
