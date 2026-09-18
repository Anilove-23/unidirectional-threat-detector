# Redis Contract
## SIH26145 — Person 3 (Publisher) Interface Specification
### Verified against System Architecture Specification v1.0

---

## Overview

Person 3 owns exactly ONE Redis interaction: PUBLISH to `flow.raw`.
This mirrors the data-diode guarantee in software.

```
Person 3 (ingestion)  ---PUBLISH--->  flow.raw  ---SUBSCRIBE--->  Person 1 & 2 (ML)
                                                 ---SUBSCRIBE--->  Person 4 (Express API, if needed)
```

Person 3 NEVER calls: SUBSCRIBE, GET, SET, XREAD, BLPOP, or any read operation.

---

## Channel: flow.raw

### Reference
SIH26145 Spec Section 3 (Architecture Diagram):
```
B -->|publish flow.raw| C[(Redis Pub/Sub Queue)]
```
SIH26145 Spec Section 4.1:
> Flow Objects are published to the Redis channel flow.raw.
> Publishing is fire-and-forget from the capture process perspective
> -- it never waits on or reads from downstream services.

### Contract

| Property | Value |
|---|---|
| Channel name | `flow.raw` |
| Publisher | Person 3 ingestion service |
| Subscribers | Person 1 (XGBoost/LightGBM), Person 2 (IsoForest/LSTM/AE) |
| Message encoding | UTF-8 JSON string |
| Message schema | FlowObject v1.0.0 (see FLOW_OBJECT_SCHEMA.md) |
| Max message size | ~64 KB (enforced by 50-packet-sample cap on packet_sizes and inter_arrival_times) |
| Publish semantics | Fire-and-forget (Redis PUBLISH command only) |
| On publish failure | Log warning + increment ingestion_redis_publish_errors_total + continue |
| Retry on failure | NEVER — retrying blocks the packet capture callback |
| Backpressure | Drop-and-log if Redis connection times out |

### Message envelope

Every message on flow.raw is a UTF-8 JSON string conforming to FlowObject v1.0.0.
The outer envelope is the FlowObject itself — there is no wrapper object.

```json
{
  "schema_version": "1.0.0",
  "flow_id": "<uuid>",
  "first_seen": "<ISO-8601 UTC>",
  "last_seen": "<ISO-8601 UTC>",
  "five_tuple": { ... },
  "sensor_id": "diode-sensor-01",
  "capture_interface": "eth1",
  "pipeline_version": "1.0.0",
  ...
}
```

---

## Channel: ingestion.health

Not specified in SIH26145 spec — added for operational monitoring.

| Property | Value |
|---|---|
| Channel name | `ingestion.health` |
| Publisher | Person 3 (heartbeat thread, every 30 seconds) |
| Subscribers | Person 4 (Express API — optional, for pipeline health dashboard) |
| Message format | JSON: `{"status":"ok","sensor_id":"...","ts":"...","active_flows":N}` |

---

## Channels Person 3 does NOT publish to

| Channel | Owner | Why not Person 3 |
|---|---|---|
| `flow.features` | Person 1 + Person 2 (feature extraction service) | Feature extraction is a downstream stage |
| `alert.new` | Person 2 (ensemble scoring) | Alert generation is downstream |

---

## Redis Client Configuration

```python
redis.Redis(
    host                   = REDIS_HOST,        # default: 127.0.0.1
    port                   = REDIS_PORT,        # default: 6379
    socket_connect_timeout = 2,                  # fail fast on connect
    socket_timeout         = 0.1,               # 100ms publish timeout
    retry_on_timeout       = False,             # NEVER retry — blocks capture loop
    decode_responses       = True,
)
```

---

## Health Check

```bash
# Verify Redis is reachable from ingestion service
redis-cli ping
# Expected: PONG

# Watch flow.raw in real time
redis-cli subscribe flow.raw

# Watch all channels
redis-cli monitor
```

---

## Schema Versioning

When the FlowObject schema changes:
1. Bump `schema_version` in `processing/flow_object.py`
2. Update `PIPELINE_VERSION` env var
3. Notify Person 1, Person 2, Person 4 simultaneously
4. Both old and new subscribers must handle the transition version

Current version: `1.0.0`
