# Redis Channels Contract

Joint contract between **Ingestion (Person 3)**, **AI/ML Pipeline (Person 1 & 2)**, and **API/Streaming Backend (Person 4)**.

---

## 1. Overview

Redis operates in **Pub/Sub mode** as an event hub between streaming stages.

```
[Ingestion (Person 3)] ---> Redis Channel: flow.raw ---> [AI/ML Engine (Person 1 & 2)]
[AI/ML Engine (Person 1 & 2)] ---> Redis Channel: alert.new ---> [Express/WS Server (Person 4)]
```

---

## 2. Channels Specification

### 2.1 Channel `flow.raw`
- **Publisher**: Ingestion / Packet Parser (Person 3)
- **Subscribers**: AI/ML Inference Pipeline (Person 1 & 2), Backend Data Archival (Person 4 - optional)
- **Message Format**: Valid UTF-8 JSON string matching [`ingestion/flow_schema.json`](../ingestion/flow_schema.json)
- **Delivery Guarantees**: Best-effort pub/sub. Non-blocking to avoid diode interface backpressure.

### 2.2 Channel `alert.new`
- **Publisher**: Threat Detection Engine (Person 1 & 2)
- **Subscribers**: Express API & WebSocket Broadcaster (Person 4)
- **Message Format**: Valid UTF-8 JSON string matching [`ml/alert_schema.json`](../ml/alert_schema.json)
- **Delivery Guarantees**: Real-time push; Person 4 backend persists to database immediately upon receipt.

---

## 3. Envelope & Payload Rules

1. All messages sent across Redis channels **MUST** be serialized JSON strings.
2. Messages must validate against their respective schema contracts before publishing.
3. Publishers **MUST NOT** send binary buffers or non-JSON payloads.
4. On subscriber JSON parsing error, Person 4 backend logs the error gracefully without crashing the subscriber process.

---

## 4. Reconnection & Backpressure Guidelines

- If the Person 4 subscriber loses connection to Redis, `ioredis` attempts exponential reconnects.
- During subscriber downtime, missed alerts can be queried via the REST historical API (`/api/alerts/search`) once reconnected, using DB timestamp indexing.
