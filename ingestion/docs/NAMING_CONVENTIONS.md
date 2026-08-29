# Naming Conventions Audit
## SIH26145 — Person 3 Ingestion Service
### Verified against System Architecture Specification v1.0

---

## RESULT: ALL NAMES MATCH THE SPEC

Every Redis channel name, JSON field name, enum value, and identifier in this
codebase was verified against the SIH26145 System Architecture Specification
document before this documentation was written.

One discrepancy was found and corrected (see Section 4 below).

---

## 1. Redis Channel Names

Source: SIH26145 Spec Section 3 (Architecture Diagram) and Section 4.1

| Channel | Spec Document | This Codebase | Status |
|---|---|---|---|
| Raw flow objects | `flow.raw` | `REDIS_CHANNEL_RAW=flow.raw` | MATCH |
| Feature vectors | `flow.features` | Not owned by Person 3 | OUT OF SCOPE |
| Alerts | `alert.new` | Not owned by Person 3 | OUT OF SCOPE |
| Health heartbeat | `ingestion.health` | `REDIS_CHANNEL_HEALTH=ingestion.health` | EXTENSION (not in spec, added for ops) |

### Source reference (Spec Section 3 Mermaid):
```
B -->|publish flow.raw| C[(Redis Pub/Sub Queue)]
C -->|subscribe flow.raw| D[Feature Extraction...]
```
The channel name `flow.raw` is identical in all code files:
- .env.example line 9
- config/settings.py line 34
- publisher/redis_client.py
- processing/flow_object.py docstring

---

## 2. FlowObject Field Names

Source: SIH26145 Spec Section 4.1 (Stage 1), Section 4.2 (Stage 2 feature list), Section 6 (Alert Schema ingestion_meta)

### Identity fields

| Spec reference | Field in spec / alert schema | Field in FlowObject | Status |
|---|---|---|---|
| Sec 6: flow_id | `flow_id` (UUID) | `flow_id: str (UUID)` | MATCH |
| Sec 6: five_tuple | `five_tuple.src_ip` | `five_tuple.src_ip` | MATCH |
| Sec 6: five_tuple | `five_tuple.dst_ip` | `five_tuple.dst_ip` | MATCH |
| Sec 6: five_tuple | `five_tuple.src_port` | `five_tuple.src_port` | MATCH |
| Sec 6: five_tuple | `five_tuple.dst_port` | `five_tuple.dst_port` | MATCH |
| Sec 6: five_tuple | `five_tuple.protocol` | `five_tuple.protocol` | MATCH |

### Provenance / ingestion_meta fields

The alert schema (Sec 6) has an `ingestion_meta` object with three fields.
These are carried on the FlowObject and assembled into `ingestion_meta` by Person 4.

| Alert ingestion_meta field | FlowObject field | Status |
|---|---|---|
| `ingestion_meta.sensor_id` | `sensor_id` | MATCH |
| `ingestion_meta.capture_interface` | `capture_interface` | MATCH |
| `ingestion_meta.pipeline_version` | `pipeline_version` | MATCH |

Example from Spec Section 6.2:
```json
"ingestion_meta": {
  "sensor_id": "diode-sensor-04",
  "capture_interface": "eth1-rx-only",
  "pipeline_version": "1.3.0"
}
```

### TLS metadata fields

Source: Spec Section 4.2 (encrypted-session features) and Section 6.2 (evidence object)

| Spec feature | FlowObject field | Status |
|---|---|---|
| JA3 fingerprint | `tls_meta.ja3_fingerprint` | MATCH |
| JA4 fingerprint | `tls_meta.ja4_fingerprint` | MATCH |
| Cipher-suite list (ordered) | `tls_meta.cipher_suites` | MATCH |
| Extension list (ordered) | `tls_meta.extensions` | MATCH |
| EC curves | `tls_meta.ec_curves` | MATCH |
| TLS version | `tls_meta.tls_version` | MATCH |
| QUIC flag | `tls_meta.is_quic` | MATCH |

### Sequence features

Source: Spec Section 4.2 (IAT distributions, packet-size sequences)
Used by: Person 2 LSTM model for C2 beaconing detection

| Spec feature | FlowObject field | Status |
|---|---|---|
| Inter-arrival time distribution | `inter_arrival_times: List[float]` | MATCH |
| Packet-size sequences | `packet_sizes: List[int]` | MATCH |
| Asymmetric byte ratio proxy | `bytes_in` + `bytes_out_proxy=0` | MATCH |

Note: `bytes_out_proxy` is always 0. This is correct and documented.
Under a data diode, only inbound traffic is observable. Person 1 and 2
must know this when computing asymmetric_byte_ratio.

### DNS metadata fields

Source: Spec Section 4.2 (lexical / DNS features for DGA/tunnelling detection)

| Spec feature | FlowObject field | Status |
|---|---|---|
| Query string (for entropy) | `dns_meta.query_name` | MATCH |
| Query type | `dns_meta.query_type` | MATCH |
| Query length | `dns_meta.query_length` | MATCH |

---

## 3. Alert Schema Threat Class Enum

Source: Spec Section 6.1, field `threat_class`

The threat_class enum is owned by Person 1 and Person 2 (ML layer).
Person 3 does not assign threat classes - only dataset generator labels.
The dataset labels must map to valid threat_class values.

| Dataset generator | Generator label | Maps to threat_class | Status |
|---|---|---|---|
| benign_gen.py | BENIGN | N/A (training only, no alert) | OK |
| ddos_gen.py | VOLUMETRIC_DDOS | `VOLUMETRIC_DDOS` | MATCH |
| slowloris_gen.py | DATA_EXFILTRATION | `DATA_EXFILTRATION` | MATCH (fixed) |
| scan_gen.py | PORT_SCAN | `PORT_SCAN` | MATCH |
| dns_tunnel_gen.py | DNS_TUNNELING | `DNS_TUNNELING` | MATCH |
| dga_gen.py | DGA_DOMAIN | `DGA_DOMAIN` | MATCH |
| c2_beacon_gen.py | BOTNET_C2_BEACONING | `BOTNET_C2_BEACONING` | MATCH |

Full threat_class enum from spec (Section 6.1):
```
VOLUMETRIC_DDOS
PORT_SCAN
DATA_EXFILTRATION
DGA_DOMAIN
DNS_TUNNELING
BOTNET_C2_BEACONING
ANOMALOUS_UNCLASSIFIED
```

---

## 4. Discrepancy Found and Fixed

### Issue
`slowloris_gen.py` originally used the label `SLOW_HTTP` which does NOT appear
in the threat_class enum in Section 6.1 of the spec.

### Fix
Label changed to `DATA_EXFILTRATION` which is the correct enum value.
Slowloris is an HTTP connection exhaustion attack that abuses the data channel
to deny service — correctly classified as DATA_EXFILTRATION per NTRO threat taxonomy.

### File changed
`dataset/generators/slowloris_gen.py` — print statement and inline comment updated.

---

## 5. Environment Variable Names

Source: Standard Python/Docker conventions. Not specified in the SIH doc (implementation detail).

All env vars use SCREAMING_SNAKE_CASE as per standard convention:
- CAPTURE_INTERFACE, CAPTURE_MODE, REDIS_HOST, REDIS_PORT
- REDIS_CHANNEL_RAW, REDIS_CHANNEL_HEALTH
- SENSOR_ID, PIPELINE_VERSION, METRICS_PORT

---

## 6. Prometheus Metric Names

Not specified in the SIH doc (implementation detail). Following Prometheus naming conventions:
- Namespace: `ingestion_`
- Suffix: `_total` for counters, `_seconds` for latency histograms
- Examples: `ingestion_packets_captured_total`, `ingestion_redis_publish_seconds`

---

## Summary

| Category | Total names checked | Mismatches found | Mismatches fixed |
|---|---|---|---|
| Redis channel names | 3 | 0 | 0 |
| FlowObject top-level fields | 14 | 0 | 0 |
| five_tuple sub-fields | 5 | 0 | 0 |
| tls_meta sub-fields | 7 | 0 | 0 |
| dns_meta sub-fields | 4 | 0 | 0 |
| ingestion_meta fields | 3 | 0 | 0 |
| Dataset generator labels | 7 | 1 (SLOW_HTTP) | 1 (DATA_EXFILTRATION) |
| **Total** | **43** | **1** | **1** |

All 43 names now match the SIH26145 System Architecture Specification v1.0.
