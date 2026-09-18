# FlowObject Schema Reference
## SIH26145 — Person 3 / ML Interface Contract
### Schema Version: 1.0.0

This document is the authoritative reference for the FlowObject JSON schema
published to Redis channel `flow.raw` by Person 3 and consumed by Person 1 and Person 2.

DO NOT change field names without:
1. Bumping schema_version
2. Updating PIPELINE_VERSION env var
3. Notifying Person 1, Person 2, and Person 4

---

## Top-Level Fields

| Field | Type | Required | Description |
|---|---|---|---|
| `schema_version` | string | YES | Always "1.0.0" — bump on breaking changes |
| `flow_id` | string (UUID v4) | YES | Stable identifier. Correlates this FlowObject to alerts across all pipeline stages |
| `first_seen` | string (ISO-8601 UTC) | YES | Timestamp of the first packet in this flow |
| `last_seen` | string (ISO-8601 UTC) | YES | Timestamp of the last packet in this flow |
| `five_tuple` | object | YES | Network identity of the flow (see below) |
| `duration_s` | float | YES | `last_seen - first_seen` in seconds |
| `total_packets` | integer | YES | Total packet count in this flow |
| `total_bytes` | integer | YES | Total byte count (bytes_in only — see bytes_out_proxy) |
| `packet_sizes` | array[int] | YES | Per-packet sizes in bytes. Capped at 50 samples. Used by Person 2 LSTM |
| `inter_arrival_times` | array[float] | YES | Seconds between consecutive packets. Capped at 50 samples. C2 beaconing signal |
| `tcp_flags_seen` | array[string] | YES | TCP flags observed, e.g. ["S","P","A","F"]. Empty for UDP/ICMP |
| `bytes_in` | integer | YES | Bytes observed (inbound mirror — all bytes we can see) |
| `bytes_out_proxy` | integer | YES | ALWAYS 0. Cannot observe outbound under data diode. See note below |
| `tls_meta` | object or null | NO | Present for TCP flows to port 443/8443. See TLS Meta below |
| `dns_meta` | object or null | NO | Present for UDP/53 and DNS-over-TCP flows. See DNS Meta below |
| `zeek_conn_state` | string or null | NO | Zeek connection state code (SF, S0, REJ, S1, RSTO, etc.) |
| `zeek_uid` | string or null | NO | Zeek connection UID for cross-log correlation |
| `sensor_id` | string | YES | Sensor identifier. Becomes `ingestion_meta.sensor_id` in the alert schema |
| `capture_interface` | string | YES | NIC name. Becomes `ingestion_meta.capture_interface` in the alert schema |
| `pipeline_version` | string | YES | Version tag. Becomes `ingestion_meta.pipeline_version` in the alert schema |

### Note on bytes_out_proxy = 0
Under a physical data diode / optical splitter, the monitoring enclave receives
only a one-way copy of traffic. Outbound traffic from monitored hosts is NOT
observable. Person 1 and Person 2 must not use bytes_out_proxy to compute
asymmetric_byte_ratio — use bytes_in relative to packet_sizes or duration_s instead.

---

## five_tuple Object

| Field | Type | Values |
|---|---|---|
| `src_ip` | string | IPv4 or IPv6 source address |
| `dst_ip` | string | IPv4 or IPv6 destination address |
| `src_port` | integer | Source port (0 for ICMP) |
| `dst_port` | integer | Destination port (0 for ICMP) |
| `protocol` | string | "TCP" / "TCP/TLS" / "UDP" / "UDP/QUIC" / "ICMP" |

Protocol assignment rules:
- Port 443 or 8443 on either side → "TCP/TLS" or "UDP/QUIC"
- UDP port 53 → "UDP" (DNS is handled in dns_meta)
- All other TCP → "TCP"
- All other UDP → "UDP"

---

## tls_meta Object (nullable)

Populated by tshark_extractor.py from TLS ClientHello fields.
All values come from the UNENCRYPTED handshake — no decryption is performed.

| Field | Type | Description |
|---|---|---|
| `tls_version` | string or null | e.g. "TLSv1.3", "TLSv1.2" |
| `cipher_suites` | array[string] or null | ORDERED list of hex cipher IDs. ORDER IS A FINGERPRINT SIGNAL |
| `extensions` | array[string] or null | ORDERED list of extension type numbers |
| `ec_curves` | array[string] or null | Elliptic curve / supported groups list |
| `ja3_raw_string` | string or null | Pre-hash JA3 string. Person 2 can inspect or re-hash |
| `ja3_fingerprint` | string or null | MD5 of ja3_raw_string (32 hex chars) |
| `ja4_fingerprint` | string or null | JA4 hash (if computed) |
| `record_length` | integer or null | TLS record byte length |
| `is_quic` | boolean | True if source was a QUIC Initial packet |

JA3 raw string format:
```
"{tls_version_decimal},{cipher_suites_dash_separated},{extensions_dash_separated},{ec_curves_dash_separated},{ec_point_formats_dash_separated}"
```
GREASE values (RFC 8701) are filtered out before hashing.

---

## dns_meta Object (nullable)

Populated by Scapy's DNS layer parsing inside flow_assembler.py.
Only query frames are processed (DNS QR bit = 0).
Responses are not seen in read-only mode (expected behaviour).

| Field | Type | Description |
|---|---|---|
| `query_name` | string or null | Raw FQDN as observed on wire. Person 1 computes Shannon entropy on this |
| `query_type` | string or null | "A" / "AAAA" / "TXT" / "CNAME" / "NULL" / "PTR" / "SRV" |
| `query_length` | integer or null | len(query_name) |
| `answer_count` | integer | Usually 0 — response packets not seen in read-only mode |
| `answer_ips` | array[string] or null | IPs from any observed answer records (rare in read-only) |

---

## Zeek Connection State Codes

Zeek conn_state values you will see in zeek_conn_state:

| State | Meaning | Common attack scenario |
|---|---|---|
| SF | Normal SYN+data+FIN (completed) | Benign, exfiltration |
| S0 | SYN only, no reply seen | Port scan (read-only: reply not visible) |
| S1 | SYN+ACK seen, but no FIN | Slowloris, slow connections |
| REJ | SYN+RST | Closed port scan |
| RSTO | RST by originator | Connection reset |
| OTH | No SYN seen | Captured mid-flow |

---

## Complete Example: C2 Beaconing Flow

```json
{
  "schema_version": "1.0.0",
  "flow_id": "9c1f2a3e-77b4-4e2d-9c6a-1d3f8b0a55e2",
  "first_seen": "2026-08-28T06:42:11.000Z",
  "last_seen":  "2026-08-28T06:42:11.200Z",
  "five_tuple": {
    "src_ip": "10.44.12.55",
    "dst_ip": "198.51.100.23",
    "src_port": 51322,
    "dst_port": 443,
    "protocol": "TCP/TLS"
  },
  "duration_s": 0.2,
  "total_packets": 4,
  "total_bytes": 296,
  "packet_sizes": [74, 74, 74, 74],
  "inter_arrival_times": [0.0, 0.05, 0.05],
  "tcp_flags_seen": ["S", "P", "A", "F"],
  "bytes_in": 296,
  "bytes_out_proxy": 0,
  "tls_meta": {
    "tls_version": "TLSv1.3",
    "cipher_suites": ["0x1301", "0x1302", "0x1303"],
    "extensions": ["0", "23", "65281", "10", "11", "35", "16", "5", "13", "18"],
    "ec_curves": ["0x001d", "0x0017"],
    "ja3_raw_string": "771,4866-4867-4865,0-23-65281-10-11-35-16-5-13-18,29-23,0",
    "ja3_fingerprint": "6734f37431670b3ab4292b8f60f29984",
    "ja4_fingerprint": null,
    "record_length": 512,
    "is_quic": false
  },
  "dns_meta": null,
  "zeek_conn_state": "SF",
  "zeek_uid": "CmFRHF1NjoUI",
  "sensor_id": "diode-sensor-01",
  "capture_interface": "eth1",
  "pipeline_version": "1.0.0"
}
```

---

## Complete Example: DNS Tunnelling Flow

```json
{
  "schema_version": "1.0.0",
  "flow_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "first_seen": "2026-08-28T07:10:05.000Z",
  "last_seen":  "2026-08-28T07:10:05.050Z",
  "five_tuple": {
    "src_ip": "10.44.12.55",
    "dst_ip": "8.8.8.8",
    "src_port": 54321,
    "dst_port": 53,
    "protocol": "UDP"
  },
  "duration_s": 0.05,
  "total_packets": 1,
  "total_bytes": 120,
  "packet_sizes": [120],
  "inter_arrival_times": [],
  "tcp_flags_seen": [],
  "bytes_in": 120,
  "bytes_out_proxy": 0,
  "tls_meta": null,
  "dns_meta": {
    "query_name": "a2VsZ2VpZmVuLmNvbQ.4921.tunnel.c2.example.com",
    "query_type": "TXT",
    "query_length": 47,
    "answer_count": 0,
    "answer_ips": null
  },
  "zeek_conn_state": "S0",
  "zeek_uid": "DnTunXy8abc",
  "sensor_id": "diode-sensor-01",
  "capture_interface": "eth1",
  "pipeline_version": "1.0.0"
}
```

---

## How ingestion_meta in Alerts is Built

Person 4 (Express API) receives this FlowObject, and when an alert is generated
for this flow by Person 2, Person 4 assembles the `ingestion_meta` object in the
alert schema (Section 6 of the SIH spec) from these FlowObject fields:

```
FlowObject.sensor_id           -->  alert.ingestion_meta.sensor_id
FlowObject.capture_interface   -->  alert.ingestion_meta.capture_interface
FlowObject.pipeline_version    -->  alert.ingestion_meta.pipeline_version
FlowObject.flow_id             -->  alert.flow_id
FlowObject.five_tuple          -->  alert.five_tuple
FlowObject.first_seen          -->  alert.timestamp
```
