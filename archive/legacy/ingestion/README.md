# SIH26145 — Ingestion Service
**Person 3 · Data Ingestion & Packet Processing Engineer**
*Smart India Hackathon 2026 · National Technical Research Organisation (NTRO)*

---

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Copy env template
cp .env.example .env

# 3. Start Redis (if not already running)
docker run -d -p 6379:6379 redis:7-alpine

# 4. Launch
python main.py
```

You will see an interactive terminal menu:

```
  [1] HARDWARE   - Real NIC + data diode  (requires root/sudo)
  [2] SIMULATION - Loopback / software only (no root needed)
  [3] PCAP REPLAY - Offline .pcap file
  [4] DATASET    - Generate labeled training data
  [5] TEST       - Run unit + integration tests
  [q] Quit
```

---

## What This Service Does

This is Stage 1 of the 5-stage pipeline defined in SIH26145 System Architecture Specification v1.0.

```
[Optical Splitter / Data Diode]
          |
          v
[RX-only NIC - promiscuous, no TX]         <- nic_lockdown.sh
          |
          v
[Zeek + Scapy + tshark]                   <- capture/ modules
          |  discard ACK/response frames
          v
[Flow Object Builder]                      <- processing/
          |
          v   publish: flow.raw
[Redis Pub/Sub]                            <- publisher/
```

Core invariant (from NTRO spec Section 5.1):
> No arrow ever crosses back over the data-diode boundary.
> No component reads from Redis. No component opens a socket back toward the monitored network.

---

## Module Map

| File | Purpose |
|---|---|
| main.py | Terminal launcher - interactive mode selection |
| config/settings.py | All config from .env via Pydantic BaseSettings |
| capture/nic_lockdown.sh | Hardens the capture NIC (hardware mode only) |
| capture/zeek_manager.py | Manages Zeek subprocess, tails conn.log / ssl.log |
| capture/tshark_extractor.py | Extracts TLS ClientHello fields for JA3/JA4 |
| capture/scapy_engine.py | Per-packet AsyncSniffer - the primary capture loop |
| capture/config/local.zeek | Passive-only Zeek script |
| processing/discard.py | ACK/response frame discard logic - most critical file |
| processing/flow_assembler.py | 5-tuple stateful flow tracker - emits FlowObjects |
| processing/flow_object.py | Pydantic schema - the ML interface contract |
| processing/tls_parser.py | JA3 hash computation |
| publisher/redis_client.py | Fire-and-forget Redis PUBLISH (never reads) |
| monitoring/metrics.py | Prometheus counters and histograms |
| monitoring/health.py | Flask /health endpoint (port 9101) |
| dataset/generators/*.py | Attack/benign traffic generators (run on separate machine) |
| tests/unit/test_discard.py | 18 unit tests for discard logic |

---

## Run Modes

### 1 - HARDWARE (Production)
- Requires root (sudo python main.py)
- Runs capture/nic_lockdown.sh first
- Captures live traffic from CAPTURE_INTERFACE (e.g. eth1)

### 2 - SIMULATION (Development / Demo)
- No root required, no NIC changes
- Captures on loopback (lo)
- Identical pipeline - same discard, assemble, publish logic
- Test: python dataset/generators/c2_beacon_gen.py --target 127.0.0.1

### 3 - PCAP REPLAY
- No live interface needed
- Reads a .pcap file through the full pipeline

### 4 - DATASET
- Sub-menu of all 7 attack generators
- Generators run on a SEPARATE machine from the capture interface

### 5 - TEST
- Runs pytest tests/ -v --tb=short
- No capture interface required

---

## Environment Variables (key ones)

| Variable | Default | Description |
|---|---|---|
| CAPTURE_INTERFACE | eth1 | NIC name (hardware mode) |
| CAPTURE_MODE | live | live / loopback / pcap_file |
| REDIS_HOST | 127.0.0.1 | Redis server |
| REDIS_CHANNEL_RAW | flow.raw | Channel Person 3 publishes to |
| SENSOR_ID | diode-sensor-01 | Appears in every FlowObject and alert ingestion_meta |
| PIPELINE_VERSION | 1.0.0 | Schema version tag |
| METRICS_PORT | 9101 | Prometheus + health endpoint port |

---

## Dataset Generators

WARNING: Run generators on a SEPARATE test machine, never on the capture machine.

| Generator | Tool | Alert class (Section 6) |
|---|---|---|
| benign_gen.py | iperf3, HTTP | BENIGN (training only) |
| ddos_gen.py | hping3 flood | VOLUMETRIC_DDOS |
| slowloris_gen.py | Python sockets | DATA_EXFILTRATION |
| scan_gen.py | hping3 SYN sweep | PORT_SCAN |
| dns_tunnel_gen.py | dnscat2 / iodine / Python | DNS_TUNNELING |
| dga_gen.py | Python (Conficker + Cryptolocker) | DGA_DOMAIN |
| c2_beacon_gen.py | Python sockets | BOTNET_C2_BEACONING |

---

## Monitoring

- Health:  curl http://localhost:9101/health
- Metrics: curl http://localhost:9101/metrics | grep ingestion_
- Redis:   redis-cli monitor | grep flow.raw

---

## Naming Conventions

See docs/NAMING_CONVENTIONS.md for the full audit of every name against the SIH26145 spec document.
See docs/REDIS_CONTRACT.md for the Redis channel and message format spec.
See docs/FLOW_OBJECT_SCHEMA.md for the complete FlowObject field reference.
