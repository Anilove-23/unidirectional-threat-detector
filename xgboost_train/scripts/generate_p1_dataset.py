"""
xgboost_train/scripts/generate_p1_dataset.py
============================================
Generates a static dataset of synthetic FlowObjects to evaluate Person 1's models
(XGBoost flow model & DNS model) on completely unseen data, avoiding training bias.

Classes (5,000 each = 30,000 total):
  1. BENIGN               — Normal web/HTTPS traffic
  2. VOLUMETRIC_DDOS      — High packet rate, short duration
  3. PORT_SCAN            — Tiny flows, S0/REJ states
  4. DATA_EXFILTRATION    — Large payloads, long durations
  5. DGA                  — Random alphanumeric DNS query names
  6. DNS_TUNNELING        — High-entropy long DNS query names (base64-like)

Usage:
    uv run python xgboost_train/scripts/generate_p1_dataset.py
"""

import json
import uuid
import random
import string
import sys
from pathlib import Path
from datetime import datetime, timedelta, timezone

OUTPUT_DIR = Path(__file__).resolve().parent.parent / "dataset"
OUTPUT_FILE = OUTPUT_DIR / "p1_synthetic_evaluation.jsonl"
SAMPLES_PER_CLASS = 5000

# ── Helpers ──────────────────────────────────────────────────────────────────

def _uuid():
    return str(uuid.uuid4())

def _ts(offset_s=0):
    base = datetime(2026, 8, 28, 6, 0, 0, tzinfo=timezone.utc)
    return (base + timedelta(seconds=offset_s)).isoformat().replace("+00:00", "Z")

def _ip():
    return f"{random.randint(10,192)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

# ── Canonical FlowObject builder ─────────────────────────────────────────────

def _flow(*, label, five_tuple, duration_s, total_packets, total_bytes,
          packet_sizes, inter_arrival_times, tcp_flags_seen,
          bytes_in, tls_meta=None, dns_meta=None, zeek_conn_state=None,
          offset_s=0):
    return {
        "schema_version": "1.0.0",
        "flow_id": _uuid(),
        "first_seen": _ts(offset_s),
        "last_seen": _ts(offset_s + duration_s),
        "five_tuple": five_tuple,
        "duration_s": round(duration_s, 6),
        "total_packets": total_packets,
        "total_bytes": total_bytes,
        "packet_sizes": packet_sizes,
        "inter_arrival_times": [round(x, 6) for x in inter_arrival_times],
        "tcp_flags_seen": tcp_flags_seen,
        "bytes_in": bytes_in,
        "bytes_out_proxy": 0,
        "tls_meta": tls_meta,
        "dns_meta": dns_meta,
        "zeek_conn_state": zeek_conn_state,
        "zeek_uid": None,
        "sensor_id": "diode-sensor-01",
        "capture_interface": "eth1",
        "pipeline_version": "1.0.0",
        "collected_label": label,
    }

def _dns(*, query_name, query_type="A"):
    return {
        "query_name": query_name,
        "query_type": query_type,
        "query_length": len(query_name),
        "answer_count": 0,
        "answer_ips": None,
    }

# ── Generators ───────────────────────────────────────────────────────────────

def gen_benign():
    flows = []
    for i in range(SAMPLES_PER_CLASS):
        dur = random.uniform(0.1, 10.0)
        n = random.randint(5, 50)
        avg = random.uniform(200, 1000)
        sizes = [max(54, int(random.gauss(avg, avg * 0.3))) for _ in range(min(n, 50))]
        base_iat = dur / max(n, 1)
        iats = [max(1e-4, abs(random.gauss(base_iat, base_iat * 0.5))) for _ in range(min(n - 1, 49))]
        tb = sum(sizes) + int(avg * max(0, n - 50))
        flows.append(_flow(
            label="BENIGN",
            five_tuple={"src_ip": _ip(), "dst_ip": _ip(),
                        "src_port": random.randint(30000, 65000),
                        "dst_port": random.choice([80, 443]), "protocol": "TCP"},
            duration_s=dur, total_packets=n, total_bytes=tb,
            packet_sizes=sizes, inter_arrival_times=iats,
            tcp_flags_seen=["S", "A", "P", "F"], bytes_in=tb,
            zeek_conn_state="SF", offset_s=i * 0.1,
        ))
    return flows

def gen_benign_dns():
    """Benign DNS queries."""
    flows = []
    normal_domains = ["google.com", "youtube.com", "microsoft.com", "apple.com", "amazon.com", "cloudflare.com"]
    for i in range(SAMPLES_PER_CLASS):
        domain = random.choice(normal_domains)
        qname = f"www.{domain}" if random.random() < 0.5 else domain
        dur = random.uniform(0.01, 0.1)
        n = random.randint(1, 2)
        sizes = [random.randint(60, 100) for _ in range(n)]
        iats = [dur] if n > 1 else []
        tb = sum(sizes)
        flows.append(_flow(
            label="BENIGN",
            five_tuple={"src_ip": _ip(), "dst_ip": "8.8.8.8",
                        "src_port": random.randint(30000, 65000),
                        "dst_port": 53, "protocol": "UDP"},
            duration_s=dur, total_packets=n, total_bytes=tb,
            packet_sizes=sizes, inter_arrival_times=iats,
            tcp_flags_seen=[], bytes_in=tb,
            dns_meta=_dns(query_name=qname),
            zeek_conn_state="S0", offset_s=i,
        ))
    return flows

def gen_ddos():
    """Volumetric DDoS: High packet rates, supporting both micro-bursts and sustained floods."""
    flows = []
    for i in range(SAMPLES_PER_CLASS):
        if random.random() < 0.5:
            # Micro-burst flood (typical of live diode / sensor windows)
            dur = random.uniform(0.001, 0.02)
            n = random.randint(30, 250)
            pkt_size = random.choice([512, 600, 800, 1024])
            sizes = [pkt_size] * min(n, 30)
            tb = pkt_size * n
            iats = [dur / max(n - 1, 1)] * min(n - 1, 29)
        else:
            # Sustained volumetric flood
            dur = random.uniform(0.02, 0.5)
            n = random.randint(500, 5000)
            sizes = [random.randint(64, 128) for _ in range(min(n, 30))]
            iats = [random.uniform(1e-6, 1e-4) for _ in range(min(n - 1, 29))]
            tb = sum(sizes) + int(n * 100)

        flows.append(_flow(
            label="VOLUMETRIC_DDOS",
            five_tuple={"src_ip": _ip(), "dst_ip": _ip(),
                        "src_port": random.randint(1024, 65000),
                        "dst_port": random.choice([80, 443, 8080, 53]), "protocol": "TCP"},
            duration_s=dur, total_packets=n, total_bytes=tb,
            packet_sizes=sizes, inter_arrival_times=iats,
            tcp_flags_seen=["S"], bytes_in=tb,
            zeek_conn_state="S0", offset_s=i,
        ))
    return flows

def gen_portscan():
    """Port Scan: Tiny probe flows (1-3 pkts), S0 or REJ, targeting many ports."""
    flows = []
    for i in range(SAMPLES_PER_CLASS):
        dur = random.uniform(0.00002, 0.002)
        n = random.choice([1, 1, 2, 3])
        sizes = [random.choice([0, 54, 60, 64]) for _ in range(n)]
        iats = [dur] if n > 1 else []
        tb = sum(sizes)
        flows.append(_flow(
            label="PORT_SCAN",
            five_tuple={"src_ip": _ip(), "dst_ip": _ip(),
                        "src_port": random.randint(30000, 65000),
                        "dst_port": random.choice([21, 22, 23, 25, 80, 110, 135, 139, 443, 445, 1433, 2100, 3306, 3389, 8080, random.randint(1, 65535)]), "protocol": "TCP"},
            duration_s=dur, total_packets=n, total_bytes=tb,
            packet_sizes=sizes, inter_arrival_times=iats,
            tcp_flags_seen=["S"], bytes_in=tb,
            zeek_conn_state=random.choice(["S0", "REJ"]), offset_s=i,
        ))
    return flows

def gen_data_exfil():
    """Data Exfiltration: Large payloads and bytes_in, spanning bursts to sustained uploads."""
    flows = []
    for i in range(SAMPLES_PER_CLASS):
        if random.random() < 0.5:
            # Burst upload / exfiltration (live pipeline window scale)
            dur = random.uniform(1.5, 6.0)
            n = random.randint(30, 120)
            avg = random.uniform(1200, 1460)
            sizes = [int(avg)] * min(n, 30)
            tb = int(avg * n)
            base_iat = dur / max(n - 1, 1)
            iats = [round(base_iat * random.uniform(0.7, 1.3), 4) for _ in range(min(n - 1, 29))]
        else:
            # Sustained large-volume upload
            dur = random.uniform(6.0, 120.0)
            n = random.randint(200, 2000)
            avg = random.uniform(1200, 1460)
            sizes = [max(1000, int(random.gauss(avg, 100))) for _ in range(min(n, 30))]
            tb = int(avg * n)
            base_iat = dur / max(n - 1, 1)
            iats = [max(0.001, abs(random.gauss(base_iat, base_iat * 0.2))) for _ in range(min(n - 1, 29))]

        flows.append(_flow(
            label="DATA_EXFILTRATION",
            five_tuple={"src_ip": _ip(), "dst_ip": _ip(),
                        "src_port": random.randint(30000, 65000),
                        "dst_port": random.choice([21, 22, 443, 8080, 52140]), "protocol": "TCP"},
            duration_s=dur, total_packets=n, total_bytes=tb,
            packet_sizes=sizes, inter_arrival_times=iats,
            tcp_flags_seen=["S", "P", "A", "F"], bytes_in=tb,
            zeek_conn_state="SF", offset_s=i,
        ))
    return flows

def gen_dga():
    """DGA: Pseudo-random algorithmic domain names (Conficker, Cryptolocker, etc.)."""
    flows = []
    tlds = ["com", "net", "org", "info", "biz", "name", "mobi", "ru", "top", "xyz"]
    dga_samples = [
        "wxsnapghers.name", "kxyzypkvyta.name", "blackstone122.top",
        "yhgxkzydcni.info", "qbcjejutuja.org", "firewind834.biz",
        "yzaludqdale.info", "grknexarqfa.mobi", "xopqlanbvsd.biz", "zxcvbnmasdf.org",
        "pqwoeiruty.biz", "lkjhgfdsa.ru", "mnbvcxzlk.cc", "qazwsxedc.top",
        "rfvtgbyhn.info", "ujmikolp.biz", "zaqxswcde.org", "plmkoijn.xyz"
    ]
    for i in range(SAMPLES_PER_CLASS):
        if random.random() < 0.3:
            qname = random.choice(dga_samples)
        else:
            payload = "".join(random.choices(string.ascii_lowercase + string.digits, k=random.randint(9, 20)))
            tld = random.choice(tlds)
            qname = f"{payload}.{tld}"
        
        dur = random.uniform(0.01, 0.08)
        n = 2
        sz = random.randint(60, 100)
        sizes = [sz, sz]
        iats = [dur]
        tb = sz * 2
        flows.append(_flow(
            label="DGA",
            five_tuple={"src_ip": _ip(), "dst_ip": "8.8.8.8",
                        "src_port": random.randint(30000, 65000),
                        "dst_port": 53, "protocol": "UDP"},
            duration_s=dur, total_packets=n, total_bytes=tb,
            packet_sizes=sizes, inter_arrival_times=iats,
            tcp_flags_seen=[], bytes_in=tb,
            dns_meta=_dns(query_name=qname),
            zeek_conn_state="SF", offset_s=i,
        ))
    return flows

def gen_dns_tunneling():
    """DNS Tunneling: Base32 / Hex encoded subdomain queries."""
    flows = []
    for i in range(SAMPLES_PER_CLASS):
        if random.random() < 0.5:
            chunk = "".join(random.choices("abcdefghijklmnopqrstuvwxyz234567", k=random.randint(28, 42)))
            qname = f"{chunk}.tunnel.c2.example.com"
        else:
            hex_data = "".join(random.choices("0123456789abcdef", k=random.randint(24, 48)))
            session = random.randint(1000, 9999)
            qname = f"{hex_data}.{session}.tunnel.c2.example.com"
        
        dur = random.uniform(0.02, 0.1)
        n = 2
        sz = random.randint(80, 180)
        sizes = [sz, sz]
        iats = [dur]
        tb = sz * 2
        flows.append(_flow(
            label="DNS_TUNNELING",
            five_tuple={"src_ip": _ip(), "dst_ip": "1.1.1.1",
                        "src_port": random.randint(30000, 65000),
                        "dst_port": 53, "protocol": "UDP"},
            duration_s=dur, total_packets=n, total_bytes=tb,
            packet_sizes=sizes, inter_arrival_times=iats,
            tcp_flags_seen=[], bytes_in=tb,
            dns_meta=_dns(query_name=qname, query_type="TXT"),
            zeek_conn_state="SF", offset_s=i,
        ))
    return flows


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    generators = [
        ("BENIGN", gen_benign),
        ("BENIGN_DNS", gen_benign_dns),
        ("VOLUMETRIC_DDOS", gen_ddos),
        ("PORT_SCAN", gen_portscan),
        ("DATA_EXFILTRATION", gen_data_exfil),
        ("DGA", gen_dga),
        ("DNS_TUNNELING", gen_dns_tunneling),
    ]

    all_flows = []
    for name, fn in generators:
        print(f"[*] Generating {SAMPLES_PER_CLASS} {name} flows...")
        all_flows.extend(fn())

    random.shuffle(all_flows)
    
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for flow in all_flows:
            f.write(json.dumps(flow) + "\n")

    print(f"\n[+] Saved {len(all_flows)} synthetic evaluation flows to: {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
