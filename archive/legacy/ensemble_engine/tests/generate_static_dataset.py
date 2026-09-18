"""
ensemble_engine/tests/generate_static_dataset.py
=================================================
Generates a static 40,000+ entry balanced JSONL dataset of synthetic FlowObjects
to evaluate Person 2's models (Isolation Forest, Autoencoder, LSTM).

Every entry is a byte-exact match of the FlowObject v1.0.0 schema that Person 3's
ingestion pipeline publishes to Redis `flow.raw` — same keys, same types, same
nullability rules. See ingestion/docs/FLOW_OBJECT_SCHEMA.md.

Classes (8,000 each = 40,000 total):
  1. BENIGN               — Normal web/HTTPS traffic with standard TLS
  2. BOTNET_C2_BEACONING  — Low-and-slow periodic keep-alives
  3. ZERO_DAY_ANOMALOUS   — Statistically unusual flows (outliers)
  4. TLS_ANOMALY          — Encrypted traffic with suspicious JA3/cipher metadata
  5. DNS_TUNNELING        — DNS flows with high-entropy long query names

Usage:
    uv run python ensemble_engine/tests/generate_static_dataset.py
"""

import json
import uuid
import random
import string
import sys
from pathlib import Path
from datetime import datetime, timedelta, timezone

OUTPUT_DIR = Path(__file__).resolve().parent / "dataset"
OUTPUT_FILE = OUTPUT_DIR / "person2_test_dataset.jsonl"
SAMPLES_PER_CLASS = 8000

# ── Helpers ──────────────────────────────────────────────────────────────────

def _uuid():
    return str(uuid.uuid4())

def _ts(offset_s=0):
    base = datetime(2026, 8, 28, 6, 0, 0, tzinfo=timezone.utc)
    return (base + timedelta(seconds=offset_s)).isoformat().replace("+00:00", "Z")

def _ip():
    return f"{random.randint(10,192)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

# ── TLS constants ────────────────────────────────────────────────────────────

BROWSER_CIPHERS = ["0x1301", "0x1302", "0x1303", "0xc02c", "0xc02b",
                   "0xc030", "0xc02f", "0xcca9", "0xcca8"]
BROWSER_EXTENSIONS = ["0", "23", "65281", "10", "11", "35", "16", "5", "13",
                      "18", "51", "45", "43", "27"]
BROWSER_CURVES = ["0x001d", "0x0017", "0x0018"]

MALWARE_CIPHERS = ["0x002f", "0x0035", "0x000a", "0x00ff"]
MALWARE_EXTENSIONS = ["0", "23"]
MALWARE_CURVES = ["0x0017"]

# ── Canonical FlowObject builder ─────────────────────────────────────────────
# Every field listed in FLOW_OBJECT_SCHEMA.md v1.0.0, in spec order.

def _flow(*, label, five_tuple, duration_s, total_packets, total_bytes,
          packet_sizes, inter_arrival_times, tcp_flags_seen,
          bytes_in, tls_meta=None, dns_meta=None, zeek_conn_state=None,
          offset_s=0):
    """Build a complete FlowObject dict identical to live ingestion output."""
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

def _tls(*, tls_version="TLSv1.3", cipher_suites=None, extensions=None,
         ec_curves=None, is_quic=False):
    """Build a tls_meta sub-object with every schema field present."""
    return {
        "tls_version": tls_version,
        "cipher_suites": cipher_suites or [],
        "extensions": extensions or [],
        "ec_curves": ec_curves or [],
        "ja3_raw_string": None,
        "ja3_fingerprint": None,
        "ja4_fingerprint": None,
        "record_length": None,
        "is_quic": is_quic,
    }

def _dns(*, query_name, query_type="A"):
    """Build a dns_meta sub-object with every schema field present."""
    return {
        "query_name": query_name,
        "query_type": query_type,
        "query_length": len(query_name),
        "answer_count": 0,
        "answer_ips": None,
    }

# ── Generators ───────────────────────────────────────────────────────────────

def gen_benign():
    """Normal HTTPS web browsing — variable sizes, irregular timing, standard TLS."""
    flows = []
    for i in range(SAMPLES_PER_CLASS):
        dur = random.uniform(0.1, 30.0)
        n = random.randint(5, 200)
        avg = random.uniform(200, 1400)
        sizes = [max(54, int(random.gauss(avg, avg * 0.3))) for _ in range(min(n, 50))]
        base_iat = dur / max(n, 1)
        iats = [max(1e-4, abs(random.gauss(base_iat, base_iat * 0.5)))
                for _ in range(min(n - 1, 49))]
        tb = sum(sizes) + int(avg * max(0, n - 50))

        nc = random.randint(5, len(BROWSER_CIPHERS))
        ne = random.randint(8, len(BROWSER_EXTENSIONS))

        flows.append(_flow(
            label="BENIGN",
            five_tuple={"src_ip": _ip(), "dst_ip": _ip(),
                        "src_port": random.randint(30000, 65000),
                        "dst_port": random.choice([80, 443, 8080, 8443]),
                        "protocol": "TCP/TLS"},
            duration_s=dur, total_packets=n, total_bytes=tb,
            packet_sizes=sizes, inter_arrival_times=iats,
            tcp_flags_seen=["S", "A", "P", "F"], bytes_in=tb,
            tls_meta=_tls(
                cipher_suites=random.sample(BROWSER_CIPHERS, nc),
                extensions=random.sample(BROWSER_EXTENSIONS, ne),
                ec_curves=random.sample(BROWSER_CURVES, random.randint(2, 3))),
            zeek_conn_state="SF", offset_s=i * 0.5,
        ))
    return flows


def gen_c2_beaconing():
    """Low-and-slow C2 keep-alive — tiny fixed packets, highly regular IATs."""
    flows = []
    for i in range(SAMPLES_PER_CLASS):
        interval = random.uniform(10, 120)
        jitter = random.uniform(0.01, 0.15)
        n = random.randint(4, 50)
        base = random.choice([54, 64, 74, 128])
        sizes = [base + random.randint(-2, 2) for _ in range(n)]
        iats = [max(0.1, interval + random.gauss(0, interval * jitter))
                for _ in range(n - 1)]
        dur = sum(iats)
        tb = sum(sizes)

        flows.append(_flow(
            label="BOTNET_C2_BEACONING",
            five_tuple={"src_ip": _ip(), "dst_ip": _ip(),
                        "src_port": random.randint(30000, 65000),
                        "dst_port": 443, "protocol": "TCP/TLS"},
            duration_s=dur, total_packets=n, total_bytes=tb,
            packet_sizes=sizes, inter_arrival_times=iats,
            tcp_flags_seen=["S", "P", "A", "F"], bytes_in=tb,
            tls_meta=_tls(
                tls_version=random.choice(["TLSv1.2", "TLSv1.3"]),
                cipher_suites=random.sample(MALWARE_CIPHERS, random.randint(1, 3)),
                extensions=MALWARE_EXTENSIONS[:],
                ec_curves=MALWARE_CURVES[:]),
            zeek_conn_state="SF", offset_s=i,
        ))
    return flows


def gen_zero_day_anomalous():
    """Statistically unusual flows — outliers for Isolation Forest / Autoencoder."""
    flows = []
    for i in range(SAMPLES_PER_CLASS):
        t = random.choice(["extreme_rate", "huge_pkt", "tiny_burst",
                           "bursty_timing", "icmp_flood", "odd_port"])

        if t == "extreme_rate":
            dur, n = random.uniform(0.01, 0.5), random.randint(500, 5000)
            sizes = [random.randint(40, 100) for _ in range(min(n, 50))]
            iats = [random.uniform(1e-5, 1e-3) for _ in range(min(n-1, 49))]
        elif t == "huge_pkt":
            dur, n = random.uniform(1, 10), random.randint(3, 20)
            sizes = [random.randint(8000, 65535) for _ in range(min(n, 50))]
            iats = [random.uniform(0.1, 2.0) for _ in range(min(n-1, 49))]
        elif t == "tiny_burst":
            dur, n = random.uniform(0.001, 0.05), random.randint(100, 1000)
            sizes = [random.randint(20, 54) for _ in range(min(n, 50))]
            iats = [random.uniform(1e-6, 1e-4) for _ in range(min(n-1, 49))]
        elif t == "bursty_timing":
            dur, n = random.uniform(10, 60), random.randint(10, 50)
            sizes = [random.randint(100, 3000) for _ in range(min(n, 50))]
            iats = [random.uniform(5, 30) if random.random() < 0.3
                    else random.uniform(1e-4, 0.01)
                    for _ in range(min(n-1, 49))]
        elif t == "icmp_flood":
            dur, n = random.uniform(0.5, 5), random.randint(50, 500)
            sizes = [random.randint(28, 84) for _ in range(min(n, 50))]
            iats = [random.uniform(0.001, 0.05) for _ in range(min(n-1, 49))]
        else:  # odd_port
            dur, n = random.uniform(0.1, 5), random.randint(5, 100)
            sizes = [random.choice([1, 2, 3, 9999, 15000, 40000])
                     for _ in range(min(n, 50))]
            iats = [random.uniform(0.0, 5.0) for _ in range(min(n-1, 49))]

        tb = sum(sizes) + int(n * 100)
        proto = ("ICMP" if t == "icmp_flood"
                 else "UDP" if t == "odd_port"
                 else random.choice(["TCP", "TCP/TLS"]))
        dp = (0 if proto == "ICMP"
              else random.randint(1, 65535))

        flows.append(_flow(
            label="ZERO_DAY_ANOMALOUS",
            five_tuple={"src_ip": _ip(), "dst_ip": _ip(),
                        "src_port": random.randint(1024, 65000),
                        "dst_port": dp, "protocol": proto},
            duration_s=dur, total_packets=n, total_bytes=tb,
            packet_sizes=sizes, inter_arrival_times=iats,
            tcp_flags_seen=([] if proto == "ICMP"
                            else random.sample(["S","A","P","F","R","U"],
                                               random.randint(1, 4))),
            bytes_in=tb, tls_meta=None, dns_meta=None,
            zeek_conn_state=random.choice(["OTH", "S0", "REJ", None]),
            offset_s=i,
        ))
    return flows


def gen_tls_anomaly():
    """Encrypted-traffic anomalies — suspicious TLS metadata (JA3 signal)."""
    flows = []
    for i in range(SAMPLES_PER_CLASS):
        v = random.choice(["old_tls", "minimal", "quic_abuse", "weird_ext"])

        dur = random.uniform(0.5, 15)
        n = random.randint(5, 100)
        avg = random.uniform(100, 800)
        sizes = [max(54, int(random.gauss(avg, 100))) for _ in range(min(n, 50))]
        base_iat = dur / max(n, 1)
        iats = [max(0.001, abs(random.gauss(base_iat, base_iat * 0.4)))
                for _ in range(min(n-1, 49))]
        tb = sum(sizes)

        if v == "old_tls":
            tls = _tls(tls_version=random.choice(["TLSv1.0","TLSv1.1","SSLv3"]),
                       cipher_suites=random.sample(
                           ["0x000a","0x002f","0x0035","0x003c","0x009c","0x009d"],
                           random.randint(1, 4)),
                       extensions=[str(random.randint(0, 5))],
                       ec_curves=[])
        elif v == "minimal":
            tls = _tls(tls_version="TLSv1.2",
                       cipher_suites=[random.choice(MALWARE_CIPHERS)],
                       extensions=[], ec_curves=[])
        elif v == "quic_abuse":
            tls = _tls(tls_version="TLSv1.3",
                       cipher_suites=[f"0x{random.randint(1,0xffff):04x}"
                                      for _ in range(random.randint(15, 40))],
                       extensions=[str(random.randint(0, 65535))
                                   for _ in range(random.randint(20, 50))],
                       ec_curves=[f"0x{random.randint(1,0xff):04x}"
                                  for _ in range(random.randint(5, 15))],
                       is_quic=True)
        else:  # weird_ext
            tls = _tls(tls_version=random.choice(["TLSv1.2","TLSv1.3"]),
                       cipher_suites=random.sample(
                           MALWARE_CIPHERS + BROWSER_CIPHERS, random.randint(2, 5)),
                       extensions=[str(random.randint(50000, 65535))
                                   for _ in range(random.randint(1, 5))],
                       ec_curves=[f"0x{random.randint(0x100,0xfff):04x}"])

        proto = "UDP/QUIC" if v == "quic_abuse" else "TCP/TLS"

        flows.append(_flow(
            label="TLS_ANOMALY",
            five_tuple={"src_ip": _ip(), "dst_ip": _ip(),
                        "src_port": random.randint(30000, 65000),
                        "dst_port": random.choice([443, 8443, 993, 995, 4443]),
                        "protocol": proto},
            duration_s=dur, total_packets=n, total_bytes=tb,
            packet_sizes=sizes, inter_arrival_times=iats,
            tcp_flags_seen=["S", "A", "P", "F"], bytes_in=tb,
            tls_meta=tls,
            zeek_conn_state="SF", offset_s=i,
        ))
    return flows


def gen_dns_tunneling():
    """DNS tunneling — high-entropy, long query names encoding data."""
    tunnel_domains = ["tunnel.c2.example.com", "dns.exfil.evil.net",
                      "cmd.botnet.io", "data.covert.channel.org",
                      "x.hidden.service.net"]
    flows = []
    for i in range(SAMPLES_PER_CLASS):
        domain = random.choice(tunnel_domains)
        v = random.choice(["b64", "hex", "random"])

        if v == "b64":
            payload = ''.join(random.choices(
                string.ascii_letters + string.digits + "+/=",
                k=random.randint(20, 60)))
            qname = f"{payload}.{random.randint(1000,9999)}.{domain}"
        elif v == "hex":
            payload = ''.join(random.choices("0123456789abcdef",
                                            k=random.randint(16, 48)))
            qname = f"{payload}.{domain}"
        else:
            labels = [''.join(random.choices(
                string.ascii_lowercase + string.digits,
                k=random.randint(6, 15)))
                for _ in range(random.randint(3, 8))]
            qname = '.'.join(labels) + '.' + domain

        dur = random.uniform(0.01, 0.5)
        n = random.randint(1, 5)
        sizes = [random.randint(60, 512) for _ in range(min(n, 50))]
        iats = [random.uniform(0.001, 0.1) for _ in range(max(n-1, 0))]
        tb = sum(sizes)

        flows.append(_flow(
            label="DNS_TUNNELING",
            five_tuple={"src_ip": _ip(),
                        "dst_ip": random.choice(["8.8.8.8","8.8.4.4","1.1.1.1"]),
                        "src_port": random.randint(30000, 65000),
                        "dst_port": 53, "protocol": "UDP"},
            duration_s=dur, total_packets=n, total_bytes=tb,
            packet_sizes=sizes, inter_arrival_times=iats,
            tcp_flags_seen=[], bytes_in=tb,
            tls_meta=None,
            dns_meta=_dns(query_name=qname,
                          query_type=random.choice(["TXT","CNAME","MX","A"])),
            zeek_conn_state="S0", offset_s=i * 0.1,
        ))
    return flows


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    generators = [
        ("BENIGN",              gen_benign),
        ("BOTNET_C2_BEACONING", gen_c2_beaconing),
        ("ZERO_DAY_ANOMALOUS",  gen_zero_day_anomalous),
        ("TLS_ANOMALY",         gen_tls_anomaly),
        ("DNS_TUNNELING",       gen_dns_tunneling),
    ]

    all_flows = []
    for name, fn in generators:
        print(f"[*] Generating {SAMPLES_PER_CLASS} {name} flows...")
        batch = fn()
        all_flows.extend(batch)
        print(f"    -> {len(batch)} done.")

    random.shuffle(all_flows)

    print(f"\n[*] Writing {len(all_flows)} flows to {OUTPUT_FILE} ...")
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for flow in all_flows:
            f.write(json.dumps(flow) + "\n")

    from collections import Counter
    counts = Counter(f["collected_label"] for f in all_flows)
    print(f"\n[+] Dataset saved: {OUTPUT_FILE}")
    print(f"[+] Total flows : {len(all_flows)}")
    print(f"[+] Distribution:")
    for label, c in sorted(counts.items()):
        print(f"    {label:<25} {c:>6}")
    size_mb = OUTPUT_FILE.stat().st_size / (1024 * 1024)
    print(f"[+] File size   : {size_mb:.1f} MB")

    # Validate one record against real schema keys
    ref_keys = sorted(["schema_version","flow_id","first_seen","last_seen",
                       "five_tuple","duration_s","total_packets","total_bytes",
                       "packet_sizes","inter_arrival_times","tcp_flags_seen",
                       "bytes_in","bytes_out_proxy","tls_meta","dns_meta",
                       "zeek_conn_state","zeek_uid","sensor_id",
                       "capture_interface","pipeline_version","collected_label"])
    sample_keys = sorted(all_flows[0].keys())
    assert sample_keys == ref_keys, f"Key mismatch!\n  expected: {ref_keys}\n  got:      {sample_keys}"
    print("[+] Schema key validation PASSED.")


if __name__ == "__main__":
    main()
