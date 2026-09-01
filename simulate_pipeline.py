"""
simulate_pipeline.py
====================
Simulates the full SIH26145 threat detection pipeline from end to end:
  [Ingestion / Attack Flows] -> Redis `flow.raw`
    -> [ML Ensemble (Person 1 XGBoost + Person 2 Deep Learning / Anomaly / LSTM)]
    -> Redis `alert.new`
    -> [Person 4 Express & WebSocket Backend (Port 4000)]
    -> [SOC React Dashboard (Port 5173)]

Usage:
  python simulate_pipeline.py [--continuous] [--interval 1.5] [--scenario all|c2|ddos|scan|dns|dga|exfil|benign]
"""

import argparse
import json
import random
import sys
import time
import uuid
from datetime import datetime, timezone

import redis

# Connect to Redis
try:
    r = redis.Redis(host='127.0.0.1', port=6379, decode_responses=True, protocol=2)
    r.ping()
except Exception as e:
    print(f"[-] Cannot connect to Redis at 127.0.0.1:6379: {e}")
    print("    Please ensure Redis is running.")
    sys.exit(1)


def generate_flow(scenario: str) -> dict:
    flow_id = str(uuid.uuid4())
    now_iso = datetime.now(timezone.utc).isoformat()

    if scenario == "c2":
        # Botnet C2 Beaconing: periodic small payloads to port 443, regular inter-arrival times with natural jitter
        src_ip = f"10.0.{random.randint(1,5)}.{random.randint(10,50)}"
        dst_ip = "198.51.100.23"
        sport = random.randint(40000, 60000)
        base_interval = random.choice([15.0, 30.0, 45.0, 60.0])
        jitter_pct = random.uniform(0.03, 0.14)
        n_p = random.randint(4, 6)
        iats = [round(base_interval * (1 + random.uniform(-jitter_pct, jitter_pct)), 2) for _ in range(n_p - 1)]
        pkts = [random.choice([64, 68, 72, 74, 80, 84]) for _ in range(n_p)]
        return {
            "schema_version": "1.0.0",
            "flow_id": flow_id,
            "first_seen": now_iso,
            "last_seen": now_iso,
            "five_tuple": {"src_ip": src_ip, "dst_ip": dst_ip, "src_port": sport, "dst_port": 443, "protocol": "TCP/TLS"},
            "sensor_id": "diode-sensor-01",
            "capture_interface": "lo",
            "pipeline_version": "1.0.0",
            "duration_s": round(sum(iats), 2),
            "total_packets": n_p,
            "total_bytes": sum(pkts),
            "bytes_in": sum(pkts),
            "bytes_out_proxy": 0,
            "packet_sizes": pkts,
            "inter_arrival_times": iats,
            "tcp_flags_seen": ["A", "F", "P", "S"],
            "tls_meta": {"ja3": "771,4865-4866-4867,0-23-65281,29-23-24,0", "ja4": "t13d1516h2_8daaf6152771_000000000000", "sni": "c2-beacon-channel.xyz", "cipher_suites": ["0x1301", "0x1302"]},
            "dns_meta": None
        }

    elif scenario == "ddos":
        # Volumetric DDoS flood: ultra-high packet rate, sub-millisecond IAT burst to port 80
        src_ip = f"192.168.{random.randint(1,10)}.{random.randint(1,254)}"
        dst_ip = "10.0.0.1"
        sport = random.randint(1024, 65535)
        return {
            "schema_version": "1.0.0",
            "flow_id": flow_id,
            "first_seen": now_iso,
            "last_seen": now_iso,
            "five_tuple": {"src_ip": src_ip, "dst_ip": dst_ip, "src_port": sport, "dst_port": 80, "protocol": "TCP"},
            "sensor_id": "diode-sensor-01",
            "capture_interface": "lo",
            "pipeline_version": "1.0.0",
            "duration_s": 0.005,
            "total_packets": 50,
            "total_bytes": 30000,
            "bytes_in": 30000,
            "bytes_out_proxy": 0,
            "packet_sizes": [600] * 30,
            "inter_arrival_times": [0.0001] * 29,
            "tcp_flags_seen": ["S"],
            "tls_meta": None,
            "dns_meta": None
        }

    elif scenario == "scan":
        # Port Scan: single probe across varied ports
        src_ip = "172.16.4.88"
        dst_ip = "10.0.0.2"
        dport = random.choice([21, 22, 23, 25, 80, 110, 135, 139, 443, 445, 1433, 2100, 3306, 3389, 8080])
        sport = random.randint(40000, 60000)
        return {
            "schema_version": "1.0.0",
            "flow_id": flow_id,
            "first_seen": now_iso,
            "last_seen": now_iso,
            "five_tuple": {"src_ip": src_ip, "dst_ip": dst_ip, "src_port": sport, "dst_port": dport, "protocol": "TCP"},
            "sensor_id": "diode-sensor-01",
            "capture_interface": "lo",
            "pipeline_version": "1.0.0",
            "duration_s": 0.000044,
            "total_packets": 1,
            "total_bytes": 0,
            "bytes_in": 0,
            "bytes_out_proxy": 0,
            "packet_sizes": [0],
            "inter_arrival_times": [],
            "tcp_flags_seen": ["S"],
            "tls_meta": None,
            "dns_meta": None
        }

    elif scenario == "dns":
        # DNS Tunnelling: Base64/Hex encoded subdomain queries to covert domain
        src_ip = f"10.0.1.{random.randint(10,99)}"
        dst_ip = "8.8.8.8"
        subdomain = "".join(random.choices("0123456789abcdefghijklmnopqrstuvwxyz", k=36))
        qname = f"{subdomain}.tunnel.c2.example.com"
        return {
            "schema_version": "1.0.0",
            "flow_id": flow_id,
            "first_seen": now_iso,
            "last_seen": now_iso,
            "five_tuple": {"src_ip": src_ip, "dst_ip": dst_ip, "src_port": random.randint(40000, 50000), "dst_port": 53, "protocol": "UDP"},
            "sensor_id": "diode-sensor-01",
            "capture_interface": "lo",
            "pipeline_version": "1.0.0",
            "duration_s": 0.08,
            "total_packets": 2,
            "total_bytes": 180,
            "bytes_in": 180,
            "bytes_out_proxy": 0,
            "packet_sizes": [90, 90],
            "inter_arrival_times": [0.08],
            "tcp_flags_seen": [],
            "tls_meta": None,
            "dns_meta": {"query_name": qname, "query_type": "TXT", "query_length": len(qname), "answer_count": 0}
        }

    elif scenario == "dga":
        # DGA Domain lookup: pseudorandom domain string
        src_ip = f"10.0.2.{random.randint(10,99)}"
        dst_ip = "1.1.1.1"
        dga_names = [
            "wxsnapghers.name", "kxyzypkvyta.name", "blackstone122.top",
            "yhgxkzydcni.info", "qbcjejutuja.org", "firewind834.biz",
            "yzaludqdale.info", "grknexarqfa.mobi", "xopqlanbvsd.biz", "zxcvbnmasdf.org"
        ]
        qname = random.choice(dga_names)
        return {
            "schema_version": "1.0.0",
            "flow_id": flow_id,
            "first_seen": now_iso,
            "last_seen": now_iso,
            "five_tuple": {"src_ip": src_ip, "dst_ip": dst_ip, "src_port": random.randint(40000, 50000), "dst_port": 53, "protocol": "UDP"},
            "sensor_id": "diode-sensor-01",
            "capture_interface": "lo",
            "pipeline_version": "1.0.0",
            "duration_s": 0.05,
            "total_packets": 2,
            "total_bytes": 140,
            "bytes_in": 140,
            "bytes_out_proxy": 0,
            "packet_sizes": [70, 70],
            "inter_arrival_times": [0.05],
            "tcp_flags_seen": [],
            "tls_meta": None,
            "dns_meta": {"query_name": qname, "query_type": "A", "query_length": len(qname), "answer_count": 0}
        }

    elif scenario == "exfil":
        # Data Exfiltration: large volume of outbound bytes, high payload
        src_ip = "10.0.0.15"
        dst_ip = "203.0.113.88"
        return {
            "schema_version": "1.0.0",
            "flow_id": flow_id,
            "first_seen": now_iso,
            "last_seen": now_iso,
            "five_tuple": {"src_ip": src_ip, "dst_ip": dst_ip, "src_port": 52140, "dst_port": 443, "protocol": "TCP/TLS"},
            "sensor_id": "diode-sensor-01",
            "capture_interface": "lo",
            "pipeline_version": "1.0.0",
            "duration_s": 2.5,
            "total_packets": 50,
            "total_bytes": 73000,
            "bytes_in": 73000,
            "bytes_out_proxy": 0,
            "packet_sizes": [1460] * 30,
            "inter_arrival_times": [0.01, 0.005, 0.02, 0.008, 0.015, 0.03, 0.005, 0.02] * 3,
            "tcp_flags_seen": ["A", "F", "P", "S"],
            "tls_meta": {"ja3": "771,4865-4866,0-23,29,0", "ja4": "t13d1516h2_8daaf6152771_000000000000", "sni": "secure-upload.cdn-node.org", "cipher_suites": ["0x1301"]},
            "dns_meta": None
        }

    else:
        # Normal Benign Traffic: varied packet sizes and irregular intervals
        src_ip = f"10.0.0.{random.randint(20, 80)}"
        dst_ip = random.choice(["142.250.190.46", "151.101.1.69", "13.107.42.14"])
        return {
            "schema_version": "1.0.0",
            "flow_id": flow_id,
            "first_seen": now_iso,
            "last_seen": now_iso,
            "five_tuple": {"src_ip": src_ip, "dst_ip": dst_ip, "src_port": random.randint(40000, 60000), "dst_port": 443, "protocol": "TCP/TLS"},
            "sensor_id": "diode-sensor-01",
            "capture_interface": "lo",
            "pipeline_version": "1.0.0",
            "duration_s": 1.2,
            "total_packets": 8,
            "total_bytes": 2276,
            "bytes_in": 2276,
            "bytes_out_proxy": 0,
            "packet_sizes": [64, 512, 1400, 80, 220],
            "inter_arrival_times": [0.1, 0.5, 0.02, 0.8, 0.04, 0.3],
            "tcp_flags_seen": ["A", "F", "P", "S"],
            "tls_meta": {"ja3": "771,4865-4866-4867,0-23,29,0", "ja4": "t13d1516h2_8daaf6152771_000000000000", "sni": "www.google.com", "cipher_suites": ["0x1301", "0x1302"]},
            "dns_meta": None
        }


def main():
    parser = argparse.ArgumentParser(description="Live traffic & threat flow injector")
    parser.add_argument("--scenario", default="all", choices=["all", "c2", "ddos", "scan", "dns", "dga", "exfil", "benign"])
    parser.add_argument("--interval", type=float, default=1.5, help="Seconds between flows")
    parser.add_argument("--count", type=int, default=0, help="Number of flows to send (0 = infinite)")
    args = parser.parse_args()

    scenarios = ["c2", "ddos", "scan", "dns", "dga", "exfil", "benign"] if args.scenario == "all" else [args.scenario]

    print("=" * 65)
    print("  SIH26145 Live Threat & Traffic Simulator")
    print("  Injecting flows to Redis channel 'flow.raw'...")
    print(f"  Scenarios: {', '.join(scenarios)}")
    print(f"  Interval:  {args.interval}s")
    print("=" * 65)

    sent = 0
    try:
        while True:
            scenario = random.choice(scenarios) if args.scenario == "all" else args.scenario
            flow = generate_flow(scenario)
            
            listeners = r.publish("flow.raw", json.dumps(flow))
            sent += 1

            ft = flow["five_tuple"]
            print(f"[{sent:03d}] Published ({scenario.upper():6s}) -> {ft['src_ip']}:{ft['src_port']} -> {ft['dst_ip']}:{ft['dst_port']} [{ft['protocol']}] (listeners: {listeners})")

            if args.count > 0 and sent >= args.count:
                break

            time.sleep(args.interval)

    except KeyboardInterrupt:
        print(f"\n[+] Stopped. Total flows injected: {sent}")


if __name__ == "__main__":
    main()
