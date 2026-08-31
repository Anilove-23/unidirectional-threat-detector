"""
scripts/collect_dataset.py
===========================
Person 2 — Unsupervised & Sequential Deep Learning Engineer

Subscribes to Redis channel `flow.raw` (Person 3's ingestion output) and
logs every FlowObject to a labeled JSONL file. Run this alongside one of
ingestion/dataset/generators/*.py to build a labeled training set that is
byte-for-byte the same FlowObject shape you'll see at live inference time
— no train/serve skew from converting to a different CSV format first.

Typical session (two terminals, both after `python main.py` -> [2] SIMULATION
is already running in a third terminal):

  Terminal A (this script):
      python ensemble_engine/scripts/collect_dataset.py --label BENIGN --duration 90

  Terminal B (traffic generator, started a couple seconds after Terminal A):
      python ingestion/dataset/generators/benign_gen.py --target 127.0.0.1 --duration 60

Repeat with a different --label for each attack scenario, e.g.:
      --label BOTNET_C2_BEACONING   <->  c2_beacon_gen.py
      --label VOLUMETRIC_DDOS       <->  ddos_gen.py
      --label PORT_SCAN             <->  scan_gen.py
      --label DNS_TUNNELING         <->  dns_tunnel_gen.py
      --label DGA_DOMAIN            <->  dga_gen.py
      --label DATA_EXFILTRATION     <->  slowloris_gen.py

All labels get appended to the SAME output file by default
(ensemble_engine/data/raw_flows.jsonl) so train_anomaly.py / train_lstm.py
can load one file and filter by label.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import redis

DATA_DIR = Path(__file__).resolve().parent.parent / "data"


def main():
    parser = argparse.ArgumentParser(description="Collect labeled FlowObjects from flow.raw")
    parser.add_argument("--label", required=True,
                         help="Label to attach to every flow collected this run "
                              "(e.g. BENIGN, BOTNET_C2_BEACONING, VOLUMETRIC_DDOS)")
    parser.add_argument("--duration", type=float, default=0,
                         help="Seconds to listen (0 = run until Ctrl+C)")
    parser.add_argument("--output", default=str(DATA_DIR / "raw_flows.jsonl"),
                         help="JSONL file to append to (default: ensemble_engine/data/raw_flows.jsonl)")
    parser.add_argument("--redis-host", default="127.0.0.1")
    parser.add_argument("--redis-port", type=int, default=6379)
    parser.add_argument("--channel", default="flow.raw")
    parser.add_argument("--dst-port", type=int, default=None,
                         help="Only log flows whose five_tuple.dst_port matches this "
                              "(e.g. 443 for c2_beacon_gen, 53 for dns_tunnel_gen). "
                              "Sharply reduces contamination from unrelated loopback "
                              "traffic (browsers, package managers, etc.) during collection.")
    args = parser.parse_args()

    # Redis pub/sub traffic between main.py and this script's own subscriber
    # travels over loopback too, and would otherwise get swept up and
    # mislabeled with whatever --label is active. Always exclude it.
    EXCLUDED_PORTS = {args.redis_port}

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        r = redis.Redis(host=args.redis_host, port=args.redis_port, decode_responses=True)
        r.ping()
    except redis.ConnectionError:
        print(f"[-] Could not connect to Redis at {args.redis_host}:{args.redis_port}")
        print("    Make sure ingestion's main.py (SIMULATION mode) is already running.")
        sys.exit(1)

    pubsub = r.pubsub()
    pubsub.subscribe(args.channel)

    print(f"[+] Connected to Redis. Listening on '{args.channel}'.")
    print(f"[+] Label for this session : {args.label}")
    print(f"[+] Writing to             : {output_path}")
    if args.duration > 0:
        print(f"[+] Will stop after        : {args.duration}s")
    else:
        print("[+] Running until Ctrl+C")
    print()

    start_time = time.time()
    count = 0
    skipped = 0

    try:
        with open(output_path, "a", encoding="utf-8") as f:
            for message in pubsub.listen():
                if args.duration > 0 and (time.time() - start_time) >= args.duration:
                    break

                if message["type"] != "message":
                    continue

                try:
                    flow_obj = json.loads(message["data"])
                except json.JSONDecodeError:
                    print("[!] Skipped malformed message (not valid JSON)")
                    continue

                five_tuple = flow_obj.get("five_tuple", {})
                src_port = five_tuple.get("src_port")
                dst_port = five_tuple.get("dst_port")

                # Exclude Redis's own pub/sub traffic in EITHER direction.
                # On a unidirectional sensor, request (dst=6379) and reply
                # (src=6379) show up as separate flows, so both must be checked.
                if src_port in EXCLUDED_PORTS or dst_port in EXCLUDED_PORTS:
                    skipped += 1
                    continue

                # Optional: only keep flows actually going to the generator's
                # target port, further reducing noise from unrelated loopback
                # traffic (browsers, package managers, other local services).
                if args.dst_port is not None and dst_port != args.dst_port:
                    skipped += 1
                    continue

                flow_obj["collected_label"] = args.label
                f.write(json.dumps(flow_obj) + "\n")
                f.flush()
                count += 1

                print(f"  [{count}] {five_tuple.get('src_ip')}:{src_port} "
                      f"-> {five_tuple.get('dst_ip')}:{dst_port} "
                      f"({five_tuple.get('protocol')})  pkts={flow_obj.get('total_packets')}")

    except KeyboardInterrupt:

        pass

    print(f"\n[+] Done. Collected {count} flows labeled '{args.label}' -> {output_path}")
    print(f"[+] Skipped {skipped} flows (Redis control traffic / port filter)")


if __name__ == "__main__":
    main()
