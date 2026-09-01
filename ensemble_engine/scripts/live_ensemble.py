"""
scripts/live_ensemble.py
==========================
Person 2 — Unsupervised & Sequential Deep Learning Engineer

The live production loop: subscribes to Redis channel `flow.raw`
(Person 3's ingestion output), runs every flow through the fused
ensemble (ensemble.score_flow — supervised + anomaly + sequence), and
publishes the resulting alert object to Redis channel `alert.new` for
Person 4's API layer to consume.

This is the piece that turns everything built in Steps 3-7 (features,
anomaly models, LSTM, infer.py, ensemble.py) into an actual running
detector, mirroring xgboost_train/scripts/live_inference.py's pattern.

Usage
-----
    python ensemble_engine/scripts/live_ensemble.py

Requires: main.py (SIMULATION mode) already running and publishing to
flow.raw, and all model artifacts already trained (train_anomaly.py,
train_lstm.py) — this script will error clearly on startup if any are
missing rather than failing confusingly mid-stream.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import redis

SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))

from ensemble import score_flow, BENIGN_CLASS


def main():
    parser = argparse.ArgumentParser(description="Live ensemble scoring: flow.raw -> alert.new")
    parser.add_argument("--redis-host", default="127.0.0.1")
    parser.add_argument("--redis-port", type=int, default=6379)
    parser.add_argument("--in-channel", default="flow.raw")
    parser.add_argument("--out-channel", default="alert.new")
    parser.add_argument("--publish-benign", action="store_true",
                         help="Also publish BENIGN-classified flows to alert.new "
                              "(off by default — only non-benign flows are alerts)")
    parser.add_argument("--log-every", type=int, default=1,
                         help="Print a line every N flows processed (not just alerts)")
    args = parser.parse_args()

    try:
        r = redis.Redis(host=args.redis_host, port=args.redis_port, decode_responses=True, protocol=2)
        r.ping()
    except redis.ConnectionError:
        print(f"[-] Could not connect to Redis at {args.redis_host}:{args.redis_port}")
        print("    Make sure ingestion's main.py (SIMULATION mode) is already running.")
        sys.exit(1)

    # Fail fast and clearly if models aren't trained yet, rather than
    # crashing confusingly on the first real flow.
    try:
        _ = score_flow({
            "flow_id": "startup-check", "five_tuple": {"src_ip": "0.0.0.0", "dst_ip": "0.0.0.0",
            "src_port": 0, "dst_port": 0, "protocol": "TCP"},
            "duration_s": 0.1, "total_packets": 1, "total_bytes": 60, "bytes_in": 60,
            "packet_sizes": [60], "inter_arrival_times": [], "tcp_flags_seen": [],
            "tls_meta": None, "dns_meta": None,
        })
        print("[+] Model artifacts loaded OK (Isolation Forest, Autoencoder, LSTM, supervised).")
    except FileNotFoundError as e:
        print(f"[-] Missing model artifact: {e}")
        print("    Run train_anomaly.py and train_lstm.py first.")
        sys.exit(1)

    pubsub = r.pubsub()
    pubsub.subscribe(args.in_channel)

    print(f"[+] Subscribed to '{args.in_channel}', publishing alerts to '{args.out_channel}'")
    print("[+] Running — Ctrl+C to stop\n")

    processed = 0
    alerts_published = 0
    errors = 0
    start_time = time.time()

    try:
        for message in pubsub.listen():
            if message["type"] != "message":
                continue

            try:
                flow_obj = json.loads(message["data"])
            except json.JSONDecodeError:
                print("[!] Skipped malformed message (not valid JSON)")
                errors += 1
                continue

            try:
                alert = score_flow(flow_obj)
            except Exception as e:
                # A single bad/unexpected flow should never take the whole
                # live detector down — log it, count it, keep processing.
                print(f"[!] Scoring error on flow {flow_obj.get('flow_id', '?')}: {e}")
                errors += 1
                continue

            processed += 1
            is_alertable = alert["threat_class"] != BENIGN_CLASS

            if is_alertable or args.publish_benign:
                r.publish(args.out_channel, json.dumps(alert))
                alerts_published += 1

            if is_alertable:
                five_tuple = alert["five_tuple"] or {}
                print(f"  🚨 [{alert['severity']}] {alert['threat_class']} "
                      f"(confidence={alert['confidence_score']:.2f})  "
                      f"{five_tuple.get('src_ip')}:{five_tuple.get('src_port')} "
                      f"-> {five_tuple.get('dst_ip')}:{five_tuple.get('dst_port')}  "
                      f"[sup={alert['model_source']['supervised_score']:.2f} "
                      f"anom={alert['model_source']['anomaly_score']:.2f} "
                      f"seq={alert['model_source']['sequence_score']:.2f}]")
            elif args.log_every and processed % args.log_every == 0:
                print(f"  [{processed}] benign — {five_tuple.get('src_ip') if (five_tuple := alert['five_tuple']) else '?'}")

    except KeyboardInterrupt:
        pass

    elapsed = time.time() - start_time
    print(f"\n[+] Stopped. Processed {processed} flows in {elapsed:.1f}s "
          f"({alerts_published} alerts published, {errors} errors)")


if __name__ == "__main__":
    main()
