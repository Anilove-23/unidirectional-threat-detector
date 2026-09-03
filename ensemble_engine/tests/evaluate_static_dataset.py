"""
ensemble_engine/tests/evaluate_static_dataset.py
==================================================
Evaluates Person 2's Isolation Forest + Autoencoder (anomaly_score) and
LSTM (beacon_likelihood) against the 40k static test dataset.

Reads:  tests/dataset/person2_test_dataset.jsonl
Writes: tests/results/person2_evaluation_results.json
        tests/results/person2_evaluation_results.csv

Usage:
    uv run python ensemble_engine/tests/evaluate_static_dataset.py
"""

import json
import sys
import time
import csv
from pathlib import Path
from collections import defaultdict

TESTS_DIR = Path(__file__).resolve().parent
SCRIPTS_DIR = TESTS_DIR.parent / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

from infer import anomaly_score, beacon_likelihood

DATASET = TESTS_DIR / "dataset" / "person2_test_dataset.jsonl"
RESULTS_DIR = TESTS_DIR / "results"


def main():
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    if not DATASET.exists():
        print(f"[-] Dataset not found: {DATASET}")
        print("    Run generate_static_dataset.py first.")
        sys.exit(1)

    # Count total lines for progress
    with open(DATASET, "r", encoding="utf-8") as f:
        total = sum(1 for _ in f)
    print(f"[*] Evaluating {total} flows from {DATASET.name}")

    # Per-class accumulators
    stats = defaultdict(lambda: {
        "count": 0,
        "anomaly_sum": 0.0, "anomaly_min": 1.0, "anomaly_max": 0.0,
        "beacon_sum": 0.0, "beacon_min": 1.0, "beacon_max": 0.0,
        "anomaly_above_50": 0, "anomaly_above_80": 0,
        "beacon_above_50": 0, "beacon_above_80": 0,
    })

    csv_rows = []
    t0 = time.time()
    processed = 0

    with open(DATASET, "r", encoding="utf-8") as f:
        for line in f:
            flow = json.loads(line)
            label = flow.get("collected_label", "UNKNOWN")

            a = anomaly_score(flow)
            b = beacon_likelihood(flow)

            s = stats[label]
            s["count"] += 1
            s["anomaly_sum"] += a
            s["anomaly_min"] = min(s["anomaly_min"], a)
            s["anomaly_max"] = max(s["anomaly_max"], a)
            s["beacon_sum"] += b
            s["beacon_min"] = min(s["beacon_min"], b)
            s["beacon_max"] = max(s["beacon_max"], b)
            if a > 0.5: s["anomaly_above_50"] += 1
            if a > 0.8: s["anomaly_above_80"] += 1
            if b > 0.5: s["beacon_above_50"] += 1
            if b > 0.8: s["beacon_above_80"] += 1

            csv_rows.append({
                "flow_id": flow["flow_id"],
                "label": label,
                "anomaly_score": round(a, 6),
                "beacon_likelihood": round(b, 6),
            })

            processed += 1
            if processed % 2000 == 0:
                elapsed = time.time() - t0
                rate = processed / elapsed
                print(f"    {processed}/{total}  ({rate:.0f} flows/s)")

    elapsed = time.time() - t0
    print(f"\n[+] Scored {processed} flows in {elapsed:.1f}s ({processed/elapsed:.0f} flows/s)\n")

    # ── Summary table ──
    header = (f"{'CLASS':<25} | {'N':>6} | {'AVG_ANOM':>8} | {'MIN':>5} | {'MAX':>5} | "
              f"{'A>0.5':>6} | {'A>0.8':>6} | {'AVG_BCN':>8} | {'B>0.5':>6} | {'B>0.8':>6}")
    sep = "=" * len(header)
    print(sep)
    print(header)
    print(sep)

    summary = {}
    for label in sorted(stats):
        s = stats[label]
        n = s["count"]
        avg_a = s["anomaly_sum"] / n
        avg_b = s["beacon_sum"] / n
        row_str = (f"{label:<25} | {n:>6} | {avg_a:>8.4f} | {s['anomaly_min']:>5.3f} | "
                   f"{s['anomaly_max']:>5.3f} | {s['anomaly_above_50']:>6} | "
                   f"{s['anomaly_above_80']:>6} | {avg_b:>8.4f} | "
                   f"{s['beacon_above_50']:>6} | {s['beacon_above_80']:>6}")
        print(row_str)
        summary[label] = {
            "count": n,
            "anomaly_avg": round(avg_a, 6),
            "anomaly_min": round(s["anomaly_min"], 6),
            "anomaly_max": round(s["anomaly_max"], 6),
            "anomaly_above_0.5": s["anomaly_above_50"],
            "anomaly_above_0.8": s["anomaly_above_80"],
            "beacon_avg": round(avg_b, 6),
            "beacon_min": round(s["beacon_min"], 6),
            "beacon_max": round(s["beacon_max"], 6),
            "beacon_above_0.5": s["beacon_above_50"],
            "beacon_above_0.8": s["beacon_above_80"],
        }
    print(sep)

    # ── Save JSON summary ──
    json_path = RESULTS_DIR / "person2_evaluation_results.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump({"total_flows": processed, "elapsed_s": round(elapsed, 2),
                    "per_class": summary}, f, indent=2)
    print(f"\n[+] JSON summary -> {json_path}")

    # ── Save per-flow CSV ──
    csv_path = RESULTS_DIR / "person2_evaluation_results.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["flow_id", "label", "anomaly_score", "beacon_likelihood"])
        w.writeheader()
        w.writerows(csv_rows)
    csv_mb = csv_path.stat().st_size / (1024 * 1024)
    print(f"[+] Per-flow CSV -> {csv_path}  ({csv_mb:.1f} MB)")


if __name__ == "__main__":
    main()
