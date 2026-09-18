"""Frozen-model evaluation on CICIDS improved CSVs using forward fields only.

This measures candidate scores, not the production decision/incident system.
CSV summaries contain neither packet history nor DNS names/TLS handshakes.
"""
from __future__ import annotations

import argparse
from collections import Counter
import gzip
import hashlib
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import torch

from .metrics import binary_metrics
from .train import LABELS


FEATURE_COLUMNS = ("Total Fwd Packet", "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Min", "Fwd IAT Max",
                   "Fwd PSH Flags", "Fwd URG Flags", "Fwd RST Flags", "Protocol")


def forward_matrix(frame, paths):
    """No label, ID, timestamp, backward or combined-flow value is accessed."""
    column = lambda name: pd.to_numeric(frame[name], errors="coerce").to_numpy(dtype=float)
    count, duration = column("Total Fwd Packet"), column("Fwd IAT Total") / 1e6
    valid = np.isfinite(count) & np.isfinite(duration) & (count >= 1) & (duration >= 0)
    tcp = column("Protocol") == 6
    with np.errstate(divide="ignore", invalid="ignore"):
        available = {"flow.packet_count": count, "flow.duration_s": duration,
                     "flow.pps": np.where(duration > 0, count / duration, np.nan)}
    for suffix in ("Mean", "Min", "Max"):
        available[f"flow.iat_s_{suffix.lower()}"] = np.where(count > 1, column(f"Fwd IAT {suffix}") / 1e6, np.nan)
    for flag in ("PSH", "URG", "RST"):
        available[f"flow.{flag.lower()}_count"] = np.where(tcp, column(f"Fwd {flag} Flags"), np.nan)
    unsupported = set(paths) - set(available)
    if unsupported:
        raise ValueError(f"unvalidated CICIDS feature mapping: {sorted(unsupported)}")
    matrix = np.column_stack([available[path] for path in paths])
    matrix[~np.isfinite(matrix)] = np.nan
    matrix[matrix < 0] = np.nan
    return matrix, valid, count, duration


def metrics(labels, probabilities, thresholds):
    normal = np.asarray([str(label).strip().upper() == "BENIGN" for label in labels])
    ddos = np.asarray(["ddos" in str(label).lower() for label in labels])
    scan = np.asarray(["portscan" in str(label).lower().replace(" ", "") for label in labels])
    predictions = probabilities >= np.asarray([thresholds[label] for label in LABELS])
    per_label = {label: binary_metrics(targets, probabilities[:, index], thresholds[label])
                 for index, (label, targets) in enumerate((("DDoS", ddos), ("PORT_SCAN", scan)))}
    # The CSV has no separate exfiltration ground-truth class. Do not rename
    # infiltration, botnet or web attacks to exfiltration to manufacture a test.
    per_label["DATA_EXFILTRATION"] = {"status": "not_measurable", "reason": "NO_MATCHING_GROUND_TRUTH_CLASS"}
    any_alert = predictions.any(axis=1)
    tp, fp = int((any_alert & ~normal).sum()), int((any_alert & normal).sum())
    fn, tn = int((~any_alert & ~normal).sum()), int((~any_alert & normal).sum())
    binary = {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": tp / max(tp+fp, 1),
              "recall": tp / max(tp+fn, 1), "f1": 2*tp / max(2*tp+fp+fn, 1),
              "accuracy": (tp+tn) / max(len(labels), 1), "fpr": fp / max(fp+tn, 1),
              "definition": "any of the three known heads passes its simulation-selected threshold"}
    by_class = {}
    for label in sorted(set(labels)):
        selected = np.asarray(labels) == label
        by_class[str(label)] = {"rows": int(selected.sum()), "any_known_alert_rate": float(any_alert[selected].mean())}
    return {"rows": len(labels), "per_label": per_label, "binary_any_attack": binary, "by_dataset_label": by_class}


def evaluate(bundle, policy, dataset, output, *, batch_size=8192):
    dataset, output = Path(dataset), Path(output)
    files = sorted(dataset.glob("*.csv"))
    if not files:
        raise FileNotFoundError(f"No CICIDS CSV files in {dataset}")
    output.mkdir(parents=True, exist_ok=False)
    all_labels, all_probabilities = [], []
    daily, total, skipped = {}, 0, 0
    prediction_path = output / "predictions.csv.gz"
    with gzip.open(prediction_path, "wt", encoding="utf-8", newline="") as predictions_stream:
        header = True
        for path in files:
            labels_parts, probability_parts = [], []
            read_count, invalid_count = 0, 0
            for frame in pd.read_csv(path, usecols=[*FEATURE_COLUMNS, "Label"], chunksize=batch_size):
                raw, valid, count, duration = forward_matrix(frame, bundle.base.paths)
                read_count += len(frame)
                invalid_count += int((~valid).sum())
                if not valid.any():
                    continue
                # Only the forward feature subset is observable. Missing window,
                # DNS and TLS values remain absent. Use the subset mask ratio
                # explicitly and document its shift from full observer visibility.
                probability = bundle.predict_forward_matrix(raw[valid], visibility=np.isfinite(raw[valid]).mean(axis=1),
                              event_count=count[valid], duration_ms=duration[valid] * 1000)
                labels = frame.loc[valid, "Label"].astype(str).str.strip().to_numpy()
                labels_parts.append(labels)
                probability_parts.append(probability.astype(np.float32))
                record = pd.DataFrame({"file": path.name, "csv_row": frame.index[valid] + 2, "label": labels})
                for i, label in enumerate(LABELS):
                    record[f"p_{label}"] = probability[:, i]
                    record[f"alert_{label}"] = probability[:, i] >= policy["thresholds"][label]
                record.to_csv(predictions_stream, index=False, header=header)
                header = False
                if read_count % (batch_size * 16) == 0:
                    print(f"  {path.name}: evaluated {read_count:,} rows", flush=True)
            total += read_count
            skipped += invalid_count
            labels = np.concatenate(labels_parts) if labels_parts else np.asarray([], dtype=str)
            probabilities = np.concatenate(probability_parts) if probability_parts else np.empty((0, len(LABELS)))
            if not len(labels):
                daily[path.name] = {"total_rows": read_count, "invalid_forward_rows": invalid_count, "status": "no_valid_rows"}
                continue
            daily[path.name] = {**metrics(labels, probabilities, policy["thresholds"]), "total_rows": read_count,
                                "invalid_forward_rows": invalid_count, "file_bytes": path.stat().st_size}
            # Stream hashing instead of copying >200MB CSVs into memory.
            digest = hashlib.sha256()
            with path.open("rb") as stream:
                for block in iter(lambda: stream.read(1024*1024), b""):
                    digest.update(block)
            daily[path.name]["sha256"] = digest.hexdigest()
            all_labels.append(labels)
            all_probabilities.append(probabilities)
            print(f"  {path.name}: {read_count:,} rows complete", flush=True)
    labels = np.concatenate(all_labels)
    probabilities = np.concatenate(all_probabilities)
    report = {"total_rows": total, "evaluated_rows": len(labels), "invalid_forward_rows": skipped,
              "overall": metrics(labels, probabilities, policy["thresholds"]), "by_file": daily,
              "thresholds": {label: policy["thresholds"][label] for label in LABELS},
              "feature_paths": bundle.base.paths, "source_columns": list(FEATURE_COLUMNS),
              "training_data": "simulation only", "fitting_on_cicids": False,
              "candidate_only": True, "predictions": prediction_path.name,
              "limitations": ["Scores on forward CSV summaries, not packet replay or final production decisions.",
                              "Full Flow Duration, reverse columns, combined rates, IPs, IDs, ports, timestamps and labels are excluded from model features.",
                              "Forward IAT Total supplies duration; IAT microseconds are converted to seconds.",
                              "Wire-byte statistics are excluded because CSV packet lengths use a different layer.",
                              "Visibility ratio covers only the mapped forward subset and differs from live full-envelope visibility.",
                              "DNS/TLS/window history is absent; Agent 1 DNS models are not measurable on these CSVs.",
                              "DDoS/PortScan are matched to corresponding dataset names; other attacks remain other attacks.",
                              "External test data is never used for training, calibration or selecting thresholds."]}
    (output / "metrics.json").write_text(json.dumps(report, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release", type=Path, required=True)
    parser.add_argument("--dataset", type=Path, default=Path("ingestion/dataset/CICIDS2017_improved"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--batch-size", type=int, default=8192)
    args = parser.parse_args()
    torch.set_num_threads(2)
    bundle = joblib.load(args.release / "bundle.joblib")
    policy = json.loads((args.release / "policy.json").read_text())
    result = evaluate(bundle, policy, args.dataset, args.output, batch_size=args.batch_size)
    print(json.dumps(result["overall"], indent=2))


if __name__ == "__main__":
    main()
