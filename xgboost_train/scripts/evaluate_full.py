"""
xgboost_train/scripts/evaluate_full.py
=======================================
Person 1 — Supervised Feature Analytics Engineer

Tests Model A (Flow classifier) and Model B (DNS classifier) on a massive 
unseen combination of datasets:
  - wednesday.csv (DoS / DATA_EXFILTRATION)
  - thursday.csv  (Infiltration / DATA_EXFILTRATION)
  - friday.csv    (DDoS, Portscan)
  - dns_dataset.csv (DNS_TUNNELING, DGA)

This script validates Person 1's models on over 1.5 Million rows across all 5 
threat classes specified in the SIH architecture.

Results saved to:
  xgboost_train/results/full_evaluation_predictions.csv
  xgboost_train/results/full_evaluation_summary.txt

Usage
-----
  uv run python xgboost_train/scripts/evaluate_full.py
"""

from __future__ import annotations

import sys
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))

import textwrap
from datetime import datetime

import numpy as np
import pandas as pd
import xgboost as xgb
import joblib
from sklearn.metrics import classification_report

from features import extract_flow_features, extract_dns_features

ROOT        = SCRIPTS_DIR.parent
MODELS_DIR  = ROOT / "models"
RESULTS_DIR = ROOT / "results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

DATA_DIR = Path(__file__).resolve().parents[2] / "ingestion" / "dataset"
CICIDS_DIR = DATA_DIR / "CICIDS2017_improved"

# The target files containing Person 1's threat classes
FILES = [
    CICIDS_DIR / "wednesday.csv",
    CICIDS_DIR / "thursday.csv",
    CICIDS_DIR / "friday.csv",
]
DNS_DATASET = DATA_DIR / "dns_dataset.csv"

FLOW_LABEL_MAP: dict[str, str] = {
    "BENIGN":                        "BENIGN",
    "DDoS":                          "VOLUMETRIC_DDOS",
    "Portscan":                      "PORT_SCAN",
    "DoS Hulk":                      "DATA_EXFILTRATION",
    "DoS Hulk - Attempted":          "DATA_EXFILTRATION",
    "DoS GoldenEye":                 "DATA_EXFILTRATION",
    "DoS GoldenEye - Attempted":     "DATA_EXFILTRATION",
    "DoS Slowloris":                 "DATA_EXFILTRATION",
    "DoS Slowloris - Attempted":     "DATA_EXFILTRATION",
    "DoS Slowhttptest":              "DATA_EXFILTRATION",
    "DoS Slowhttptest - Attempted":  "DATA_EXFILTRATION",
    "Infiltration - Portscan":       "PORT_SCAN",
    "Infiltration":                  "DATA_EXFILTRATION",
    "Infiltration - Attempted":      "DATA_EXFILTRATION",
}

def _banner(msg: str) -> None:
    bar = "=" * 64
    print(f"\n{bar}\n  {msg}\n{bar}")

def run_test() -> None:
    _banner("Model A (Flow) — Massive Dataset Evaluation")

    print(f"[*] Loading Model A from {MODELS_DIR} ...")
    flow_model = xgb.XGBClassifier()
    flow_model.load_model(MODELS_DIR / "flow_model.json")
    flow_le = joblib.load(MODELS_DIR / "flow_label_encoder.pkl")
    flow_classes = list(flow_le.classes_)
    print(f"[*] Flow Model Classes: {flow_classes}")

    # 1. Load the massive flow dataset
    dfs = []
    for file in FILES:
        print(f"[*] Reading {file.name} ...")
        df_part = pd.read_csv(file, low_memory=False)
        dfs.append(df_part)
    
    df_flow = pd.concat(dfs, ignore_index=True)
    print(f"[*] Total Flow Rows loaded: {len(df_flow):,}")

    df_flow["true_class"] = df_flow["Label"].str.strip().map(FLOW_LABEL_MAP)
    df_flow_known = df_flow.dropna(subset=["true_class"]).copy()
    print(f"[*] Filtered to known classes: {len(df_flow_known):,} rows")

    # Feature extraction
    print("[*] Extracting Flow features (this might take a minute) ...")
    X_flow = extract_flow_features(df_flow_known)
    
    import json
    train_cols = json.loads((MODELS_DIR / "flow_feature_columns.json").read_text(encoding="utf-8"))
    X_flow = X_flow.reindex(columns=train_cols, fill_value=0)
    
    print("[*] Running Flow inference ...")
    flow_preds = flow_model.predict(X_flow)
    df_flow_known["predicted_class"] = flow_le.inverse_transform(flow_preds)

    report_flow = classification_report(
        df_flow_known["true_class"], df_flow_known["predicted_class"],
        labels=sorted(df_flow_known["true_class"].unique()),
        zero_division=0,
    )
    print(f"\n--- FLOW MODEL RESULTS ---\n{report_flow}")


    # 2. Evaluate DNS Model
    _banner("Model B (DNS) — Evaluation")
    
    if not DNS_DATASET.exists():
        print(f"[-] DNS dataset not found at {DNS_DATASET}")
        report_dns = "Not evaluated (DNS dataset missing)"
    else:
        print(f"[*] Loading Model B from {MODELS_DIR} ...")
        dns_model = xgb.XGBClassifier()
        dns_model.load_model(MODELS_DIR / "dns_model.json")
        dns_le = joblib.load(MODELS_DIR / "dns_label_encoder.pkl")
        dns_vec = joblib.load(MODELS_DIR / "dns_vectorizer.pkl")
        print(f"[*] DNS Model Classes: {list(dns_le.classes_)}")

        print(f"[*] Reading {DNS_DATASET.name} ...")
        df_dns = pd.read_csv(DNS_DATASET)
        print(f"[*] Total DNS Rows loaded: {len(df_dns):,}")

        X_dns = extract_dns_features(df_dns, dns_vec)
        dns_preds = dns_model.predict(X_dns)
        df_dns["predicted_class"] = dns_le.inverse_transform(dns_preds)

        report_dns = classification_report(
            df_dns["threat_class"], df_dns["predicted_class"],
            zero_division=0,
        )
        print(f"\n--- DNS MODEL RESULTS ---\n{report_dns}")

    
    # 3. Save Summary
    _banner("Saving Results")
    summary_lines = textwrap.dedent(f"""
        Test run             : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        Flow Dataset Rows    : {len(df_flow_known):,}
        DNS Dataset Rows     : {len(df_dns) if DNS_DATASET.exists() else 0:,}

        === FLOW MODEL (Model A) REPORT ===
        {report_flow}

        === DNS MODEL (Model B) REPORT ===
        {report_dns}
    """).strip()

    txt_path = RESULTS_DIR / "full_evaluation_summary.txt"
    txt_path.write_text(summary_lines, encoding="utf-8")
    print(f"[+] Saved summary -> {txt_path}")

    # Flow predictions CSV
    out_cols = ["Label", "true_class", "predicted_class", "Src IP", "Dst IP", "Src Port", "Dst Port", "Protocol"]
    csv_path = RESULTS_DIR / "full_evaluation_predictions.csv"
    df_flow_known[out_cols].to_csv(csv_path, index=False)
    print(f"[+] Saved predictions CSV -> {csv_path}")

if __name__ == "__main__":
    run_test()
