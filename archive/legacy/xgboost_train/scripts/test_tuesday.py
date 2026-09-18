"""
scripts/test_tuesday.py
========================
Person 1 — Supervised Feature Analytics Engineer

Tests Model A (flow classifier) on an unseen dataset:
  ingestion/dataset/CICIDS2017_improved/tuesday.csv

Tuesday contains: BENIGN, FTP-Patator, SSH-Patator (brute-force labels).
These are NOT in Person 1's five target classes, so the test has two goals:

  1. Verify Model A correctly classifies the large BENIGN majority.
  2. Show how unrecognised threat types (brute-force) manifest in the
     probability output — useful diagnostic for Person 2's ensemble.

Results saved to:
  xgboost_train/results/tuesday_predictions.csv   — row-level predictions
  xgboost_train/results/tuesday_summary.txt        — metrics + class report

Usage
-----
  uv run python xgboost_train/scripts/test_tuesday.py
"""

from __future__ import annotations

import sys
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))

import json
import textwrap
from datetime import datetime

import numpy as np
import pandas as pd
import xgboost as xgb
import joblib
from sklearn.metrics import classification_report, confusion_matrix

from features import extract_flow_features

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
ROOT        = SCRIPTS_DIR.parent
MODELS_DIR  = ROOT / "models"
RESULTS_DIR = ROOT / "results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

TUESDAY_CSV  = Path(__file__).resolve().parents[2] / "ingestion" / "dataset" / "CICIDS2017_improved" / "tuesday.csv"

# Same label map used during training — rows not in this map get threat_class = "UNKNOWN"
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
}


def _banner(msg: str) -> None:
    bar = "=" * 64
    print(f"\n{bar}\n  {msg}\n{bar}")


def run_test() -> None:
    _banner("Model A — Tuesday.csv Evaluation")

    # -- Load model & encoder ------------------------------------------------
    print(f"  Loading model from {MODELS_DIR} ...")
    model = xgb.XGBClassifier()
    model.load_model(MODELS_DIR / "flow_model.json")
    le = joblib.load(MODELS_DIR / "flow_label_encoder.pkl")
    classes = list(le.classes_)
    print(f"  Model classes : {classes}")

    # -- Load tuesday.csv ----------------------------------------------------
    print(f"\n  Reading {TUESDAY_CSV} ...")
    df_raw = pd.read_csv(TUESDAY_CSV, low_memory=False)
    print(f"  Rows loaded   : {len(df_raw):,}")
    print(f"  Original label distribution:")
    print(df_raw["Label"].value_counts().to_string())

    # -- Map known labels; mark unknowns -------------------------------------
    df_raw["true_class"] = df_raw["Label"].str.strip().map(FLOW_LABEL_MAP).fillna("UNKNOWN")

    # -- Feature extraction --------------------------------------------------
    print(f"  Extracting features ...")
    X = extract_flow_features(df_raw)
    print(f"  Feature matrix (raw): {X.shape}")

    # Align to the exact columns the model was trained on
    col_path = MODELS_DIR / "flow_feature_columns.json"
    if col_path.exists():
        import json as _json
        train_cols = _json.loads(col_path.read_text(encoding="utf-8"))
        X = X.reindex(columns=train_cols, fill_value=0)
        print(f"  Feature matrix (aligned to training): {X.shape}")
    else:
        print("  WARNING: flow_feature_columns.json not found — column mismatch may occur.")
        print("           Re-run train.py to generate it.")

    # -- Predict -------------------------------------------------------------
    print(f"  Running inference ...")
    proba_matrix = model.predict_proba(X)                      # shape (N, n_classes)
    pred_indices = np.argmax(proba_matrix, axis=1)
    pred_labels  = le.inverse_transform(pred_indices)

    # -- Build results DataFrame ---------------------------------------------
    proba_df = pd.DataFrame(proba_matrix, columns=[f"p_{c}" for c in classes], index=df_raw.index)
    results = pd.concat(
        [
            df_raw[["Label", "true_class", "Src IP", "Dst IP", "Src Port", "Dst Port",
                     "Protocol", "Timestamp"]].reset_index(drop=True),
            proba_df.reset_index(drop=True),
        ],
        axis=1,
    )
    results["predicted_class"] = pred_labels
    results["confidence"]      = proba_matrix.max(axis=1).round(6)
    results["correct"]         = results["true_class"] == results["predicted_class"]

    # -- Save predictions CSV ------------------------------------------------
    csv_path = RESULTS_DIR / "tuesday_predictions.csv"
    results.to_csv(csv_path, index=False)
    print(f"\n  Saved predictions -> {csv_path}")

    # -- Compute metrics on known rows only (BENIGN) -------------------------
    known_mask = results["true_class"] != "UNKNOWN"
    known_results = results[known_mask]

    _banner("Results — Known Classes (BENIGN only in Tuesday)")

    y_true_known = known_results["true_class"]
    y_pred_known = known_results["predicted_class"]

    print(f"\n  Known rows: {known_mask.sum():,} / {len(results):,}")
    print(f"\n  Classification Report (known rows):")
    report_str = classification_report(
        y_true_known, y_pred_known,
        labels=sorted(y_true_known.unique()),
        zero_division=0,
    )
    print(report_str)

    _banner("Results — UNKNOWN labels (Brute-force: FTP/SSH-Patator)")
    unknown_results = results[~known_mask]
    print(f"\n  Unknown rows  : {len(unknown_results):,}")
    print(f"\n  Original label breakdown:")
    print(df_raw.loc[~known_mask, "Label"].value_counts().to_string())
    print(f"\n  Model prediction distribution on unknown rows:")
    print(unknown_results["predicted_class"].value_counts().to_string())
    print(f"\n  Mean probability scores on unknown rows:")
    print(unknown_results[[f"p_{c}" for c in classes]].mean().round(4).to_string())

    # -- Overall summary -----------------------------------------------------
    _banner("Overall Summary")
    total    = len(results)
    correct  = results["correct"].sum()
    accuracy = correct / total

    summary_lines = textwrap.dedent(f"""
        Test run        : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        Source file     : {TUESDAY_CSV.name}
        Total rows      : {total:,}
        Known-class rows: {known_mask.sum():,}
        Unknown rows    : {(~known_mask).sum():,}

        Accuracy (known classes)  : {known_results['correct'].mean():.4%}
        Overall accuracy          : {accuracy:.4%}

        Model classes : {classes}

        --- Classification Report (known rows) ---
        {report_str}

        --- Prediction distribution on UNKNOWN (brute-force) rows ---
        {unknown_results['predicted_class'].value_counts().to_string()}

        --- Mean probabilities on UNKNOWN rows ---
        {unknown_results[[f'p_{c}' for c in classes]].mean().round(4).to_string()}
    """).strip()

    print(summary_lines)

    txt_path = RESULTS_DIR / "tuesday_summary.txt"
    txt_path.write_text(summary_lines, encoding="utf-8")
    print(f"\n  Saved summary  -> {txt_path}")
    print(f"\n  Done.")


if __name__ == "__main__":
    run_test()
