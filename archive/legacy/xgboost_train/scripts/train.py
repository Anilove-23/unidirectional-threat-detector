"""
scripts/train.py
================
Person 1 — Supervised Feature Analytics Engineer

Trains and persists two XGBoost classifiers:

  Model A  (flow_model.json)
      Detects volumetric/connection-layer threats from network flow statistics.
      Classes: BENIGN | VOLUMETRIC_DDOS | PORT_SCAN | DATA_EXFILTRATION

  Model B  (dns_model.json)
      Detects DNS-layer threats from domain lexical features.
      Classes: BENIGN | DGA | DNS_TUNNEL

Both models output a class-probability dictionary.
Person 2's ensemble layer consumes those dicts; no ensemble logic is built here.

OUT OF SCOPE — NOT IMPLEMENTED HERE:
  - PyTorch / LSTMs / sequence memory models         (Person 2)
  - Isolation Forests / Autoencoders                 (Person 2)
  - TLS/QUIC features: JA3/JA4, cipher-suite order  (Person 2)
  - Final ensemble scoring                           (Person 2)

Usage
-----
  uv run python xgboost_train/scripts/train.py

Artefacts written to  xgboost_train/models/
  flow_model.json           XGBoost native format
  dns_model.json            XGBoost native format
  flow_label_encoder.pkl    sklearn LabelEncoder
  dns_label_encoder.pkl     sklearn LabelEncoder
  dns_vectorizer.pkl        sklearn CountVectorizer  (written by features.py)
"""

from __future__ import annotations

import sys
from pathlib import Path

# Fix Windows terminal encoding (cp1252 -> utf-8) before any print()
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

# Make scripts/ importable regardless of CWD
SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))

import joblib
import numpy as np
import pandas as pd
import xgboost as xgb
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

from features import extract_dns_features, extract_flow_features

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
ROOT       = SCRIPTS_DIR.parent
DATA_DIR   = ROOT / "data"
MODELS_DIR = ROOT / "models"
MODELS_DIR.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------------------
# CICIDS label -> Person 1 threat class mapping
# Labels not in this map are DROPPED (e.g. Botnet — not in P1 scope).
# ---------------------------------------------------------------------------
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

# ---------------------------------------------------------------------------
# Shared XGBoost hyper-parameters (regularized to prevent overfitting)
# ---------------------------------------------------------------------------
XGB_PARAMS: dict = dict(
    objective          = "multi:softprob",
    n_estimators       = 150,
    max_depth          = 4,
    learning_rate      = 0.08,
    min_child_weight   = 3,
    reg_alpha          = 0.1,
    reg_lambda         = 1.0,
    subsample          = 0.8,
    colsample_bytree   = 0.8,
    eval_metric        = "mlogloss",
    early_stopping_rounds = 20,
    random_state       = 42,
    n_jobs             = -1,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _banner(title: str) -> None:
    bar = "=" * 64
    print(f"\n{bar}\n  {title}\n{bar}")


def _evaluate(
    model: xgb.XGBClassifier,
    X_test: pd.DataFrame,
    y_test: np.ndarray,
    le: LabelEncoder,
    name: str,
) -> None:
    """
    Print classification_report and confusion_matrix.
    Handles multi:softprob output (2-D probability array) for both binary
    and multiclass cases by calling argmax when ndim == 2.
    """
    raw = model.predict(X_test)
    y_pred = np.argmax(raw, axis=1) if raw.ndim == 2 else raw.astype(int)

    print(f"\n--- {name}: Classification Report ---")
    print(classification_report(y_test, y_pred, target_names=le.classes_, zero_division=0))
    print(f"--- {name}: Confusion Matrix (rows=true, cols=pred) ---")
    print(pd.DataFrame(
        confusion_matrix(y_test, y_pred),
        index=le.classes_,
        columns=le.classes_,
    ).to_string())


# =============================================================================
# MODEL A — Flow Attack Classifier
# Detects: VOLUMETRIC_DDOS | PORT_SCAN | DATA_EXFILTRATION | BENIGN
# =============================================================================

def train_flow_model() -> None:
    _banner("MODEL A — Flow Attack Classifier (Person 1)")

    # -- Load synthetic multi-scale flows (Person 1 FlowObject schema) ----------
    synth_path = ROOT / "dataset" / "p1_synthetic_evaluation.jsonl"
    if not synth_path.exists():
        print(f"[*] Generating synthetic flow dataset at {synth_path}...")
        import subprocess
        subprocess.run([sys.executable, str(SCRIPTS_DIR / "generate_p1_dataset.py")], check=True)

    df_synth = pd.read_json(synth_path, lines=True)
    df_flow = df_synth[df_synth["dns_meta"].isnull() & df_synth["collected_label"].isin([
        "BENIGN", "VOLUMETRIC_DDOS", "PORT_SCAN", "DATA_EXFILTRATION"
    ])].copy()
    print(f"  Loaded Synthetic Flow Objects: {len(df_flow):,} rows")

    # -- Optionally blend with CICIDS flow attacks dataset if available --------
    cicids_path = DATA_DIR / "flow_attacks_dataset.csv"
    if cicids_path.exists():
        print(f"  Loading CICIDS reference data: {cicids_path.name}")
        df_cic = pd.read_csv(cicids_path, low_memory=False)
        label_col = "Label" if "Label" in df_cic.columns else "threat_class"
        df_cic["threat_class"] = df_cic[label_col].str.strip().map(FLOW_LABEL_MAP)
        df_cic = df_cic.dropna(subset=["threat_class"])
        # Sample balanced subset from CICIDS to avoid class imbalance
        sampled_dfs = []
        for _, group in df_cic.groupby("threat_class"):
            sampled_dfs.append(group.sample(min(len(group), 2500), random_state=42))
        df_cic_sampled = pd.concat(sampled_dfs, ignore_index=True)
        print(f"  Blended CICIDS subset: {len(df_cic_sampled):,} rows")
        X_cic = extract_flow_features(df_cic_sampled)
        y_cic = df_cic_sampled["threat_class"].values
    else:
        X_cic, y_cic = None, None

    # -- Feature extraction on Flow Objects -----------------------------------
    X_flow = extract_flow_features(df_flow)
    y_flow = df_flow["collected_label"].values

    if X_cic is not None:
        X = pd.concat([X_flow, X_cic], ignore_index=True)
        y_raw = np.concatenate([y_flow, y_cic])
    else:
        X = X_flow
        y_raw = y_flow

    # -- Label encode --------------------------------------------------------
    le_flow = LabelEncoder()
    y = le_flow.fit_transform(y_raw)
    joblib.dump(le_flow, MODELS_DIR / "flow_label_encoder.pkl")
    print(f"\n  Classes  : {list(le_flow.classes_)}")
    print(f"  Saved    : flow_label_encoder.pkl")

    # Persist column list so test scripts can align unseen data exactly
    import json as _json
    col_path = MODELS_DIR / "flow_feature_columns.json"
    col_path.write_text(_json.dumps(list(X.columns)), encoding="utf-8")
    print(f"  Saved    : flow_feature_columns.json ({len(X.columns)} cols)")

    # -- Split ---------------------------------------------------------------
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"  Split    : {len(X_train):,} train / {len(X_test):,} test")

    # -- Train ---------------------------------------------------------------
    model_a = xgb.XGBClassifier(
        **XGB_PARAMS,
        num_class=len(le_flow.classes_),
    )
    model_a.fit(X_train, y_train, eval_set=[(X_test, y_test)], verbose=50)

    # -- Evaluate ------------------------------------------------------------
    _evaluate(model_a, X_test, y_test, le_flow, "Model A (Flow)")

    # -- Save ----------------------------------------------------------------
    out = MODELS_DIR / "flow_model.json"
    model_a.save_model(out)
    print(f"\n  Saved    : {out}")


# =============================================================================
# MODEL B — DNS Lexical Classifier
# Detects: DGA | DNS_TUNNELING | BENIGN
# =============================================================================

def train_dns_model() -> None:
    _banner("MODEL B — DNS Lexical Classifier (Person 1)")

    # -- Load CSV base dataset -----------------------------------------------
    df_csv = pd.read_csv(DATA_DIR / "dns_dataset.csv")
    df_csv["threat_class"] = df_csv["threat_class"].str.strip().replace({"DNS_TUNNEL": "DNS_TUNNELING"})
    print(f"  Loaded CSV : {df_csv.shape[0]:,} rows x {df_csv.shape[1]} cols")

    # -- Load synthetic DNS queries for live generator domain patterns -------
    synth_path = ROOT / "dataset" / "p1_synthetic_evaluation.jsonl"
    if synth_path.exists():
        df_synth = pd.read_json(synth_path, lines=True)
        df_synth_dns = df_synth[df_synth["dns_meta"].notnull()].copy()
        df_synth_dns["domain"] = df_synth_dns["dns_meta"].apply(lambda x: x["query_name"])
        df_synth_dns["threat_class"] = df_synth_dns["collected_label"]
        df_combined = pd.concat([df_csv[["domain", "threat_class"]], df_synth_dns[["domain", "threat_class"]]], ignore_index=True)
    else:
        df_combined = df_csv[["domain", "threat_class"]]

    print(f"  Combined DNS rows: {len(df_combined):,}")
    print(f"  Class dist:\n{df_combined['threat_class'].value_counts().to_string()}")

    # -- Label encode --------------------------------------------------------
    le_dns = LabelEncoder()
    y = le_dns.fit_transform(df_combined["threat_class"])
    joblib.dump(le_dns, MODELS_DIR / "dns_label_encoder.pkl")
    print(f"\n  Classes  : {list(le_dns.classes_)}")
    print(f"  Saved    : dns_label_encoder.pkl")

    # -- Feature extraction (fits + saves CountVectorizer) -------------------
    X, _ = extract_dns_features(df_combined, fit=True)
    print(f"  Features : {X.shape[1]} columns")

    # -- Split ---------------------------------------------------------------
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"  Split    : {len(X_train):,} train / {len(X_test):,} test")

    # -- Train ---------------------------------------------------------------
    model_b = xgb.XGBClassifier(
        **XGB_PARAMS,
        num_class=len(le_dns.classes_),
    )
    model_b.fit(X_train, y_train, eval_set=[(X_test, y_test)], verbose=50)

    # -- Evaluate ------------------------------------------------------------
    _evaluate(model_b, X_test, y_test, le_dns, "Model B (DNS)")

    # -- Save ----------------------------------------------------------------
    out = MODELS_DIR / "dns_model.json"
    model_b.save_model(out)
    print(f"\n  Saved    : {out}")


# =============================================================================
# Entry point
# =============================================================================

if __name__ == "__main__":
    train_flow_model()
    train_dns_model()

    _banner("Training Complete — Artefacts")
    for f in sorted(MODELS_DIR.iterdir()):
        print(f"  {f.name:<35}  {f.stat().st_size / 1024:>8.1f} KB")
