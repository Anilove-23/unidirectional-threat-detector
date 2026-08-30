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
# Shared XGBoost hyper-parameters
# ---------------------------------------------------------------------------
XGB_PARAMS: dict = dict(
    objective          = "multi:softprob",
    n_estimators       = 300,
    max_depth          = 6,
    learning_rate      = 0.1,
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

    # -- Load ----------------------------------------------------------------
    df = pd.read_csv(DATA_DIR / "flow_attacks_dataset.csv", low_memory=False)
    print(f"  Loaded   : {df.shape[0]:,} rows x {df.shape[1]} cols")

    # -- Remap CICIDS labels -> P1 threat classes ----------------------------
    label_col = "Label" if "Label" in df.columns else "threat_class"
    df["threat_class"] = df[label_col].str.strip().map(FLOW_LABEL_MAP)
    before = len(df)
    df = df.dropna(subset=["threat_class"])   # drop out-of-scope rows
    print(f"  Remapped : {len(df):,} rows kept ({before - len(df)} out-of-scope dropped)")
    print(f"  Class dist:\n{df['threat_class'].value_counts().to_string()}")

    # -- Label encode --------------------------------------------------------
    le_flow = LabelEncoder()
    y = le_flow.fit_transform(df["threat_class"])
    joblib.dump(le_flow, MODELS_DIR / "flow_label_encoder.pkl")
    print(f"\n  Classes  : {list(le_flow.classes_)}")
    print(f"  Saved    : flow_label_encoder.pkl")

    # -- Feature extraction --------------------------------------------------
    X = extract_flow_features(df)
    print(f"  Features : {X.shape[1]} columns after cleaning")

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
# Detects: DGA | DNS_TUNNEL | BENIGN
# =============================================================================

def train_dns_model() -> None:
    _banner("MODEL B — DNS Lexical Classifier (Person 1)")

    # -- Load ----------------------------------------------------------------
    df = pd.read_csv(DATA_DIR / "dns_dataset.csv")
    print(f"  Loaded   : {df.shape[0]:,} rows x {df.shape[1]} cols")
    print(f"  Class dist:\n{df['threat_class'].value_counts().to_string()}")

    # -- Label encode --------------------------------------------------------
    le_dns = LabelEncoder()
    y = le_dns.fit_transform(df["threat_class"].str.strip())
    joblib.dump(le_dns, MODELS_DIR / "dns_label_encoder.pkl")
    print(f"\n  Classes  : {list(le_dns.classes_)}")
    print(f"  Saved    : dns_label_encoder.pkl")

    # -- Feature extraction (fits + saves CountVectorizer) -------------------
    X, _ = extract_dns_features(df, fit=True)
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
