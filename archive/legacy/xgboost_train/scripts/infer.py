"""
scripts/infer.py
================
Person 1 — Supervised Feature Analytics Engineer

Inference helpers: load trained XGBoost models and return class-probability
dictionaries.  This is Person 1's public API surface — Person 2's ensemble
layer calls these functions and consumes the dicts.

Person 1's responsibility ends here.  The ensemble scoring that combines
these probabilities with LSTM and Isolation Forest scores is Person 2's job.

Usage (as a module)
-------------------
    from scripts.infer import predict_flow_proba, predict_dns_proba

    # Single-row dict from the ingestion FlowObject
    flow_proba = predict_flow_proba(flow_record_dict)
    # e.g. {'BENIGN': 0.01, 'DATA_EXFILTRATION': 0.02,
    #        'PORT_SCAN': 0.03, 'VOLUMETRIC_DDOS': 0.94}

    dns_proba = predict_dns_proba("xkcd123.ru")
    # e.g. {'BENIGN': 0.03, 'DGA': 0.95, 'DNS_TUNNEL': 0.02}

Usage (standalone smoke-test)
------------------------------
    uv run python xgboost_train/scripts/infer.py
"""

from __future__ import annotations

import sys
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))

import joblib
import numpy as np
import pandas as pd
import xgboost as xgb

from features import extract_dns_features, extract_flow_features

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
MODELS_DIR = SCRIPTS_DIR.parent / "models"


# ---------------------------------------------------------------------------
# Lazy-loaded singletons (loaded once on first call)
# ---------------------------------------------------------------------------
_flow_model:   xgb.XGBClassifier | None = None
_flow_le:      object | None = None

_dns_model:    xgb.XGBClassifier | None = None
_dns_le:       object | None = None
_dns_vec:      object | None = None


def _load_flow() -> tuple:
    global _flow_model, _flow_le
    if _flow_model is None:
        _flow_model = xgb.XGBClassifier()
        _flow_model.load_model(MODELS_DIR / "flow_model.json")
        _flow_le = joblib.load(MODELS_DIR / "flow_label_encoder.pkl")
    return _flow_model, _flow_le


def _load_dns() -> tuple:
    global _dns_model, _dns_le, _dns_vec
    if _dns_model is None:
        _dns_model = xgb.XGBClassifier()
        _dns_model.load_model(MODELS_DIR / "dns_model.json")
        _dns_le  = joblib.load(MODELS_DIR / "dns_label_encoder.pkl")
        _dns_vec = joblib.load(MODELS_DIR / "dns_vectorizer.pkl")
    return _dns_model, _dns_le, _dns_vec


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def predict_flow_proba(record: dict | pd.DataFrame) -> dict[str, float]:
    """
    Return a class-probability dictionary for a network flow record.

    Parameters
    ----------
    record : dict  — single flow as a flat key-value dict (e.g. from FlowObject)
               or pd.DataFrame — batch of flows (one row per flow).

    Returns
    -------
    dict  — {class_name: probability} sorted descending by probability.
            For a batch DataFrame, returns a list of dicts (one per row).

    Example return value (single record)
    -------------------------------------
    {'VOLUMETRIC_DDOS': 0.9412, 'BENIGN': 0.0341,
     'PORT_SCAN': 0.0147, 'DATA_EXFILTRATION': 0.0100}
    """
    model, le = _load_flow()

    if isinstance(record, dict):
        df = pd.DataFrame([record])
        X  = extract_flow_features(df)
        proba = model.predict_proba(X)[0]          # 1-D array
        result = {cls: float(p) for cls, p in zip(le.classes_, proba)}
        return dict(sorted(result.items(), key=lambda kv: kv[1], reverse=True))

    # Batch path
    X = extract_flow_features(record)
    probas = model.predict_proba(X)                # 2-D array
    return [
        dict(sorted(
            {cls: float(p) for cls, p in zip(le.classes_, row)}.items(),
            key=lambda kv: kv[1], reverse=True,
        ))
        for row in probas
    ]


def predict_dns_proba(domain: str | list[str]) -> dict[str, float] | list[dict]:
    """
    Return a class-probability dictionary for one or more domain name strings.

    Parameters
    ----------
    domain : str        — single domain name string.
             list[str]  — batch of domain strings.

    Returns
    -------
    dict  — {class_name: probability} sorted descending by probability.
            For a list input, returns a list of dicts.

    Example return value (single domain)
    --------------------------------------
    {'DGA': 0.9521, 'DNS_TUNNEL': 0.0312, 'BENIGN': 0.0167}
    """
    model, le, vec = _load_dns()

    domains = [domain] if isinstance(domain, str) else domain
    df = pd.DataFrame({"domain": domains})
    X, _ = extract_dns_features(df, vectorizer=vec, fit=False)

    probas = model.predict_proba(X)               # 2-D array

    results = [
        dict(sorted(
            {cls: float(p) for cls, p in zip(le.classes_, row)}.items(),
            key=lambda kv: kv[1], reverse=True,
        ))
        for row in probas
    ]

    return results[0] if isinstance(domain, str) else results


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import json

    DATA_DIR = SCRIPTS_DIR.parent / "data"

    print("\n=== Model A — Flow Inference Smoke Test ===")
    # Load one real row per class from the training CSV so all 60 columns are present
    flow_df = pd.read_csv(DATA_DIR / "flow_attacks_dataset.csv", low_memory=False)
    sample_row = flow_df.iloc[[0]]   # single row — feature extractor will align columns
    result_a = predict_flow_proba(sample_row)
    print(f"  Label in CSV : {flow_df['Label'].iloc[0]}")
    print(f"  Predicted    : {json.dumps(result_a, indent=2)}")

    print("\n=== Model B — DNS Inference Smoke Test ===")
    test_domains = [
        "google.com",                                  # benign
        "uvsdqfgbshe.org",                             # DGA (Conficker)
        "a12239e94a6f0567fed9.tunnel.c2.example.com",  # DNS tunnel
    ]
    for domain in test_domains:
        result_b = predict_dns_proba(domain)
        print(f"  {domain[:55]:<55}  ->  {json.dumps(result_b)}")
