"""
xgboost_train/tests/test_live_simulation.py
============================================
Live-simulation benchmark for Person 1's XGBoost classifiers.

DESIGN PRINCIPLE: No stale datasets are read from disk.
All test flows are generated on-the-fly using the same `generate_flow()`
factory that the live simulation pipeline uses.  This guarantees that
the measured metrics reflect the model's actual performance on the exact
distribution it will encounter at runtime.

Usage:
  cd <repo-root>
  python -m pytest xgboost_train/tests/test_live_simulation.py -v
  # or directly:
  python xgboost_train/tests/test_live_simulation.py [--n-flows 500] [--seed 0]

Outputs:
  • Per-class precision / recall / F1
  • Macro and weighted averages
  • Per-class mean prediction confidence
  • Confusion matrix
  • Overall pass/fail assertions (F1 ≥ 0.90 per class)
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional

import joblib
import numpy as np
import pandas as pd
import xgboost as xgb
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
)

# ---------------------------------------------------------------------------
# Path bootstrap: make `simulate_pipeline` and `scripts/features` importable
# ---------------------------------------------------------------------------
ROOT = Path(__file__).resolve().parents[2]   # repo root
SCRIPTS_DIR = ROOT / "xgboost_train" / "scripts"
MODELS_DIR  = ROOT / "xgboost_train" / "models"

sys.path.insert(0, str(SCRIPTS_DIR))         # features.py
sys.path.insert(0, str(ROOT))               # simulate_pipeline.py

from features import extract_flow_features, extract_dns_features  # noqa: E402
from simulate_pipeline import generate_flow  # noqa: E402

# ---------------------------------------------------------------------------
# Configurable constants
# ---------------------------------------------------------------------------

# Person 1 is responsible for these classes only.
FLOW_CLASSES = ["BENIGN", "VOLUMETRIC_DDOS", "PORT_SCAN", "DATA_EXFILTRATION"]
DNS_CLASSES  = ["BENIGN", "DGA", "DNS_TUNNELING"]

# Simulator scenario -> (label, model_type)
SCENARIO_META = {
    "ddos":    ("VOLUMETRIC_DDOS",   "flow"),
    "scan":    ("PORT_SCAN",         "flow"),
    "exfil":   ("DATA_EXFILTRATION", "flow"),
    "benign":  ("BENIGN",            "mixed"),   # benign generates both flow + dns
    "dga":     ("DGA",               "dns"),
    "dns":     ("DNS_TUNNELING",     "dns"),
}

# Minimum acceptable F1 per class (anything below = test FAILS)
MIN_F1 = 0.90

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _generate_batch(scenario: str, n: int, seed: Optional[int]) -> list[dict]:
    """Generate `n` fresh flows for a scenario with optional seeding."""
    import random
    if seed is not None:
        random.seed(seed + hash(scenario) % 1000)
    return [generate_flow(scenario) for _ in range(n)]


def _load_models():
    """Load all saved XGBoost artefacts."""
    flow_model = xgb.XGBClassifier()
    flow_model.load_model(MODELS_DIR / "flow_model.json")
    flow_le  = joblib.load(MODELS_DIR / "flow_label_encoder.pkl")
    flow_cols = json.loads((MODELS_DIR / "flow_feature_columns.json").read_text(encoding="utf-8"))

    dns_model = xgb.XGBClassifier()
    dns_model.load_model(MODELS_DIR / "dns_model.json")
    dns_le  = joblib.load(MODELS_DIR / "dns_label_encoder.pkl")
    dns_vec = joblib.load(MODELS_DIR / "dns_vectorizer.pkl")

    return {
        "flow": (flow_model, flow_le, flow_cols),
        "dns":  (dns_model,  dns_le,  dns_vec),
    }


def _flows_to_df(flows: list[dict]) -> pd.DataFrame:
    """Convert a list of raw flow dicts into a DataFrame."""
    return pd.DataFrame(flows)


def _confidence_stats(proba: np.ndarray) -> dict:
    """Return mean / min / max of the winning class probability."""
    top = proba.max(axis=1)
    return {"mean": float(top.mean()), "min": float(top.min()), "max": float(top.max())}


def _print_header(title: str) -> None:
    bar = "═" * 68
    print(f"\n{bar}")
    print(f"  {title}")
    print(bar)


def _print_confusion(cm: np.ndarray, labels: list[str]) -> None:
    df = pd.DataFrame(cm, index=labels, columns=labels)
    print("\n  Confusion Matrix (rows = true, cols = predicted):\n")
    # simple fixed-width print
    col_w = max(max(len(l) for l in labels), 8) + 2
    header = "".ljust(col_w) + "".join(l.ljust(col_w) for l in labels)
    print("  " + header)
    for i, row_label in enumerate(labels):
        row = row_label.ljust(col_w) + "".join(str(cm[i, j]).ljust(col_w) for j in range(len(labels)))
        print("  " + row)


# ---------------------------------------------------------------------------
# Core evaluation routines
# ---------------------------------------------------------------------------

def evaluate_flow_model(
    models: dict,
    n_per_class: int,
    seed: Optional[int],
) -> dict[str, float]:
    """
    Generate fresh live flows for each FLOW class, run the flow classifier,
    return per-class F1 scores.
    """
    _print_header("FLOW MODEL  ─  Live Simulation Evaluation")

    flow_model, flow_le, flow_cols = models["flow"]

    all_dicts  = []
    all_labels = []

    # Scenarios that produce non-DNS flows for FLOW_CLASSES
    flow_scenarios = {
        "ddos":   "VOLUMETRIC_DDOS",
        "scan":   "PORT_SCAN",
        "exfil":  "DATA_EXFILTRATION",
        "benign": "BENIGN",       # non-DNS benign (HTTP/TCP)
    }

    for scenario, expected_label in flow_scenarios.items():
        batch = _generate_batch(scenario, n_per_class, seed)
        # For benign we only keep the TCP flows (dns_meta == None)
        if scenario == "benign":
            batch = [f for f in batch if f.get("dns_meta") is None]
            if not batch:
                # Re-generate until we get enough TCP benign flows
                extra_batch = []
                attempts = 0
                while len(extra_batch) < n_per_class and attempts < n_per_class * 5:
                    f = generate_flow("benign")
                    if f.get("dns_meta") is None:
                        extra_batch.append(f)
                    attempts += 1
                batch = extra_batch

        for f in batch:
            all_dicts.append(f)
            all_labels.append(expected_label)

    df = _flows_to_df(all_dicts)
    df["collected_label"] = all_labels   # ensure label column exists

    X = extract_flow_features(df)
    X = X.reindex(columns=flow_cols, fill_value=0)

    # Raw predict returns class indices
    raw = flow_model.predict(X)
    y_pred_idx = np.argmax(raw, axis=1) if raw.ndim == 2 else raw.astype(int)
    y_pred = flow_le.inverse_transform(y_pred_idx)

    # Probabilities for confidence reporting
    proba = flow_model.predict_proba(X)

    # Filter to only classes the model knows
    mask = pd.Series(all_labels).isin(flow_le.classes_)
    y_true = pd.Series(all_labels)[mask].values
    y_pred = y_pred[mask.values]
    proba  = proba[mask.values]

    print(f"\n  Evaluated {len(y_true)} fresh simulation flows across {len(flow_scenarios)} classes.\n")

    report = classification_report(
        y_true, y_pred,
        labels=flow_le.classes_,
        target_names=flow_le.classes_,
        output_dict=True,
        zero_division=0,
    )
    print(classification_report(
        y_true, y_pred,
        labels=flow_le.classes_,
        target_names=flow_le.classes_,
        zero_division=0,
    ))

    # Confidence per true class
    print("  Per-class Prediction Confidence (winning-class probability):")
    for i, cls in enumerate(flow_le.classes_):
        cls_mask = y_true == cls
        if cls_mask.sum() == 0:
            continue
        stats = _confidence_stats(proba[cls_mask])
        print(f"    {cls:<22}  mean={stats['mean']:.3f}  min={stats['min']:.3f}  max={stats['max']:.3f}")

    cm = confusion_matrix(y_true, y_pred, labels=flow_le.classes_)
    _print_confusion(cm, list(flow_le.classes_))

    # Return per-class F1
    return {cls: report[cls]["f1-score"] for cls in flow_le.classes_ if cls in report}


def evaluate_dns_model(
    models: dict,
    n_per_class: int,
    seed: Optional[int],
) -> dict[str, float]:
    """
    Generate fresh live DNS flows for each DNS class, run the DNS classifier,
    return per-class F1 scores.
    """
    _print_header("DNS MODEL  ─  Live Simulation Evaluation")

    dns_model, dns_le, dns_vec = models["dns"]

    dns_scenarios = {
        "dga":    "DGA",
        "dns":    "DNS_TUNNELING",
        "benign": "BENIGN",   # DNS-only benign
    }

    all_dicts  = []
    all_labels = []

    for scenario, expected_label in dns_scenarios.items():
        batch = _generate_batch(scenario, n_per_class, seed)

        # For benign we only keep the DNS flows (dns_meta != None)
        if scenario == "benign":
            batch = [f for f in batch if f.get("dns_meta") is not None]
            if not batch:
                extra_batch = []
                attempts = 0
                while len(extra_batch) < n_per_class and attempts < n_per_class * 5:
                    f = generate_flow("benign")
                    if f.get("dns_meta") is not None:
                        extra_batch.append(f)
                    attempts += 1
                batch = extra_batch

        for f in batch:
            all_dicts.append(f)
            all_labels.append(expected_label)

    df = _flows_to_df(all_dicts)
    df["collected_label"] = all_labels
    df["domain"] = df["dns_meta"].apply(lambda x: x.get("query_name", "") if isinstance(x, dict) else "")

    X, _ = extract_dns_features(df, vectorizer=dns_vec, fit=False)

    raw = dns_model.predict(X)
    y_pred_idx = np.argmax(raw, axis=1) if raw.ndim == 2 else raw.astype(int)
    y_pred = dns_le.inverse_transform(y_pred_idx)
    proba  = dns_model.predict_proba(X)

    mask = pd.Series(all_labels).isin(dns_le.classes_)
    y_true = pd.Series(all_labels)[mask].values
    y_pred = y_pred[mask.values]
    proba  = proba[mask.values]

    print(f"\n  Evaluated {len(y_true)} fresh simulation flows across {len(dns_scenarios)} classes.\n")

    report = classification_report(
        y_true, y_pred,
        labels=dns_le.classes_,
        target_names=dns_le.classes_,
        output_dict=True,
        zero_division=0,
    )
    print(classification_report(
        y_true, y_pred,
        labels=dns_le.classes_,
        target_names=dns_le.classes_,
        zero_division=0,
    ))

    print("  Per-class Prediction Confidence (winning-class probability):")
    for i, cls in enumerate(dns_le.classes_):
        cls_mask = y_true == cls
        if cls_mask.sum() == 0:
            continue
        stats = _confidence_stats(proba[cls_mask])
        print(f"    {cls:<22}  mean={stats['mean']:.3f}  min={stats['min']:.3f}  max={stats['max']:.3f}")

    cm = confusion_matrix(y_true, y_pred, labels=dns_le.classes_)
    _print_confusion(cm, list(dns_le.classes_))

    return {cls: report[cls]["f1-score"] for cls in dns_le.classes_ if cls in report}


# ---------------------------------------------------------------------------
# Summary & assertion
# ---------------------------------------------------------------------------

def print_summary(flow_f1: dict, dns_f1: dict) -> bool:
    """Print combined summary table and return True if all F1 ≥ MIN_F1."""
    _print_header(f"SUMMARY  ─  Minimum Acceptable F1 = {MIN_F1:.2f}")

    all_pass = True
    rows = []

    for cls, f1 in flow_f1.items():
        ok = f1 >= MIN_F1
        if not ok:
            all_pass = False
        rows.append(("Flow", cls, f"{f1:.4f}", "✓ PASS" if ok else "✗ FAIL"))

    for cls, f1 in dns_f1.items():
        ok = f1 >= MIN_F1
        if not ok:
            all_pass = False
        rows.append(("DNS", cls, f"{f1:.4f}", "✓ PASS" if ok else "✗ FAIL"))

    print(f"\n  {'Model':<8}  {'Class':<26}  {'F1':>7}  {'Status'}")
    print(f"  {'─'*8}  {'─'*26}  {'─'*7}  {'─'*8}")
    for model, cls, f1, status in rows:
        print(f"  {model:<8}  {cls:<26}  {f1:>7}  {status}")

    print()
    if all_pass:
        print("  ✅  ALL CLASSES PASS  ─  Models are production-ready.\n")
    else:
        print("  ❌  SOME CLASSES FAILED  ─  Review confusion matrix above.\n")

    return all_pass


# ---------------------------------------------------------------------------
# pytest hooks (so `pytest` can discover and run this as a test module)
# ---------------------------------------------------------------------------

def test_flow_model_live_simulation():
    """pytest entry-point: flow model must hit F1 ≥ 0.90 on all classes."""
    models = _load_models()
    flow_f1 = evaluate_flow_model(models, n_per_class=200, seed=42)
    for cls, f1 in flow_f1.items():
        assert f1 >= MIN_F1, (
            f"Flow model F1 for '{cls}' = {f1:.4f} — below threshold {MIN_F1}"
        )


def test_dns_model_live_simulation():
    """pytest entry-point: DNS model must hit F1 ≥ 0.90 on all classes."""
    models = _load_models()
    dns_f1 = evaluate_dns_model(models, n_per_class=200, seed=42)
    for cls, f1 in dns_f1.items():
        assert f1 >= MIN_F1, (
            f"DNS model F1 for '{cls}' = {f1:.4f} — below threshold {MIN_F1}"
        )


# ---------------------------------------------------------------------------
# Direct CLI execution
# ---------------------------------------------------------------------------

def main():
    global MIN_F1  # noqa: PLW0603
    _default_f1 = MIN_F1

    parser = argparse.ArgumentParser(
        description="Live-simulation XGBoost benchmark — no stale data"
    )
    parser.add_argument(
        "--n-flows", type=int, default=300,
        help="Flows to generate per class (default: 300)"
    )
    parser.add_argument(
        "--seed", type=int, default=None,
        help="Random seed for reproducibility (default: unseeded)"
    )
    parser.add_argument(
        "--min-f1", type=float, default=_default_f1,
        help=f"Minimum acceptable F1 per class (default: {_default_f1})"
    )
    args = parser.parse_args()
    MIN_F1 = args.min_f1

    print("\n" + "═" * 68)
    print("  Person 1 — XGBoost Live Simulation Benchmark")
    print(f"  Flows per class : {args.n_flows}")
    print(f"  Seed            : {args.seed if args.seed is not None else 'unseeded (fully random)'}")
    print(f"  Min F1 threshold: {MIN_F1}")
    print("  Data source     : generate_flow() — no stale files read")
    print("═" * 68)

    models = _load_models()

    flow_f1 = evaluate_flow_model(models, n_per_class=args.n_flows, seed=args.seed)
    dns_f1  = evaluate_dns_model(models,  n_per_class=args.n_flows, seed=args.seed)

    passed = print_summary(flow_f1, dns_f1)
    sys.exit(0 if passed else 1)


if __name__ == "__main__":
    main()
