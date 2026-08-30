"""
scripts/features.py
===================
Person 1 — Supervised Feature Analytics Engineer
Standalone feature extraction for two XGBoost classifiers.

Designed to be imported by both:
  • train.py  (offline training)
  • infer.py  (live stream inference)

OUT OF SCOPE — DO NOT ADD:
  • JA3 / JA4 / TLS cipher-suite features  (Person 2)
  • Sequence / temporal features (IAT sequences as time-series)  (Person 2)
  • Unsupervised anomaly scores  (Person 2)
  • Ensemble scoring  (Person 2)

Libraries: pandas, numpy, scipy.stats.entropy, sklearn.CountVectorizer, joblib
"""

from __future__ import annotations

import ast
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from scipy.stats import entropy as scipy_entropy
from sklearn.feature_extraction.text import CountVectorizer

# ---------------------------------------------------------------------------
# Artefact directory (sibling of scripts/)
# ---------------------------------------------------------------------------
MODELS_DIR = Path(__file__).resolve().parent.parent / "models"

# ---------------------------------------------------------------------------
# Columns that must never enter the flow feature matrix
# ---------------------------------------------------------------------------
_FLOW_DROP_COLS: list[str] = [
    # CICIDS identifiers / admin
    "id", "Flow ID", "Src IP", "Dst IP", "Timestamp", "Attempted Category",
    # Label columns (all variants)
    "Label", "threat_class",
    # FlowObject identifiers
    "flow_id", "src_ip", "dst_ip", "first_seen", "last_seen",
    "sensor_id", "capture_interface", "pipeline_version", "schema_version",
    # Raw list columns (expanded into aggregates below when present)
    "packet_sizes", "inter_arrival_times",
    # Flag list (non-numeric string)
    "tcp_flags_seen",
    # Protocol string — Person 2 uses this for TLS routing, not a flow stat
    "protocol", "Protocol",
]


# ===========================================================================
# MODEL A — Flow feature extraction
# ===========================================================================

def extract_flow_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Return a clean, fully-numeric feature matrix from a flow DataFrame.

    Handles two source formats transparently:

    FlowObject format (live ingestion pipeline)
        Columns ``packet_sizes`` and ``inter_arrival_times`` are stringified
        Python lists.  ast.literal_eval is used to parse them; mean and std
        aggregates are derived using numpy.  ``byte_rate`` and ``packet_rate``
        are computed from ``bytes_in`` and ``duration_s`` (clipped to 0.001 s
        to prevent zero-division).

    CICIDS-style format (offline CSV training data)
        Pre-computed aggregate columns (Flow IAT Mean, Fwd Packet Length Mean,
        Flow Bytes/s, etc.) are already present; no list parsing needed.

    In both cases the function:
      1. Drops all identifier, label, and raw-array columns.
      2. Keeps only numeric dtypes.
      3. Replaces +/-inf with NaN, then fills NaN with the column median.

    Parameters
    ----------
    df : pd.DataFrame

    Returns
    -------
    pd.DataFrame  — numeric feature matrix, same row order as input.
    """
    df = df.copy()

    # -- Map FlowObject format to CICIDS format if live ingestion ----------------
    if "duration_s" in df.columns:
        df["Flow Duration"] = df["duration_s"] * 1e6
    if "total_packets" in df.columns:
        df["Total Fwd Packet"] = df["total_packets"]
    if "bytes_in" in df.columns:
        df["Total Length of Fwd Packet"] = df["bytes_in"]

    # -- Parse list columns if present (FlowObject format) -------------------
    if "packet_sizes" in df.columns:
        parsed_sizes = df["packet_sizes"].apply(
            lambda v: ast.literal_eval(v) if isinstance(v, str) else (v if isinstance(v, list) else [])
        )
        df["Fwd Packet Length Mean"] = parsed_sizes.apply(lambda lst: float(np.mean(lst)) if lst else 0.0)
        df["Fwd Packet Length Std"] = parsed_sizes.apply(lambda lst: float(np.std(lst)) if lst else 0.0)
        df["Fwd Packet Length Max"] = parsed_sizes.apply(lambda lst: float(np.max(lst)) if lst else 0.0)
        df["Fwd Packet Length Min"] = parsed_sizes.apply(lambda lst: float(np.min(lst)) if lst else 0.0)

    if "inter_arrival_times" in df.columns:
        parsed_iats = df["inter_arrival_times"].apply(
            lambda v: ast.literal_eval(v) if isinstance(v, str) else (v if isinstance(v, list) else [])
        )
        # Convert seconds to microseconds for CICIDS match
        df["Flow IAT Mean"] = parsed_iats.apply(lambda lst: float(np.mean(lst)) * 1e6 if lst else 0.0)
        df["Flow IAT Std"] = parsed_iats.apply(lambda lst: float(np.std(lst)) * 1e6 if lst else 0.0)
        df["Flow IAT Max"] = parsed_iats.apply(lambda lst: float(np.max(lst)) * 1e6 if lst else 0.0)
        df["Flow IAT Min"] = parsed_iats.apply(lambda lst: float(np.min(lst)) * 1e6 if lst else 0.0)

    # -- Rate features from FlowObject base columns (if present) -------------
    if {"bytes_in", "duration_s", "total_packets"}.issubset(df.columns):
        dur = df["duration_s"].clip(lower=0.001)
        df["Flow Bytes/s"]   = df["bytes_in"]     / dur
        df["Flow Packets/s"] = df["total_packets"] / dur
        
    # -- TCP Flags from FlowObject -------------------------------------------
    if "tcp_flags_seen" in df.columns:
        parsed_flags = df["tcp_flags_seen"].apply(
            lambda v: ast.literal_eval(v) if isinstance(v, str) else (v if isinstance(v, list) else [])
        )
        df["FIN Flag Count"] = parsed_flags.apply(lambda x: 1 if "F" in x else 0)
        df["SYN Flag Count"] = parsed_flags.apply(lambda x: 1 if "S" in x else 0)
        df["RST Flag Count"] = parsed_flags.apply(lambda x: 1 if "R" in x else 0)
        df["PSH Flag Count"] = parsed_flags.apply(lambda x: 1 if "P" in x else 0)
        df["ACK Flag Count"] = parsed_flags.apply(lambda x: 1 if "A" in x else 0)
        df["URG Flag Count"] = parsed_flags.apply(lambda x: 1 if "U" in x else 0)
        df["CWR Flag Count"] = parsed_flags.apply(lambda x: 1 if "C" in x else 0)
        df["ECE Flag Count"] = parsed_flags.apply(lambda x: 1 if "E" in x else 0)

    # -- Drop non-feature columns --------------------------------------------
    df = df.drop(columns=[c for c in _FLOW_DROP_COLS if c in df.columns], errors="ignore")

    # -- Numeric only --------------------------------------------------------
    df = df.select_dtypes(include=[np.number])

    # -- Sanitise ------------------------------------------------------------
    df = df.replace([np.inf, -np.inf], np.nan)
    df = df.fillna(df.median(numeric_only=True))
    df = df.fillna(0) # fallback if median is nan

    # -- Align columns to model's exact training signature -------------------
    col_path = MODELS_DIR / "flow_feature_columns.json"
    if col_path.exists():
        import json as _json
        train_cols = _json.loads(col_path.read_text(encoding="utf-8"))
        df = df.reindex(columns=train_cols, fill_value=0.0)

    return df


# ===========================================================================
# MODEL B — DNS lexical feature extraction
# ===========================================================================

def _char_entropy(series: pd.Series) -> pd.Series:
    """
    Shannon entropy (base-2) per domain string via scipy.stats.entropy.
    Operates on character frequency histograms — no custom implementation.
    """
    def _ent(domain: str) -> float:
        _, counts = np.unique(list(domain), return_counts=True)
        return float(scipy_entropy(counts, base=2))

    return series.apply(_ent)


def extract_dns_features(
    df: pd.DataFrame,
    vectorizer: CountVectorizer | None = None,
    fit: bool = False,
) -> tuple[pd.DataFrame, CountVectorizer]:
    """
    Return a numeric feature matrix from a DataFrame with a ``domain`` column.

    Feature groups
    --------------
    Scalar lexical (5 features)
        entropy           scipy.stats.entropy on character histogram
        length            total string length
        dot_count         number of '.' separators (subdomain depth proxy)
        digit_ratio       fraction of characters that are digits [0-1]
        unique_char_ratio lexical diversity: unique chars / total length [0-1]

    Character n-grams (50 features)
        sklearn CountVectorizer(analyzer='char', ngram_range=(2,3),
                                max_features=50) fitted on the domain column.

    Parameters
    ----------
    df          : DataFrame containing a ``domain`` column.
    vectorizer  : Pre-fitted CountVectorizer (pass for inference).
                  If None and fit=True, a new one is fitted and persisted.
    fit         : Fit a new vectorizer (training mode).

    Returns
    -------
    (feature_df, vectorizer)
    """
    domains: pd.Series = df["domain"].astype(str).str.lower().str.strip()

    # -- Scalar lexical features ---------------------------------------------
    feat = pd.DataFrame(
        {
            "entropy": _char_entropy(domains),
            "length":  domains.str.len(),
            "dot_count":         domains.str.count(r"\."),
            "digit_ratio":       domains.apply(
                lambda d: sum(c.isdigit() for c in d) / max(len(d), 1)
            ),
            "unique_char_ratio": domains.apply(
                lambda d: len(set(d)) / max(len(d), 1)
            ),
        },
        index=df.index,
    )

    # -- Character n-gram features (sklearn CountVectorizer) -----------------
    if fit:
        vectorizer = CountVectorizer(
            analyzer="char",
            ngram_range=(2, 3),
            max_features=50,
        )
        ngram_matrix = vectorizer.fit_transform(domains)
        MODELS_DIR.mkdir(parents=True, exist_ok=True)
        joblib.dump(vectorizer, MODELS_DIR / "dns_vectorizer.pkl")
        print(f"  [features] CountVectorizer saved -> {MODELS_DIR / 'dns_vectorizer.pkl'}")
    else:
        if vectorizer is None:
            vectorizer = joblib.load(MODELS_DIR / "dns_vectorizer.pkl")
        ngram_matrix = vectorizer.transform(domains)

    ngram_df = pd.DataFrame(
        ngram_matrix.toarray(),
        columns=vectorizer.get_feature_names_out(),
        index=feat.index,
    )

    return pd.concat([feat, ngram_df], axis=1), vectorizer
