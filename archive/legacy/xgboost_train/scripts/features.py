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
UNIVERSAL_FLOW_FEATURES: list[str] = [
    "Dst Port",
    "Flow Duration",
    "Total Fwd Packet",
    "Total Length of Fwd Packet",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Average Packet Size",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
]


def extract_flow_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Return a clean, fully-numeric feature matrix from a flow DataFrame.

    Extracts a robust universal feature set (20 informative metrics) that are
    meaningfully present in both live FlowObjects and offline CSVs:
      - Service port: Dst Port
      - Volume & duration: Flow Duration, Total Fwd Packet, Total Length of Fwd Packet
      - Packet size stats: Mean, Std, Max, Min, Average Packet Size
      - Rate features: Flow Bytes/s, Flow Packets/s
      - Inter-arrival times: Mean, Std, Max, Min (in microseconds)
      - TCP flags: FIN, SYN, RST, PSH, ACK counts

    Constant/dead features (Active/Idle windows, Bulk rates, ICMP codes, etc.)
    and ephemeral noise (Src Port) are excluded to prevent overfitting.
    """
    df = df.copy()

    # -- Map FlowObject format to standard features ----------------------------
    if "five_tuple" in df.columns:
        df["Dst Port"] = df["five_tuple"].apply(
            lambda t: float(t.get("dst_port", 0)) if isinstance(t, dict) else 0.0
        )
    elif "dst_port" in df.columns:
        df["Dst Port"] = df["dst_port"].astype(float)
    elif "Dst Port" not in df.columns:
        df["Dst Port"] = 0.0

    if "duration_s" in df.columns:
        df["Flow Duration"] = df["duration_s"].astype(float) * 1e6
    elif "Flow Duration" not in df.columns:
        df["Flow Duration"] = 0.0

    if "total_packets" in df.columns:
        df["Total Fwd Packet"] = df["total_packets"].astype(float)
    elif "Total Fwd Packet" not in df.columns:
        df["Total Fwd Packet"] = 1.0

    if "bytes_in" in df.columns:
        df["Total Length of Fwd Packet"] = df["bytes_in"].astype(float)
    elif "total_bytes" in df.columns:
        df["Total Length of Fwd Packet"] = df["total_bytes"].astype(float)
    elif "Total Length of Fwd Packet" not in df.columns:
        df["Total Length of Fwd Packet"] = 0.0

    # -- Parse packet sizes ----------------------------------------------------
    if "packet_sizes" in df.columns:
        parsed_sizes = df["packet_sizes"].apply(
            lambda v: ast.literal_eval(v) if isinstance(v, str) else (v if isinstance(v, list) else [])
        )
        df["Fwd Packet Length Mean"] = parsed_sizes.apply(lambda lst: float(np.mean(lst)) if lst else 0.0)
        df["Fwd Packet Length Std"]  = parsed_sizes.apply(lambda lst: float(np.std(lst)) if lst else 0.0)
        df["Fwd Packet Length Max"]  = parsed_sizes.apply(lambda lst: float(np.max(lst)) if lst else 0.0)
        df["Fwd Packet Length Min"]  = parsed_sizes.apply(lambda lst: float(np.min(lst)) if lst else 0.0)
        df["Average Packet Size"]    = df["Fwd Packet Length Mean"]
    else:
        for col in ["Fwd Packet Length Mean", "Fwd Packet Length Std", "Fwd Packet Length Max", "Fwd Packet Length Min"]:
            if col not in df.columns:
                df[col] = 0.0
        if "Average Packet Size" not in df.columns:
            df["Average Packet Size"] = df["Fwd Packet Length Mean"]

    # Fallback for Average Packet Size if 0 but total packets/bytes available
    zero_avg = (df["Average Packet Size"] == 0) & (df["Total Fwd Packet"] > 0) & (df["Total Length of Fwd Packet"] > 0)
    if zero_avg.any():
        df.loc[zero_avg, "Average Packet Size"] = (
            df.loc[zero_avg, "Total Length of Fwd Packet"] / df.loc[zero_avg, "Total Fwd Packet"].clip(lower=1.0)
        )

    # -- Parse inter-arrival times ---------------------------------------------
    if "inter_arrival_times" in df.columns:
        parsed_iats = df["inter_arrival_times"].apply(
            lambda v: ast.literal_eval(v) if isinstance(v, str) else (v if isinstance(v, list) else [])
        )
        df["Flow IAT Mean"] = parsed_iats.apply(lambda lst: float(np.mean(lst)) * 1e6 if lst else 0.0)
        df["Flow IAT Std"]  = parsed_iats.apply(lambda lst: float(np.std(lst)) * 1e6 if lst else 0.0)
        df["Flow IAT Max"]  = parsed_iats.apply(lambda lst: float(np.max(lst)) * 1e6 if lst else 0.0)
        df["Flow IAT Min"]  = parsed_iats.apply(lambda lst: float(np.min(lst)) * 1e6 if lst else 0.0)
    else:
        for col in ["Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min"]:
            if col not in df.columns:
                df[col] = 0.0

    # -- Rate features ---------------------------------------------------------
    if {"bytes_in", "duration_s", "total_packets"}.issubset(df.columns):
        dur = df["duration_s"].astype(float).clip(lower=1e-6)
        df["Flow Bytes/s"]   = df["bytes_in"].astype(float) / dur
        df["Flow Packets/s"] = df["total_packets"].astype(float) / dur
    else:
        if "Flow Bytes/s" not in df.columns:
            dur_s = (df["Flow Duration"] / 1e6).clip(lower=1e-6)
            df["Flow Bytes/s"] = df["Total Length of Fwd Packet"] / dur_s
        if "Flow Packets/s" not in df.columns:
            dur_s = (df["Flow Duration"] / 1e6).clip(lower=1e-6)
            df["Flow Packets/s"] = df["Total Fwd Packet"] / dur_s

    # -- TCP Flags -------------------------------------------------------------
    if "tcp_flags_seen" in df.columns:
        parsed_flags = df["tcp_flags_seen"].apply(
            lambda v: ast.literal_eval(v) if isinstance(v, str) else (v if isinstance(v, list) else [])
        )
        df["FIN Flag Count"] = parsed_flags.apply(lambda x: float(x.count("F") if isinstance(x, list) else (1 if "F" in str(x) else 0)))
        df["SYN Flag Count"] = parsed_flags.apply(lambda x: float(x.count("S") if isinstance(x, list) else (1 if "S" in str(x) else 0)))
        df["RST Flag Count"] = parsed_flags.apply(lambda x: float(x.count("R") if isinstance(x, list) else (1 if "R" in str(x) else 0)))
        df["PSH Flag Count"] = parsed_flags.apply(lambda x: float(x.count("P") if isinstance(x, list) else (1 if "P" in str(x) else 0)))
        df["ACK Flag Count"] = parsed_flags.apply(lambda x: float(x.count("A") if isinstance(x, list) else (1 if "A" in str(x) else 0)))
    else:
        for flag in ["FIN Flag Count", "SYN Flag Count", "RST Flag Count", "PSH Flag Count", "ACK Flag Count"]:
            if flag not in df.columns:
                df[flag] = 0.0

    # -- Select feature columns ------------------------------------------------
    col_path = MODELS_DIR / "flow_feature_columns.json"
    if col_path.exists():
        import json as _json
        try:
            train_cols = _json.loads(col_path.read_text(encoding="utf-8"))
        except Exception:
            train_cols = UNIVERSAL_FLOW_FEATURES
    else:
        train_cols = UNIVERSAL_FLOW_FEATURES

    out_df = df.reindex(columns=train_cols, fill_value=0.0)

    # -- Sanitise numeric values -----------------------------------------------
    out_df = out_df.apply(pd.to_numeric, errors="coerce")
    out_df = out_df.replace([np.inf, -np.inf], np.nan)
    out_df = out_df.fillna(0.0)

    return out_df


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
