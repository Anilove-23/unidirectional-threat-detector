"""
scripts/features.py
===================
Person 2 — Unsupervised & Sequential Deep Learning Engineer
Feature extraction shared by the Isolation Forest, Autoencoder, and LSTM.

Designed to be imported by:
  • train_anomaly.py   (offline Isolation Forest / Autoencoder training)
  • train_lstm.py       (offline LSTM training)
  • infer.py            (live stream inference)
  • ensemble.py         (reads tls_meta / evidence fields for the alert)

This module produces TWO independent feature views from the same FlowObject:

  1. TABULAR features  -> extract_tabular_features()
     Fixed-length numeric vector per flow. Feeds Isolation Forest / Autoencoder.

  2. SEQUENCE features -> extract_sequence_features()
     Padded (packet_sizes, inter_arrival_times) pair per flow. Feeds the LSTM.

IMPORTANT — read before using
------------------------------
FlowObject.bytes_out_proxy is ALWAYS 0 under the data-diode constraint
(outbound traffic is not observable). Per FLOW_OBJECT_SCHEMA.md, do NOT use
it to compute an asymmetric byte ratio. This module instead derives a proxy
signal from bytes_in relative to duration_s / packet count, as instructed.

OUT OF SCOPE — DO NOT ADD:
  • Anything from xgboost_train (that's Person 1's CICIDS-aggregate feature set)
  • Ensemble fusion logic (lives in ensemble.py)
"""

from __future__ import annotations

import numpy as np
import pandas as pd

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Must match ingestion's 50-sample cap (see FLOW_OBJECT_SCHEMA.md)
SEQUENCE_LENGTH = 50

# Order of tabular feature columns. Fixed order matters — the trained
# Isolation Forest / Autoencoder expect columns in exactly this order.
TABULAR_FEATURE_COLUMNS = [
    "duration_s",
    "total_packets",
    "total_bytes",
    "bytes_in",
    "packet_rate",
    "byte_rate",
    "bytes_in_per_packet",       # proxy for asymmetric byte ratio (see module docstring)
    "packet_size_mean",
    "packet_size_std",
    "packet_size_min",
    "packet_size_max",
    "iat_mean",
    "iat_std",
    "iat_min",
    "iat_max",
    "iat_coefficient_of_variation",  # low CV + tight iat_mean -> beaconing regularity signal
    "flag_syn", "flag_ack", "flag_fin", "flag_psh", "flag_rst", "flag_urg",
    "is_tcp", "is_tcp_tls", "is_udp", "is_udp_quic", "is_icmp",
    "dst_port_is_well_known",
    "has_tls",
    "has_dns",
    "tls_cipher_suite_count",
    "tls_extension_count",
    "tls_ec_curve_count",
    "tls_is_quic",
    "tls_is_tls13",
    "dns_query_length",
    "dns_query_entropy",
]


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def _safe_list(value) -> list:
    """FlowObject list fields are already Python lists when read from Redis
    JSON (json.loads), but be defensive in case a caller passes a CSV row
    where the list got stringified."""
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        import ast
        try:
            parsed = ast.literal_eval(value)
            return parsed if isinstance(parsed, list) else []
        except (ValueError, SyntaxError):
            return []
    return []


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    _, counts = np.unique(list(s), return_counts=True)
    probs = counts / counts.sum()
    return float(-np.sum(probs * np.log2(probs)))


# ---------------------------------------------------------------------------
# 1. TABULAR features — Isolation Forest / Autoencoder
# ---------------------------------------------------------------------------

def extract_tabular_features(flow_obj: dict) -> dict:
    """
    Build a fixed-length numeric feature dict from a single FlowObject.

    Parameters
    ----------
    flow_obj : dict — a parsed FlowObject (see FLOW_OBJECT_SCHEMA.md)

    Returns
    -------
    dict — keys match TABULAR_FEATURE_COLUMNS exactly, values are floats.
    """
    duration_s = float(flow_obj.get("duration_s", 0.0)) or 0.0
    total_packets = float(flow_obj.get("total_packets", 0))
    total_bytes = float(flow_obj.get("total_bytes", 0))
    bytes_in = float(flow_obj.get("bytes_in", 0))

    safe_duration = max(duration_s, 0.001)  # avoid div-by-zero, mirrors Person 1's convention
    packet_rate = total_packets / safe_duration
    byte_rate = bytes_in / safe_duration
    bytes_in_per_packet = bytes_in / max(total_packets, 1.0)

    packet_sizes = _safe_list(flow_obj.get("packet_sizes"))
    iats = _safe_list(flow_obj.get("inter_arrival_times"))

    packet_size_mean = float(np.mean(packet_sizes)) if packet_sizes else 0.0
    packet_size_std = float(np.std(packet_sizes)) if packet_sizes else 0.0
    packet_size_min = float(np.min(packet_sizes)) if packet_sizes else 0.0
    packet_size_max = float(np.max(packet_sizes)) if packet_sizes else 0.0

    iat_mean = float(np.mean(iats)) if iats else 0.0
    iat_std = float(np.std(iats)) if iats else 0.0
    iat_min = float(np.min(iats)) if iats else 0.0
    iat_max = float(np.max(iats)) if iats else 0.0
    # Coefficient of variation: std/mean. Low value = tightly regular timing,
    # the single strongest tabular signal for beaconing (see NTRO spec 5.2).
    iat_cv = (iat_std / iat_mean) if iat_mean > 0 else 0.0

    flags = _safe_list(flow_obj.get("tcp_flags_seen"))
    flag_syn = 1.0 if "S" in flags else 0.0
    flag_ack = 1.0 if "A" in flags else 0.0
    flag_fin = 1.0 if "F" in flags else 0.0
    flag_psh = 1.0 if "P" in flags else 0.0
    flag_rst = 1.0 if "R" in flags else 0.0
    flag_urg = 1.0 if "U" in flags else 0.0

    protocol = (flow_obj.get("five_tuple") or {}).get("protocol", "")
    is_tcp = 1.0 if protocol == "TCP" else 0.0
    is_tcp_tls = 1.0 if protocol == "TCP/TLS" else 0.0
    is_udp = 1.0 if protocol == "UDP" else 0.0
    is_udp_quic = 1.0 if protocol == "UDP/QUIC" else 0.0
    is_icmp = 1.0 if protocol == "ICMP" else 0.0

    dst_port = (flow_obj.get("five_tuple") or {}).get("dst_port", 0) or 0
    dst_port_is_well_known = 1.0 if 0 < dst_port < 1024 else 0.0

    tls_meta = flow_obj.get("tls_meta") or {}
    has_tls = 1.0 if flow_obj.get("tls_meta") is not None else 0.0
    tls_cipher_suite_count = float(len(tls_meta.get("cipher_suites") or []))
    tls_extension_count = float(len(tls_meta.get("extensions") or []))
    tls_ec_curve_count = float(len(tls_meta.get("ec_curves") or []))
    tls_is_quic = 1.0 if tls_meta.get("is_quic") else 0.0
    tls_is_tls13 = 1.0 if tls_meta.get("tls_version") == "TLSv1.3" else 0.0

    dns_meta = flow_obj.get("dns_meta") or {}
    has_dns = 1.0 if flow_obj.get("dns_meta") is not None else 0.0
    dns_query_length = float(dns_meta.get("query_length") or 0)
    dns_query_entropy = _shannon_entropy(dns_meta.get("query_name") or "")

    features = {
        "duration_s": duration_s,
        "total_packets": total_packets,
        "total_bytes": total_bytes,
        "bytes_in": bytes_in,
        "packet_rate": packet_rate,
        "byte_rate": byte_rate,
        "bytes_in_per_packet": bytes_in_per_packet,
        "packet_size_mean": packet_size_mean,
        "packet_size_std": packet_size_std,
        "packet_size_min": packet_size_min,
        "packet_size_max": packet_size_max,
        "iat_mean": iat_mean,
        "iat_std": iat_std,
        "iat_min": iat_min,
        "iat_max": iat_max,
        "iat_coefficient_of_variation": iat_cv,
        "flag_syn": flag_syn,
        "flag_ack": flag_ack,
        "flag_fin": flag_fin,
        "flag_psh": flag_psh,
        "flag_rst": flag_rst,
        "flag_urg": flag_urg,
        "is_tcp": is_tcp,
        "is_tcp_tls": is_tcp_tls,
        "is_udp": is_udp,
        "is_udp_quic": is_udp_quic,
        "is_icmp": is_icmp,
        "dst_port_is_well_known": dst_port_is_well_known,
        "has_tls": has_tls,
        "has_dns": has_dns,
        "tls_cipher_suite_count": tls_cipher_suite_count,
        "tls_extension_count": tls_extension_count,
        "tls_ec_curve_count": tls_ec_curve_count,
        "tls_is_quic": tls_is_quic,
        "tls_is_tls13": tls_is_tls13,
        "dns_query_length": dns_query_length,
        "dns_query_entropy": dns_query_entropy,
    }
    return features


def extract_tabular_features_batch(flow_objs: list[dict]) -> pd.DataFrame:
    """
    Batch version for training. Returns a DataFrame with columns in the
    exact order of TABULAR_FEATURE_COLUMNS (safe to feed straight into
    IsolationForest.fit() / autoencoder training after scaling).
    """
    rows = [extract_tabular_features(f) for f in flow_objs]
    df = pd.DataFrame(rows)
    df = df.reindex(columns=TABULAR_FEATURE_COLUMNS, fill_value=0.0)
    df = df.replace([np.inf, -np.inf], np.nan).fillna(0.0)
    return df


# ---------------------------------------------------------------------------
# 2. SEQUENCE features — LSTM (C2 beaconing)
# ---------------------------------------------------------------------------

def extract_sequence_features(flow_obj: dict, seq_len: int = SEQUENCE_LENGTH) -> dict:
    """
    Build padded (packet_sizes, inter_arrival_times) sequences for the LSTM.

    Sequences are truncated or zero-padded to a fixed length so they can be
    batched into a single tensor. A boolean mask marks real vs. padded
    positions, since the LSTM should not be misled by trailing zeros.

    Parameters
    ----------
    flow_obj : dict — a parsed FlowObject
    seq_len  : int  — fixed sequence length (default matches ingestion's cap)

    Returns
    -------
    dict with keys:
        packet_sizes   : np.ndarray, shape (seq_len,), float32
        inter_arrivals : np.ndarray, shape (seq_len,), float32
        mask           : np.ndarray, shape (seq_len,), float32 (1.0 = real, 0.0 = padding)
        real_length    : int — number of real (non-padded) samples
    """
    packet_sizes = _safe_list(flow_obj.get("packet_sizes"))
    iats = _safe_list(flow_obj.get("inter_arrival_times"))

    # inter_arrival_times has one fewer entry than packet_sizes (gaps between
    # packets, not per-packet), so pad it to the same length with a leading 0
    # to keep both sequences index-aligned for the LSTM.
    if len(iats) < len(packet_sizes):
        iats = [0.0] + iats

    real_length = min(len(packet_sizes), seq_len)

    padded_sizes = np.zeros(seq_len, dtype=np.float32)
    padded_iats = np.zeros(seq_len, dtype=np.float32)
    mask = np.zeros(seq_len, dtype=np.float32)

    truncated_sizes = packet_sizes[:seq_len]
    truncated_iats = iats[:seq_len]

    padded_sizes[: len(truncated_sizes)] = truncated_sizes
    padded_iats[: len(truncated_iats)] = truncated_iats
    mask[:real_length] = 1.0

    return {
        "packet_sizes": padded_sizes,
        "inter_arrivals": padded_iats,
        "mask": mask,
        "real_length": real_length,
    }


def extract_sequence_features_batch(
    flow_objs: list[dict], seq_len: int = SEQUENCE_LENGTH
) -> dict:
    """
    Batch version for training. Returns stacked arrays ready for
    torch.from_numpy():
        packet_sizes   : np.ndarray, shape (N, seq_len)
        inter_arrivals : np.ndarray, shape (N, seq_len)
        mask           : np.ndarray, shape (N, seq_len)
    """
    per_flow = [extract_sequence_features(f, seq_len) for f in flow_objs]
    return {
        "packet_sizes": np.stack([f["packet_sizes"] for f in per_flow]),
        "inter_arrivals": np.stack([f["inter_arrivals"] for f in per_flow]),
        "mask": np.stack([f["mask"] for f in per_flow]),
    }


# ---------------------------------------------------------------------------
# Smoke test — run directly to sanity-check against the spec's example flows
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import json

    c2_beacon_flow = {
        "schema_version": "1.0.0",
        "flow_id": "9c1f2a3e-77b4-4e2d-9c6a-1d3f8b0a55e2",
        "first_seen": "2026-08-28T06:42:11.000Z",
        "last_seen": "2026-08-28T06:42:11.200Z",
        "five_tuple": {
            "src_ip": "10.44.12.55", "dst_ip": "198.51.100.23",
            "src_port": 51322, "dst_port": 443, "protocol": "TCP/TLS",
        },
        "duration_s": 0.2,
        "total_packets": 4,
        "total_bytes": 296,
        "packet_sizes": [74, 74, 74, 74],
        "inter_arrival_times": [0.0, 0.05, 0.05],
        "tcp_flags_seen": ["S", "P", "A", "F"],
        "bytes_in": 296,
        "bytes_out_proxy": 0,
        "tls_meta": {
            "tls_version": "TLSv1.3",
            "cipher_suites": ["0x1301", "0x1302", "0x1303"],
            "extensions": ["0", "23", "65281", "10", "11", "35", "16", "5", "13", "18"],
            "ec_curves": ["0x001d", "0x0017"],
            "ja3_raw_string": "771,4866-4867-4865,...",
            "ja3_fingerprint": "6734f37431670b3ab4292b8f60f29984",
            "ja4_fingerprint": None,
            "record_length": 512,
            "is_quic": False,
        },
        "dns_meta": None,
        "zeek_conn_state": "SF",
        "zeek_uid": "CmFRHF1NjoUI",
        "sensor_id": "diode-sensor-01",
        "capture_interface": "eth1",
        "pipeline_version": "1.0.0",
    }

    dns_tunnel_flow = {
        "duration_s": 0.05, "total_packets": 1, "total_bytes": 120, "bytes_in": 120,
        "packet_sizes": [120], "inter_arrival_times": [], "tcp_flags_seen": [],
        "five_tuple": {"src_ip": "10.44.12.55", "dst_ip": "8.8.8.8",
                       "src_port": 54321, "dst_port": 53, "protocol": "UDP"},
        "tls_meta": None,
        "dns_meta": {"query_name": "a2VsZ2VpZmVuLmNvbQ.4921.tunnel.c2.example.com",
                     "query_type": "TXT", "query_length": 47,
                     "answer_count": 0, "answer_ips": None},
    }

    print("=== Tabular features: C2 beacon flow ===")
    print(json.dumps(extract_tabular_features(c2_beacon_flow), indent=2))

    print("\n=== Tabular features: DNS tunnel flow ===")
    print(json.dumps(extract_tabular_features(dns_tunnel_flow), indent=2))

    print("\n=== Sequence features: C2 beacon flow ===")
    seq = extract_sequence_features(c2_beacon_flow, seq_len=10)
    print("packet_sizes  :", seq["packet_sizes"])
    print("inter_arrivals:", seq["inter_arrivals"])
    print("mask          :", seq["mask"])
    print("real_length   :", seq["real_length"])

    print("\n=== Batch tabular (both flows) ===")
    batch_df = extract_tabular_features_batch([c2_beacon_flow, dns_tunnel_flow])
    print(batch_df.to_string())
