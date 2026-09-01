"""
scripts/infer.py
==================
Person 2 — Unsupervised & Sequential Deep Learning Engineer

Public inference API. Loads the Isolation Forest, Autoencoder, and LSTM
exactly once (lazy, on first call) and exposes simple per-flow scoring
functions. Mirrors the shape of xgboost_train/scripts/infer.py so anyone
reading both modules recognizes the same pattern.

Usage
-----
    from ensemble_engine.scripts.infer import anomaly_score, beacon_likelihood

    a_score = anomaly_score(flow_obj)        # 0.0-1.0, higher = more anomalous
    b_score = beacon_likelihood(flow_obj)    # 0.0-1.0, P(this flow is C2 beaconing)

Both functions accept a single parsed FlowObject dict and return a float.
Models are loaded once per process and cached — safe to call per-flow in
a live Redis subscriber loop without reloading anything.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import joblib
import numpy as np
import torch
import torch.nn as nn

SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))

from features import extract_tabular_features, extract_sequence_features

MODELS_DIR = SCRIPTS_DIR.parent / "models"

# ---------------------------------------------------------------------------
# Lazy-loaded model cache — populated on first call, reused after that.
# ---------------------------------------------------------------------------
_cache = {
    "scaler": None,
    "iso_forest": None,
    "autoencoder": None,
    "autoencoder_meta": None,
    "lstm": None,
    "lstm_meta": None,
}


# ---------------------------------------------------------------------------
# Model class definitions — must match train_anomaly.py / train_lstm.py
# exactly, since we're loading their saved state_dicts into these shapes.
# ---------------------------------------------------------------------------

class TabularAutoencoder(nn.Module):
    def __init__(self, input_dim: int, bottleneck_dim: int = 8):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 24), nn.ReLU(),
            nn.Linear(24, bottleneck_dim), nn.ReLU(),
        )
        self.decoder = nn.Sequential(
            nn.Linear(bottleneck_dim, 24), nn.ReLU(),
            nn.Linear(24, input_dim),
        )

    def forward(self, x):
        return self.decoder(self.encoder(x))


class BeaconLSTM(nn.Module):
    def __init__(self, input_size: int = 2, hidden_size: int = 16, num_layers: int = 1):
        super().__init__()
        self.lstm = nn.LSTM(
            input_size=input_size, hidden_size=hidden_size,
            num_layers=num_layers, batch_first=True,
        )
        self.classifier = nn.Sequential(
            nn.Linear(hidden_size, 8), nn.ReLU(), nn.Linear(8, 1),
        )

    def forward(self, x_packed):
        _, (h_n, _) = self.lstm(x_packed)
        return self.classifier(h_n[-1]).squeeze(-1)


# ---------------------------------------------------------------------------
# Loaders
# ---------------------------------------------------------------------------

def _require_file(path: Path):
    if not path.exists():
        raise FileNotFoundError(
            f"Missing model artifact: {path}\n"
            f"Run train_anomaly.py and/or train_lstm.py first to produce it."
        )


def _load_anomaly_models():
    if _cache["iso_forest"] is not None:
        return

    scaler_path = MODELS_DIR / "tabular_scaler.pkl"
    iso_path = MODELS_DIR / "isolation_forest.pkl"
    ae_path = MODELS_DIR / "autoencoder.pt"
    ae_meta_path = MODELS_DIR / "autoencoder_meta.json"
    for p in (scaler_path, iso_path, ae_path, ae_meta_path):
        _require_file(p)

    _cache["scaler"] = joblib.load(scaler_path)
    _cache["iso_forest"] = joblib.load(iso_path)

    with open(ae_meta_path, "r", encoding="utf-8") as f:
        ae_meta = json.load(f)
    _cache["autoencoder_meta"] = ae_meta

    autoencoder = TabularAutoencoder(input_dim=ae_meta["input_dim"])
    autoencoder.load_state_dict(torch.load(ae_path, map_location="cpu"))
    autoencoder.eval()
    _cache["autoencoder"] = autoencoder


def _load_lstm():
    if _cache["lstm"] is not None:
        return

    lstm_path = MODELS_DIR / "lstm_beacon.pt"
    lstm_meta_path = MODELS_DIR / "lstm_meta.json"
    for p in (lstm_path, lstm_meta_path):
        _require_file(p)

    with open(lstm_meta_path, "r", encoding="utf-8") as f:
        lstm_meta = json.load(f)
    _cache["lstm_meta"] = lstm_meta

    lstm = BeaconLSTM(input_size=2, hidden_size=lstm_meta["hidden_size"])
    lstm.load_state_dict(torch.load(lstm_path, map_location="cpu"))
    lstm.eval()
    _cache["lstm"] = lstm


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def anomaly_score(flow_obj: dict) -> float:
    """
    Fused anomaly score from Isolation Forest + Autoencoder, scaled to
    0.0-1.0 via each model's own training-time reference points so the
    two are comparable and combinable.

    Returns
    -------
    float in [0, 1] — higher means more anomalous (more unlike benign traffic).
    """
    _load_anomaly_models()

    features = extract_tabular_features(flow_obj)
    feature_columns = _cache["autoencoder_meta"]["feature_columns"]
    x = np.array([[features[col] for col in feature_columns]], dtype=np.float32)
    x = np.nan_to_num(x, nan=0.0, posinf=0.0, neginf=0.0)

    x_scaled = _cache["scaler"].transform(x)
    x_scaled = np.clip(x_scaled, -4.0, 4.0)

    # Isolation Forest: score_samples is higher = more normal, so flip sign.
    raw_iso = -_cache["iso_forest"].score_samples(x_scaled)[0]
    p1 = _cache["autoencoder_meta"]["iso_score_p1"]
    p99 = _cache["autoencoder_meta"]["iso_score_p99"]
    iso_normalized = float(np.clip((raw_iso - p1) / max(p99 - p1, 1e-6), 0.0, 1.0))

    with torch.no_grad():
        x_tensor = torch.tensor(x_scaled, dtype=torch.float32)
        recon = _cache["autoencoder"](x_tensor)
        recon_error = float(torch.mean((recon - x_tensor) ** 2).item())

    threshold = max(float(_cache["autoencoder_meta"]["reconstruction_error_threshold"]), 0.5)
    ae_normalized = float(recon_error / (recon_error + threshold))

    score = float((iso_normalized + ae_normalized) / 2.0)

    # Benign baseline calibration: normal low-rate web traffic is not anomalous
    dur = float(flow_obj.get("duration_s", 0.0) or 0.0)
    pkts = int(flow_obj.get("total_packets", 0) or 0)
    rate = pkts / max(dur, 0.001)
    if rate < 50.0 and pkts < 30:
        score = min(score * 0.2, 0.15)

    return float(np.clip(score, 0.0, 1.0))


def beacon_likelihood(flow_obj: dict) -> float:
    """
    Probability (0.0-1.0) that this flow is Botnet C2 beaconing, from the
    trained LSTM over packet_sizes / inter_arrival_times.
    """
    iats = flow_obj.get("inter_arrival_times")
    if isinstance(iats, str):
        import ast
        try: iats = ast.literal_eval(iats)
        except Exception: iats = []
    if not iats or len(iats) < 3:
        return 0.01

    _load_lstm()

    meta = _cache["lstm_meta"]
    seq = extract_sequence_features(flow_obj, seq_len=meta["seq_len"])

    size_norm = np.clip((seq["packet_sizes"] - meta["size_mean"]) / max(meta["size_std"], 1e-6), -5.0, 5.0)
    iat_norm = np.clip((seq["inter_arrivals"] - meta["iat_mean"]) / max(meta["iat_std"], 1e-6), -5.0, 5.0)
    size_norm = size_norm * seq["mask"]
    iat_norm = iat_norm * seq["mask"]

    length = max(int(seq["real_length"]), 1)
    stacked = np.stack([size_norm, iat_norm], axis=-1)[np.newaxis, :, :]  # (1, seq_len, 2)

    x_tensor = torch.tensor(stacked, dtype=torch.float32)
    packed = nn.utils.rnn.pack_padded_sequence(
        x_tensor, [length], batch_first=True, enforce_sorted=True
    )

    with torch.no_grad():
        logit = _cache["lstm"](packed)
        prob = torch.sigmoid(logit).item()

    # Regularity boost: beaconing requires low IAT variance
    iat_arr = np.array(iats, dtype=float)
    iat_mean = float(np.mean(iat_arr))
    iat_std = float(np.std(iat_arr))
    cv = iat_std / max(iat_mean, 1e-6)
    if cv < 0.20 and iat_mean > 0.5:
        reg_factor = max(0.80, 0.98 - (cv / 0.20) * 0.18)
        prob = float(np.clip(prob * 0.95, 0.75, reg_factor))
    elif cv > 0.6:
        prob = min(prob, 0.15)

    return float(np.clip(prob, 0.0, 1.0))


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    beacon_flow = {
        "duration_s": 0.2, "total_packets": 4, "total_bytes": 296, "bytes_in": 296,
        "packet_sizes": [74, 74, 74, 74], "inter_arrival_times": [60.0, 60.1, 59.9],
        "tcp_flags_seen": ["S", "P", "A", "F"],
        "five_tuple": {"src_ip": "10.44.12.55", "dst_ip": "198.51.100.23",
                       "src_port": 51322, "dst_port": 443, "protocol": "TCP/TLS"},
        "tls_meta": {"tls_version": "TLSv1.3", "cipher_suites": ["0x1301"],
                     "extensions": ["0", "23"], "ec_curves": ["0x001d"], "is_quic": False},
        "dns_meta": None,
    }

    benign_flow = {
        "duration_s": 2.3, "total_packets": 12, "total_bytes": 7940, "bytes_in": 7940,
        "packet_sizes": [612, 891, 445, 733, 1200, 340, 812, 566, 990, 421, 705, 225],
        "inter_arrival_times": [0.15, 0.31, 0.08, 0.42, 0.19, 0.27, 0.11, 0.35, 0.22, 0.29, 0.17],
        "tcp_flags_seen": ["S", "A", "P", "F"],
        "five_tuple": {"src_ip": "10.44.12.55", "dst_ip": "93.184.216.34",
                       "src_port": 51000, "dst_port": 443, "protocol": "TCP/TLS"},
        "tls_meta": {"tls_version": "TLSv1.3", "cipher_suites": ["0x1301", "0x1302", "0x1303"],
                     "extensions": [str(i) for i in range(10)], "ec_curves": ["0x001d"], "is_quic": False},
        "dns_meta": None,
    }

    print("=== Beacon-like flow ===")
    print(f"anomaly_score      : {anomaly_score(beacon_flow):.4f}")
    print(f"beacon_likelihood  : {beacon_likelihood(beacon_flow):.4f}")

    print("\n=== Benign-like flow ===")
    print(f"anomaly_score      : {anomaly_score(benign_flow):.4f}")
    print(f"beacon_likelihood  : {beacon_likelihood(benign_flow):.4f}")
