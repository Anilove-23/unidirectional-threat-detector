"""
scripts/train_anomaly.py
==========================
Person 2 — Unsupervised & Sequential Deep Learning Engineer

Trains the Isolation Forest and Autoencoder anomaly detectors on BENIGN
flows only. This is standard practice for anomaly detection: both models
learn what "normal" looks like, so anything that deviates -- including
zero-day threat types neither model has ever seen -- scores as anomalous
at inference time. This is exactly the spec's requirement (Section 4.3):
catch "statistically anomalous flows that don't match any known-attack
signature."

Input
-----
A JSONL file where each line is a FlowObject with an added
"collected_label" field (produced by collect_dataset.py). Only rows where
collected_label == --benign-label are used for training. If other labeled
attack rows are present in the same file, they're used purely for
EVALUATION at the end (to sanity-check that attack flows score higher
than benign ones) -- they never enter training.

Usage
-----
    python ensemble_engine/scripts/train_anomaly.py \\
        --data ensemble_engine/data/raw_flows.jsonl \\
        --benign-label BENIGN

Outputs (saved to ensemble_engine/models/)
-------------------------------------------
    tabular_scaler.pkl        StandardScaler fit on benign features
    isolation_forest.pkl      Trained sklearn IsolationForest
    autoencoder.pt            Trained PyTorch autoencoder state_dict
    autoencoder_meta.json     Input dim + reconstruction-error threshold
                              (95th percentile of benign training error)
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import joblib
import numpy as np
import torch
import torch.nn as nn
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))

from features import TABULAR_FEATURE_COLUMNS, extract_tabular_features_batch

MODELS_DIR = SCRIPTS_DIR.parent / "models"


# ---------------------------------------------------------------------------
# Autoencoder — small feed-forward net, matches the tabular feature width
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


def load_jsonl(path: Path) -> list[dict]:
    rows = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def train_autoencoder(X_train: np.ndarray, epochs: int = 50, lr: float = 1e-3) -> tuple[TabularAutoencoder, float]:
    input_dim = X_train.shape[1]
    model = TabularAutoencoder(input_dim)
    optimizer = torch.optim.Adam(model.parameters(), lr=lr)
    loss_fn = nn.MSELoss()

    X_tensor = torch.tensor(X_train, dtype=torch.float32)

    model.train()
    for epoch in range(epochs):
        optimizer.zero_grad()
        reconstructed = model(X_tensor)
        loss = loss_fn(reconstructed, X_tensor)
        loss.backward()
        optimizer.step()
        if (epoch + 1) % 10 == 0 or epoch == 0:
            print(f"  [autoencoder] epoch {epoch + 1}/{epochs}  loss={loss.item():.6f}")

    # Reconstruction error per training sample -> threshold at 95th percentile.
    # Anything above this at inference time is flagged anomalous.
    model.eval()
    with torch.no_grad():
        reconstructed = model(X_tensor)
        per_sample_error = torch.mean((reconstructed - X_tensor) ** 2, dim=1).numpy()
    threshold = float(np.percentile(per_sample_error, 95))

    return model, threshold


def main():
    parser = argparse.ArgumentParser(description="Train Isolation Forest + Autoencoder on benign flows")
    parser.add_argument("--data", default=str(Path(__file__).resolve().parent.parent / "data" / "raw_flows.jsonl"))
    parser.add_argument("--benign-label", default="BENIGN")
    parser.add_argument("--epochs", type=int, default=50)
    parser.add_argument("--contamination", type=float, default=0.05,
                         help="IsolationForest expected outlier fraction in training data")
    args = parser.parse_args()

    data_path = Path(args.data)
    if not data_path.exists():
        print(f"[-] Data file not found: {data_path}")
        print("    Run collect_dataset.py first to build a labeled dataset.")
        sys.exit(1)

    print(f"[+] Loading {data_path}...")
    all_rows = load_jsonl(data_path)
    print(f"[+] Loaded {len(all_rows)} total flows")

    benign_rows = [r for r in all_rows if r.get("collected_label") == args.benign_label]
    other_rows = [r for r in all_rows if r.get("collected_label") != args.benign_label]
    print(f"[+] {len(benign_rows)} benign flows for training, {len(other_rows)} other flows held out for evaluation")

    if len(benign_rows) < 20:
        print(f"[-] Only {len(benign_rows)} benign flows found — need at least 20 to train meaningfully.")
        print(f"    Run: python ensemble_engine/scripts/collect_dataset.py --label {args.benign_label}")
        print(f"    alongside: python ingestion/dataset/generators/benign_gen.py --target 127.0.0.1")
        sys.exit(1)

    # -- Feature extraction + scaling --------------------------------------
    print("[+] Extracting tabular features...")
    benign_df = extract_tabular_features_batch(benign_rows)

    scaler = StandardScaler()
    X_benign_scaled = scaler.fit_transform(benign_df.values)

    # -- Isolation Forest ----------------------------------------------------
    print("[+] Training Isolation Forest...")
    iso_forest = IsolationForest(
        n_estimators=200,
        contamination=args.contamination,
        random_state=42,
    )
    iso_forest.fit(X_benign_scaled)

    # Calibration: capture where benign traffic actually falls on the raw
    # score_samples scale, since that range varies by dataset and can't be
    # assumed as a fixed constant (e.g. [-0.5, 0.5]) at inference time.
    raw_iso_benign = -iso_forest.score_samples(X_benign_scaled)
    iso_score_p1 = float(np.percentile(raw_iso_benign, 1))
    iso_score_p99 = float(np.percentile(raw_iso_benign, 99))

    # -- Autoencoder -----------------------------------------------------
    print("[+] Training Autoencoder...")
    autoencoder, ae_threshold = train_autoencoder(X_benign_scaled, epochs=args.epochs)

    # -- Save artifacts ----------------------------------------------------
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(scaler, MODELS_DIR / "tabular_scaler.pkl")
    joblib.dump(iso_forest, MODELS_DIR / "isolation_forest.pkl")
    torch.save(autoencoder.state_dict(), MODELS_DIR / "autoencoder.pt")
    with open(MODELS_DIR / "autoencoder_meta.json", "w", encoding="utf-8") as f:
        json.dump({
            "input_dim": len(TABULAR_FEATURE_COLUMNS),
            "reconstruction_error_threshold": ae_threshold,
            "feature_columns": TABULAR_FEATURE_COLUMNS,
            "iso_score_p1": iso_score_p1,
            "iso_score_p99": iso_score_p99,
        }, f, indent=2)

    print(f"\n[+] Saved artifacts to {MODELS_DIR}/:")
    print("    tabular_scaler.pkl, isolation_forest.pkl, autoencoder.pt, autoencoder_meta.json")

    # -- Evaluation: do held-out attack flows score higher? ------------------
    if other_rows:
        print("\n[+] Evaluation — mean anomaly scores by label (higher = more anomalous):")
        print(f"    {'label':<24}{'iso_forest_score':<20}{'ae_recon_error':<20}{'n':<5}")

        by_label: dict[str, list[dict]] = {}
        for r in benign_rows + other_rows:
            by_label.setdefault(r.get("collected_label", "UNKNOWN"), []).append(r)

        for label, rows in by_label.items():
            df = extract_tabular_features_batch(rows)
            X_scaled = scaler.transform(df.values)

            # IsolationForest: score_samples is higher = more normal, so flip sign
            iso_scores = -iso_forest.score_samples(X_scaled)

            with torch.no_grad():
                X_tensor = torch.tensor(X_scaled, dtype=torch.float32)
                recon = autoencoder(X_tensor)
                ae_errors = torch.mean((recon - X_tensor) ** 2, dim=1).numpy()

            print(f"    {label:<24}{np.mean(iso_scores):<20.4f}{np.mean(ae_errors):<20.6f}{len(rows):<5}")

        print(f"\n    (Autoencoder anomaly threshold from training: {ae_threshold:.6f})")
        print("    Attack labels should show clearly higher iso_forest_score and ae_recon_error")
        print("    than BENIGN. If they don't, the benign training set may be too small/uniform.")


if __name__ == "__main__":
    main()
