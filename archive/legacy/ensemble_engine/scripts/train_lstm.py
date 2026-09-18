"""
scripts/train_lstm.py
=======================
Person 2 — Unsupervised & Sequential Deep Learning Engineer

Trains a PyTorch LSTM to detect low-and-slow Botnet C2 beaconing from
per-flow packet_sizes / inter_arrival_times sequences (see
features.extract_sequence_features). Binary classifier: beacon vs. benign.

Why sequences and not tabular stats: a single beacon connection often
looks unremarkable on its own (a handful of small packets), but the
REGULARITY across the sequence (near-identical inter-arrival gaps) is the
tell. That temporal pattern is exactly what an LSTM is suited to learn,
and exactly what the tabular Isolation Forest/Autoencoder can only see a
blurry proxy of (iat_coefficient_of_variation).

Handles class imbalance (beacon flows are naturally rarer than benign)
via pos_weight in BCEWithLogitsLoss rather than discarding benign data.

Usage
-----
    python ensemble_engine/scripts/train_lstm.py \\
        --data ensemble_engine/data/raw_flows.jsonl \\
        --beacon-label BOTNET_C2_BEACONING --benign-label BENIGN

Outputs (saved to ensemble_engine/models/)
-------------------------------------------
    lstm_beacon.pt        Trained PyTorch LSTM state_dict
    lstm_meta.json        Normalization stats + seq_len + architecture dims
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn
from sklearn.model_selection import train_test_split

SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))

from features import SEQUENCE_LENGTH, extract_sequence_features_batch

MODELS_DIR = SCRIPTS_DIR.parent / "models"


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------

class BeaconLSTM(nn.Module):
    """
    Input per flow: 2 channels per timestep (normalized packet_size,
    normalized inter_arrival_time), fed as a packed sequence so padding
    doesn't influence the learned representation.
    """

    def __init__(self, input_size: int = 2, hidden_size: int = 16, num_layers: int = 1):
        super().__init__()
        self.lstm = nn.LSTM(
            input_size=input_size,
            hidden_size=hidden_size,
            num_layers=num_layers,
            batch_first=True,
        )
        self.classifier = nn.Sequential(
            nn.Linear(hidden_size, 8),
            nn.ReLU(),
            nn.Linear(8, 1),  # raw logit; BCEWithLogitsLoss applies sigmoid internally
        )

    def forward(self, x_packed):
        _, (h_n, _) = self.lstm(x_packed)
        last_hidden = h_n[-1]  # (batch, hidden_size) — final layer's hidden state
        return self.classifier(last_hidden).squeeze(-1)  # (batch,) raw logits


def load_jsonl(path: Path) -> list[dict]:
    rows = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def build_dataset(flow_objs: list[dict], seq_len: int):
    """Returns (packet_sizes, inter_arrivals, mask, lengths) as numpy arrays."""
    batch = extract_sequence_features_batch(flow_objs, seq_len=seq_len)
    lengths = batch["mask"].sum(axis=1).astype(np.int64)
    lengths = np.clip(lengths, 1, seq_len)  # pack_padded_sequence needs length >= 1
    return batch["packet_sizes"], batch["inter_arrivals"], batch["mask"], lengths


def normalize(sizes: np.ndarray, iats: np.ndarray, size_stats, iat_stats):
    size_mean, size_std = size_stats
    iat_mean, iat_std = iat_stats
    norm_sizes = (sizes - size_mean) / max(size_std, 1e-6)
    norm_iats = (iats - iat_mean) / max(iat_std, 1e-6)
    return norm_sizes, norm_iats


def make_packed_input(sizes: np.ndarray, iats: np.ndarray, lengths: np.ndarray):
    """Stack the two channels and pack for the LSTM, sorted by length desc
    (required by pack_padded_sequence with enforce_sorted=True, the fastest path)."""
    stacked = np.stack([sizes, iats], axis=-1)  # (N, seq_len, 2)
    order = np.argsort(-lengths)
    stacked_sorted = stacked[order]
    lengths_sorted = lengths[order]

    x_tensor = torch.tensor(stacked_sorted, dtype=torch.float32)
    packed = nn.utils.rnn.pack_padded_sequence(
        x_tensor, lengths_sorted, batch_first=True, enforce_sorted=True
    )
    return packed, order  # order lets caller map predictions back to original rows


def main():
    parser = argparse.ArgumentParser(description="Train LSTM for C2 beacon detection")
    parser.add_argument("--data", default=str(Path(__file__).resolve().parent.parent / "data" / "raw_flows.jsonl"))
    parser.add_argument("--beacon-label", default="BOTNET_C2_BEACONING")
    parser.add_argument("--benign-label", default="BENIGN")
    parser.add_argument("--epochs", type=int, default=500,
                         help="Max epochs — early stopping on validation F1 usually stops sooner")
    parser.add_argument("--patience", type=int, default=60,
                         help="Stop if validation F1 doesn't improve for this many epochs")
    parser.add_argument("--warmup-epochs", type=int, default=40,
                         help="Epochs before early stopping is allowed to trigger, "
                              "giving the model room to escape an initial degenerate state")
    parser.add_argument("--lr", type=float, default=0.01)
    parser.add_argument("--weight-decay", type=float, default=1e-4)
    parser.add_argument("--hidden-size", type=int, default=16)
    parser.add_argument("--test-size", type=float, default=0.2)
    parser.add_argument("--val-size", type=float, default=0.2,
                         help="Fraction of the TRAINING split (after test is carved out) held out for early stopping")
    args = parser.parse_args()

    data_path = Path(args.data)
    if not data_path.exists():
        print(f"[-] Data file not found: {data_path}")
        sys.exit(1)

    print(f"[+] Loading {data_path}...")
    all_rows = load_jsonl(data_path)

    beacon_rows = [r for r in all_rows if r.get("collected_label") == args.beacon_label]
    benign_rows = [r for r in all_rows if r.get("collected_label") == args.benign_label]
    print(f"[+] {len(beacon_rows)} beacon flows, {len(benign_rows)} benign flows")

    if len(beacon_rows) < 10:
        print(f"[-] Only {len(beacon_rows)} beacon flows — need at least 10 to train meaningfully.")
        sys.exit(1)

    flows = beacon_rows + benign_rows
    labels = np.array([1.0] * len(beacon_rows) + [0.0] * len(benign_rows), dtype=np.float32)

    print("[+] Extracting sequence features...")
    sizes, iats, mask, lengths = build_dataset(flows, SEQUENCE_LENGTH)

    # -- Three-way split: test held out first, then val carved from the rest.
    # val is used ONLY for early stopping (deciding when to stop training),
    # test is touched exactly once at the very end for the reported metrics.
    idx = np.arange(len(flows))
    idx_trainval, idx_test = train_test_split(
        idx, test_size=args.test_size, random_state=42, stratify=labels
    )
    idx_train, idx_val = train_test_split(
        idx_trainval, test_size=args.val_size, random_state=42,
        stratify=labels[idx_trainval],
    )

    # -- Normalization stats from TRAINING split only (avoid leakage) --
    real_mask_train = mask[idx_train].astype(bool)
    size_mean = float(sizes[idx_train][real_mask_train].mean()) if real_mask_train.any() else 0.0
    size_std = float(sizes[idx_train][real_mask_train].std()) if real_mask_train.any() else 1.0
    iat_mean = float(iats[idx_train][real_mask_train].mean()) if real_mask_train.any() else 0.0
    iat_std = float(iats[idx_train][real_mask_train].std()) if real_mask_train.any() else 1.0

    norm_sizes, norm_iats = normalize(sizes, iats, (size_mean, size_std), (iat_mean, iat_std))
    # Zero out padded positions again after normalization (mean-subtraction
    # would otherwise turn padding zeros into nonzero noise the LSTM sees).
    norm_sizes = norm_sizes * mask
    norm_iats = norm_iats * mask

    # -- Build model --
    model = BeaconLSTM(input_size=2, hidden_size=args.hidden_size)

    # Initialize the final layer's bias to the class-prior log-odds. Without
    # this, a random initial bias combined with heavy class imbalance can
    # trap training in a degenerate "always predict benign" state for many
    # epochs before any useful gradient signal emerges — which is exactly
    # what triggered early stopping prematurely in initial testing.
    n_pos = int(labels[idx_train].sum())
    n_neg = len(idx_train) - n_pos
    prior = n_pos / max(n_pos + n_neg, 1)
    prior = min(max(prior, 1e-4), 1 - 1e-4)  # avoid log(0)
    bias_init = float(np.log(prior / (1 - prior)))
    with torch.no_grad():
        model.classifier[-1].bias.fill_(bias_init)

    # Softened class weight: sqrt of the raw ratio rather than the full ratio.
    # The full ratio (n_neg/n_pos) with only ~40 positive examples pushed the
    # model to keep drifting toward "always predict positive" the longer it
    # trained, since the loss landscape rewards recall almost exclusively.
    # sqrt() keeps the correction meaningful without that runaway effect.
    pos_weight = torch.tensor([np.sqrt(n_neg / max(n_pos, 1))], dtype=torch.float32)
    loss_fn = nn.BCEWithLogitsLoss(pos_weight=pos_weight)
    optimizer = torch.optim.Adam(model.parameters(), lr=args.lr, weight_decay=args.weight_decay)

    print(f"[+] Train={len(idx_train)} ({n_pos} beacon / {n_neg} benign)  "
          f"Val={len(idx_val)}  Test={len(idx_test)}  pos_weight={pos_weight.item():.2f}")

    packed_train, order_train = make_packed_input(
        norm_sizes[idx_train], norm_iats[idx_train], lengths[idx_train]
    )
    y_train = torch.tensor(labels[idx_train][order_train], dtype=torch.float32)

    packed_val, order_val = make_packed_input(
        norm_sizes[idx_val], norm_iats[idx_val], lengths[idx_val]
    )
    y_val = labels[idx_val][order_val]

    def compute_f1(y_true, y_pred):
        tp = ((y_pred == 1) & (y_true == 1)).sum()
        fp = ((y_pred == 1) & (y_true == 0)).sum()
        fn = ((y_pred == 0) & (y_true == 1)).sum()
        precision = tp / max(tp + fp, 1)
        recall = tp / max(tp + fn, 1)
        f1 = 2 * precision * recall / max(precision + recall, 1e-8)
        return f1, precision, recall

    best_val_f1 = -1.0
    best_state = None
    best_epoch = 0
    epochs_since_improvement = 0

    for epoch in range(args.epochs):
        model.train()
        optimizer.zero_grad()
        logits = model(packed_train)
        loss = loss_fn(logits, y_train)
        loss.backward()
        optimizer.step()

        model.eval()
        with torch.no_grad():
            val_logits = model(packed_val)
            val_probs = torch.sigmoid(val_logits).numpy()
        val_preds = (val_probs >= 0.5).astype(np.float32)
        val_f1, val_p, val_r = compute_f1(y_val, val_preds)

        if val_f1 > best_val_f1:
            best_val_f1 = val_f1
            best_state = {k: v.clone() for k, v in model.state_dict().items()}
            best_epoch = epoch + 1
            epochs_since_improvement = 0
        else:
            epochs_since_improvement += 1

        if (epoch + 1) % 25 == 0 or epoch == 0:
            print(f"  [lstm] epoch {epoch + 1}/{args.epochs}  train_loss={loss.item():.4f}  "
                  f"val_f1={val_f1:.3f} (p={val_p:.2f} r={val_r:.2f})  "
                  f"best_val_f1={best_val_f1:.3f}@epoch{best_epoch}")

        if epochs_since_improvement >= args.patience and epoch >= args.warmup_epochs:
            print(f"  [lstm] Early stopping — no val F1 improvement in {args.patience} epochs")
            break

    print(f"\n[+] Restoring best checkpoint from epoch {best_epoch} (val_f1={best_val_f1:.3f})")
    model.load_state_dict(best_state)

    # -- Evaluate on held-out test split --
    model.eval()
    packed_test, order_test = make_packed_input(
        norm_sizes[idx_test], norm_iats[idx_test], lengths[idx_test]
    )
    y_test = labels[idx_test][order_test]
    with torch.no_grad():
        test_logits = model(packed_test)
        test_probs = torch.sigmoid(test_logits).numpy()
    preds = (test_probs >= 0.5).astype(np.float32)

    tp = int(((preds == 1) & (y_test == 1)).sum())
    fp = int(((preds == 1) & (y_test == 0)).sum())
    tn = int(((preds == 0) & (y_test == 0)).sum())
    fn = int(((preds == 0) & (y_test == 1)).sum())
    accuracy = (tp + tn) / max(len(y_test), 1)
    precision = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn, 1)

    print(f"\n[+] Test set ({len(y_test)} flows): accuracy={accuracy:.3f}  "
          f"precision={precision:.3f}  recall={recall:.3f}")
    print(f"    Confusion matrix — TP={tp}  FP={fp}  TN={tn}  FN={fn}")

    # -- Save artifacts --
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    torch.save(model.state_dict(), MODELS_DIR / "lstm_beacon.pt")
    with open(MODELS_DIR / "lstm_meta.json", "w", encoding="utf-8") as f:
        json.dump({
            "seq_len": SEQUENCE_LENGTH,
            "hidden_size": args.hidden_size,
            "size_mean": size_mean, "size_std": size_std,
            "iat_mean": iat_mean, "iat_std": iat_std,
            "best_epoch": best_epoch, "best_val_f1": best_val_f1,
            "test_accuracy": accuracy, "test_precision": precision, "test_recall": recall,
        }, f, indent=2)

    print(f"\n[+] Saved artifacts to {MODELS_DIR}/: lstm_beacon.pt, lstm_meta.json")


if __name__ == "__main__":
    main()
