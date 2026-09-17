"""Masked/denoising representation with contrastive and temporal objectives."""

import numpy as np
import torch
from torch import nn
from torch.nn import functional as F
from ...contracts import feature


class MaskedPreprocessor:
    def __init__(self, feature_paths):
        if not feature_paths or any(p.split(".")[0] not in {"flow", "window", "dns", "tls"} for p in feature_paths):
            raise ValueError("explicit canonical numeric feature paths required")
        if any(any(token in p.lower() for token in ("src_ip", "dst_ip", "source", "destination_ip", "sensor", "label", "scenario")) for p in feature_paths):
            raise ValueError("identity/label features are prohibited")
        self.paths = list(feature_paths)
        self.mean = self.scale = None

    def raw(self, envelopes):
        rows = []
        for envelope in envelopes:
            row = []
            for path in self.paths:
                value, present = feature(envelope, path)
                numeric = present and isinstance(value, (int, float)) and not isinstance(value, bool)
                row.append(float(value) if numeric else np.nan)
            rows.append(row)
        return np.asarray(rows, dtype=np.float32)

    def fit(self, envelopes, *, split):
        if split != "train":
            raise ValueError("preprocessing may only fit training data")
        x = self.raw(envelopes)
        if len(x) == 0:
            raise ValueError("empty training data")
        mask = np.isfinite(x)
        count = np.maximum(mask.sum(axis=0), 1)
        self.mean = np.where(mask, x, 0).sum(axis=0) / count
        variance = np.where(mask, (x - self.mean) ** 2, 0).sum(axis=0) / count
        self.scale = np.maximum(np.sqrt(variance), 1e-6)
        return self

    def transform(self, envelopes):
        if self.mean is None:
            raise ValueError("preprocessor not fitted")
        raw = self.raw(envelopes)
        mask = np.isfinite(raw).astype(np.float32)
        # Neutral numeric placeholders are always accompanied by presence masks.
        values = np.where(mask.astype(bool), (raw - self.mean) / self.scale, 0)
        return np.clip(values, -20, 20).astype(np.float32), mask


class SSLEncoder(nn.Module):
    def __init__(self, features, latent_dim=32):
        super().__init__()
        if not 32 <= latent_dim <= 64:
            raise ValueError("V2 embeddings must be 32-64 dimensional")
        self.encoder = nn.Sequential(nn.Linear(2 * features, 96), nn.GELU(), nn.Linear(96, latent_dim))
        self.decoder = nn.Sequential(nn.Linear(latent_dim, 96), nn.GELU(), nn.Linear(96, features))

    def forward(self, values, mask):
        z = self.encoder(torch.cat((values * mask, mask), dim=-1))
        return z, self.decoder(z)

    def fit(self, values, mask, *, split, epochs=20, batch_size=128, seed=26, temporal_pairs=None):
        if split != "train":
            raise ValueError("SSL pretraining must exclude validation/test distributions")
        torch.manual_seed(seed)
        x, m = torch.as_tensor(values), torch.as_tensor(mask)
        optimizer = torch.optim.Adam(self.parameters(), lr=1e-3)
        self.train()
        for _ in range(epochs):
            for indices in torch.randperm(len(x)).split(batch_size):
                target, observed = x[indices], m[indices]
                views = []
                loss = target.new_tensor(0.0)
                for _view in range(2):
                    kept = observed * (torch.rand_like(observed) > 0.2)
                    corrupted = target + torch.randn_like(target) * 0.05
                    z, reconstruction = self(corrupted, kept)
                    loss = loss + (((reconstruction - target) ** 2) * observed).sum() / observed.sum().clamp_min(1)
                    views.append(F.normalize(z, dim=1))
                logits = views[0] @ views[1].T / 0.2
                loss = loss + 0.1 * (F.cross_entropy(logits, torch.arange(len(indices))) + F.cross_entropy(logits.T, torch.arange(len(indices))))
                optimizer.zero_grad()
                loss.backward()
                optimizer.step()
            if temporal_pairs:
                left, right = zip(*temporal_pairs)
                zl, _ = self(x[list(left)], m[list(left)])
                zr, _ = self(x[list(right)], m[list(right)])
                loss = 0.05 * F.mse_loss(zl, zr)
                optimizer.zero_grad()
                loss.backward()
                optimizer.step()
        self.eval()
        return self

    def embed(self, values, mask):
        self.eval()
        with torch.no_grad():
            z, _ = self(torch.as_tensor(values), torch.as_tensor(mask))
        return z.numpy()
