"""Energy is -T logsumexp(logits/T); higher values are out-of-support."""

import numpy as np
import torch
from torch import nn


class EnergyHead(nn.Module):
    def __init__(self, dimensions, classes, temperature=1.0):
        super().__init__()
        if temperature <= 0:
            raise ValueError("positive temperature required")
        self.head = nn.Linear(dimensions, classes)
        self.temperature = temperature

    def fit(self, values, targets, *, split, epochs=30):
        if split != "train":
            raise ValueError("energy head requires training split")
        x, y = torch.as_tensor(values, dtype=torch.float32), torch.as_tensor(targets, dtype=torch.long)
        optimizer = torch.optim.Adam(self.parameters(), lr=1e-3)
        for _ in range(epochs):
            loss = nn.functional.cross_entropy(self.head(x), y)
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()
        return self

    def energy(self, values):
        with torch.no_grad():
            logits = self.head(torch.as_tensor(values, dtype=torch.float32))
            return (-self.temperature * torch.logsumexp(logits / self.temperature, dim=1)).numpy()


class PrototypeDistance:
    def fit(self, values, labels, *, split):
        if split != "train":
            raise ValueError("prototypes require training split")
        x, y = np.asarray(values), np.asarray(labels)
        self.prototypes = np.stack([x[y == label].mean(axis=0) for label in np.unique(y)])
        return self

    def distance(self, values):
        return np.linalg.norm(np.asarray(values)[:, None, :] - self.prototypes[None, :, :], axis=-1).min(axis=1)


class ReferencePercentiles:
    """Benign validation-tail ranks, not a claim of calibrated OOD probability."""
    def fit(self, values, *, split):
        if split != "validation":
            raise ValueError("OOD thresholds require validation data")
        self.reference = np.sort(np.asarray(values))
        if len(self.reference) < 2:
            raise ValueError("at least two validation reference values required")
        return self

    def transform(self, values):
        return np.searchsorted(self.reference, values, side="right") / len(self.reference)
