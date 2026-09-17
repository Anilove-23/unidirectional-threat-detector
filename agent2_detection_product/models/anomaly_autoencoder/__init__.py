import numpy as np
import torch
from torch import nn


class BenignAutoencoder(nn.Module):
    def __init__(self, dimensions):
        super().__init__()
        self.network = nn.Sequential(nn.Linear(dimensions, 32), nn.ReLU(), nn.Linear(32, 8), nn.ReLU(), nn.Linear(8, dimensions))

    def fit(self, values, *, split, verified_benign, epochs=30):
        if split != "train" or not verified_benign:
            raise ValueError("AE requires verified benign training data")
        x = torch.as_tensor(np.asarray(values, dtype=np.float32))
        if not len(x):
            raise ValueError("no verified benign samples")
        optimizer = torch.optim.Adam(self.parameters(), lr=1e-3)
        self.train()
        for _ in range(epochs):
            for batch in x.split(128):
                loss = ((self.network(batch) - batch) ** 2).mean()
                optimizer.zero_grad()
                loss.backward()
                optimizer.step()
        self.eval()
        return self

    def error(self, values):
        with torch.no_grad():
            x = torch.as_tensor(np.asarray(values, dtype=np.float32))
            return ((self.network(x) - x) ** 2).mean(dim=1).numpy()
