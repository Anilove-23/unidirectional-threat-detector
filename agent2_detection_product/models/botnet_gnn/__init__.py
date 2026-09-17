"""Directed GraphSAGE; IPs are graph indices, never predictive attributes."""

import torch
from torch import nn


class GraphSAGE(nn.Module):
    def __init__(self, features, hidden=32, dimensions=32):
        super().__init__()
        self.first = nn.Linear(features * 2, hidden)
        self.second = nn.Linear(hidden * 2, dimensions)
        self.head = nn.Linear(dimensions, 2)

    @staticmethod
    def neighbors(values, edges):
        sums, count = torch.zeros_like(values), values.new_zeros((len(values), 1))
        if edges.numel():
            source, destination = edges
            sums.index_add_(0, destination, values[source])
            count.index_add_(0, destination, values.new_ones((len(source), 1)))
        return sums / count.clamp_min(1)

    def embed(self, values, edges):
        hidden = torch.relu(self.first(torch.cat((values, self.neighbors(values, edges)), dim=1)))
        return torch.relu(self.second(torch.cat((hidden, self.neighbors(hidden, edges)), dim=1)))

    def forward(self, values, edges):
        return self.head(self.embed(values, edges))

    def fit(self, graphs, *, split, epochs=20):
        if split != "train":
            raise ValueError("GNN pretraining requires training graphs")
        optimizer = torch.optim.Adam(self.parameters(), lr=1e-3)
        for _ in range(epochs):
            for values, edges, targets in graphs:
                loss = nn.functional.binary_cross_entropy_with_logits(self(values, edges), targets)
                optimizer.zero_grad()
                loss.backward()
                optimizer.step()
        self.eval()
        return self
