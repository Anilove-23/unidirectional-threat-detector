import torch
from torch import nn


class TemporalCandidate(nn.Module):
    def __init__(self, features=2, kind="gru", hidden=32):
        super().__init__()
        if kind not in {"gru", "tcn"}:
            raise ValueError("kind must be gru or tcn")
        self.kind = kind
        self.sequence = nn.GRU(features, hidden, batch_first=True) if kind == "gru" else nn.Sequential(nn.Conv1d(features, hidden, 3, padding=2, dilation=1), nn.ReLU(), nn.Conv1d(hidden, hidden, 3, padding=4, dilation=2), nn.ReLU())
        self.head = nn.Linear(hidden, 1)

    def forward(self, sequences, lengths=None):
        if self.kind == "gru":
            if lengths is not None:
                sequences = nn.utils.rnn.pack_padded_sequence(sequences, lengths.cpu(), batch_first=True, enforce_sorted=False)
            _, state = self.sequence(sequences)
            features = state[-1]
        else:
            # Causal convolutions: discard the right-side padded future output.
            first = self.sequence[1](self.sequence[0](sequences.transpose(1, 2))[:, :, :-2])
            second = self.sequence[3](self.sequence[2](first)[:, :, :-4])
            index = lengths - 1 if lengths is not None else torch.full((len(sequences),), sequences.shape[1] - 1, device=sequences.device)
            features = second[torch.arange(len(sequences)), :, index]
        return self.head(features).squeeze(-1)


def fit_binary(model, values, targets, *, split, epochs=20, lengths=None):
    if split != "train":
        raise ValueError("temporal model requires training split")
    x, y = torch.as_tensor(values, dtype=torch.float32), torch.as_tensor(targets, dtype=torch.float32)
    optimizer = torch.optim.Adam(model.parameters(), lr=1e-3)
    positive_weight = (len(y) - y.sum()) / y.sum().clamp_min(1)
    for _ in range(epochs):
        loss = nn.functional.binary_cross_entropy_with_logits(model(x, lengths), y, pos_weight=positive_weight)
        optimizer.zero_grad()
        loss.backward()
        optimizer.step()
    model.eval()
    return model
