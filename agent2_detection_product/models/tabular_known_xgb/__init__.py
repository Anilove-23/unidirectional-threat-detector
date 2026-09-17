import numpy as np
from xgboost import XGBClassifier


class KnownXGBoost:
    """Independent binary heads retain simultaneous labels."""
    def __init__(self, labels=("DDoS", "PORT_SCAN", "DATA_EXFILTRATION"), **params):
        if any(label in {"DGA", "DNS_TUNNEL"} for label in labels):
            raise ValueError("DNS models are owned by Agent 1")
        self.labels = tuple(labels)
        self.params = {"n_estimators": 80, "max_depth": 4, "learning_rate": 0.08, "n_jobs": 1, "random_state": 26, "eval_metric": "logloss", **params}

    def fit(self, values, targets, *, split):
        if split != "train":
            raise ValueError("XGBoost fit requires training split")
        self.models = {}
        for index, label in enumerate(self.labels):
            y = np.asarray(targets)[:, index]
            if len(np.unique(y)) != 2:
                raise ValueError(f"training fold lacks positives or negatives for {label}")
            positive = y.sum()
            model = XGBClassifier(**self.params, scale_pos_weight=(len(y) - positive) / positive)
            self.models[label] = model.fit(values, y)
        return self

    def predict(self, values):
        return np.column_stack([self.models[label].predict_proba(values)[:, 1] for label in self.labels])
