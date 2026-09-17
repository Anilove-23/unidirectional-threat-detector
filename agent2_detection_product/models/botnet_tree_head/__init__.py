import numpy as np
from sklearn.ensemble import ExtraTreesClassifier


class BotnetTreeHead:
    labels = ("BOTNET_HOST", "BOTNET_COORDINATION")

    def fit(self, embeddings, flow_features, targets, *, split):
        if split != "train":
            raise ValueError("botnet head requires training split")
        self.models = []
        x = np.column_stack((embeddings, flow_features))
        for i in range(2):
            if len(np.unique(targets[:, i])) != 2:
                raise ValueError("each botnet label requires positive and negative training examples")
            self.models.append(ExtraTreesClassifier(n_estimators=100, class_weight="balanced", random_state=26, n_jobs=1).fit(x, targets[:, i]))
        return self

    def predict(self, embeddings, flow_features):
        x = np.column_stack((embeddings, flow_features))
        return np.column_stack([m.predict_proba(x)[:, 1] for m in self.models])
