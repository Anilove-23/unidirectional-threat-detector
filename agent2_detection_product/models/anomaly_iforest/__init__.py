from sklearn.ensemble import IsolationForest


class LatentIsolationForest:
    def fit(self, values, *, split):
        if split != "train":
            raise ValueError("IF must fit training data only")
        self.model = IsolationForest(n_estimators=100, random_state=26, n_jobs=1).fit(values)
        return self

    def anomaly(self, values):
        return -self.model.score_samples(values)
