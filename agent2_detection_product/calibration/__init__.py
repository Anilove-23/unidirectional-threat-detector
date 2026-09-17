import numpy as np
from sklearn.isotonic import IsotonicRegression
from sklearn.metrics import precision_recall_curve


class LabelCalibrator:
    def fit(self, scores, targets, *, split):
        if split != "validation":
            raise ValueError("calibration requires validation split")
        if len(np.unique(targets)) != 2:
            raise ValueError("calibration requires positives and negatives")
        self.model = IsotonicRegression(out_of_bounds="clip").fit(scores, targets)
        return self

    def predict(self, scores):
        return self.model.predict(scores)


def select_threshold(scores, targets, *, split, max_fpr=0.01, min_recall=0.85):
    if split != "validation":
        raise ValueError("threshold selection requires validation split")
    scores, targets = np.asarray(scores), np.asarray(targets)
    if len(np.unique(targets)) != 2:
        raise ValueError("threshold validation requires both classes")
    candidates = sorted(set(scores.tolist()) | {1.0})
    eligible = []
    for threshold in candidates:
        predicted = scores >= threshold
        tp = np.sum(predicted & (targets == 1))
        fp = np.sum(predicted & (targets == 0))
        fn = np.sum(~predicted & (targets == 1))
        recall = tp / max(np.sum(targets == 1), 1)
        fpr = fp / max(np.sum(targets == 0), 1)
        f1 = 2 * tp / max(2 * tp + fp + fn, 1)
        if fpr <= max_fpr and recall >= min_recall:
            eligible.append((f1, threshold))
    if not eligible:
        raise ValueError("no validation threshold meets FPR/recall gates; release rejected")
    return float(max(eligible)[1])
