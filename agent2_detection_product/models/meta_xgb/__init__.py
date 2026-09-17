"""Out-of-fold stacking with explicit held-out group provenance."""

import numpy as np
from sklearn.model_selection import GroupKFold
from ..tabular_known_xgb import KnownXGBoost


def generate_oof(factory, records, targets, groups, *, folds=3):
    """factory creates the ENTIRE train-only preprocessing+model pipeline."""
    if len(records) != len(targets) or len(records) != len(groups):
        raise ValueError("OOF inputs must align")
    groups = np.asarray(groups)
    if len(set(groups)) < folds:
        raise ValueError("insufficient independent scenario/family groups")
    scores, provenance = None, []
    for fold, (train, heldout) in enumerate(GroupKFold(folds).split(records, targets, groups)):
        model = factory()
        model.fit([records[i] for i in train], np.asarray(targets)[train], split="train")
        predicted = np.asarray(model.predict([records[i] for i in heldout]))
        if scores is None:
            scores = np.full((len(records), predicted.shape[1]), np.nan)
        scores[heldout] = predicted
        for index in heldout:
            provenance.append({"index": int(index), "fold": fold, "prediction_group": str(groups[index]), "training_groups": sorted(set(groups[train].tolist())), "split": "train"})
    return scores, sorted(provenance, key=lambda row: row["index"])


def validate_oof(provenance, count):
    if len(provenance) != count or sorted(row["index"] for row in provenance) != list(range(count)):
        raise ValueError("one provenance record per OOF row required")
    for row in provenance:
        if row["split"] != "train" or not row["training_groups"] or row["prediction_group"] in row["training_groups"]:
            raise ValueError("in-sample or non-training score cannot enter meta training")


class MetaXGBoost(KnownXGBoost):
    def __init__(self, labels, **params):
        # DNS labels may be fused here, but never trained as Agent 2 base models.
        super().__init__((), **params)
        self.labels = tuple(labels)

    def fit_oof(self, values, targets, provenance):
        validate_oof(provenance, len(values))
        return super().fit(values, targets, split="train")

    def fit(self, *args, **kwargs):
        raise ValueError("use fit_oof with held-out provenance")


def context_vector(envelope, scores, *, baseline_mature=False, drift=False, queue_age=0):
    """Fixed score order is supplied by the immutable model manifest."""
    values, masks = [], []
    for value in scores:
        values.append(float(value) if value is not None else np.nan)
        masks.append(float(value is not None))
    present = [v for v in scores if v is not None]
    ordered = sorted(present, reverse=True)
    entropy = float(np.mean([-v * np.log(max(v, 1e-9)) - (1-v) * np.log(max(1-v, 1e-9)) for v in present])) if present else np.nan
    return values + masks + [envelope["visibility"]["feature_availability_ratio"], envelope["history"]["event_count"], envelope["history"]["duration_ms"], float(envelope["history"]["window_complete"]), float(baseline_mature), float(drift), queue_age, entropy, ordered[0] - ordered[1] if len(ordered) > 1 else np.nan, float(np.std(present)) if present else np.nan]
