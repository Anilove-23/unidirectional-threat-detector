from ..state_detection import TTLStore


def adaptation_action(level, *, verified_labels=False):
    if level == "NONE":
        return "NO_ACTION"
    if not verified_labels:
        return "ANALYST_REVIEW_NO_TRAINING"
    return {"MILD": "VALIDATION_RECALIBRATION", "MODERATE": "VALIDATED_PROFILE_REVIEW", "SEVERE": "OFFLINE_RETRAIN_WITH_REPLAY"}.get(level, "ANALYST_REVIEW_NO_TRAINING")


class BenignBaselines:
    def __init__(self, capacity=10000, alpha=0.05):
        self.state = TTLStore(ttl=86400, capacity=capacity)
        self.alpha = alpha

    def update(self, key, values, decision, now):
        if decision["decision_state"] != "BENIGN" or (decision["confidence"] or 0) < 0.95 or decision["uncertainty"]["overall"] > 0.1 or decision["drift_status"] not in {"NONE", "MILD"}:
            return False
        baseline = self.state.get(key, now, {"count": 0, "means": {}})
        for name, value in values.items():
            if value is not None:
                previous = baseline["means"].get(name, value)
                baseline["means"][name] = previous + self.alpha * (value - previous)
        baseline["count"] += 1
        self.state.put(key, baseline, now)
        return True


def regression_gate(previous, candidate, max_recall_drop=0.01, max_ece_increase=0.01):
    for label, metrics in previous.items():
        new = candidate.get(label)
        if not new or metrics["recall"] - new["recall"] > max_recall_drop or new["ece"] - metrics["ece"] > max_ece_increase:
            return False
    return True
