import numpy as np
from sklearn.metrics import (average_precision_score, roc_auc_score, precision_recall_fscore_support,
                             confusion_matrix, matthews_corrcoef, balanced_accuracy_score, roc_curve)


def calibration_metrics(targets, probabilities, bins=10):
    y, p = np.asarray(targets), np.asarray(probabilities)
    if not len(y):
        return {"ece": None, "brier": None}
    ece = 0.0
    for index in range(bins):
        selected = (p >= index / bins) & (p < (index + 1) / bins if index < bins - 1 else p <= 1)
        if selected.any():
            ece += selected.mean() * abs(y[selected].mean() - p[selected].mean())
    return {"ece": float(ece), "brier": float(np.mean((p-y) ** 2))}


def binary_metrics(targets, scores, threshold=0.5):
    y, p = np.asarray(targets), np.asarray(scores)
    predicted = p >= threshold
    precision, recall, f1, _ = precision_recall_fscore_support(y, predicted, average="binary", zero_division=0)
    tn, fp, fn, tp = confusion_matrix(y, predicted, labels=[0, 1]).ravel()
    both = len(np.unique(y)) == 2
    return {"precision": float(precision), "recall": float(recall), "f1": float(f1),
            "fpr": float(fp / (fp+tn)) if fp+tn else None, "fnr": float(fn / (fn+tp)) if fn+tp else None,
            "pr_auc": float(average_precision_score(y, p)) if both else None,
            "roc_auc": float(roc_auc_score(y, p)) if both else None,
            "mcc": float(matthews_corrcoef(y, predicted)) if both else None,
            "balanced_accuracy": float(balanced_accuracy_score(y, predicted)) if both else None,
            **calibration_metrics(y, p)}


def ood_metrics(targets, scores, target_recall=.75):
    metrics = binary_metrics(targets, scores)
    if len(np.unique(targets)) == 2:
        fpr, tpr, _ = roc_curve(targets, scores)
        metrics["fpr_at_target_recall"] = float(fpr[tpr >= target_recall].min())
    else:
        metrics["fpr_at_target_recall"] = None
    return metrics


def report(rows):
    """Rows pair ground truth with decisions. Missing scores stay unmeasured."""
    labels = sorted({label for row in rows for label in row["truth_labels"] if label != "ANOMALOUS_UNCLASSIFIED"})
    per_label = {}
    for label in labels:
        eligible = [r for r in rows if label in r["decision"]["label_probabilities"]]
        per_label[label] = binary_metrics([int(label in r["truth_labels"]) for r in eligible], [r["decision"]["label_probabilities"][label] for r in eligible], eligible[0]["decision"]["thresholds"][label]) if eligible else {"status": "not_measured"}
        # End-to-end recall includes routing skips and abstentions as misses.
        positives = [r for r in rows if label in r["truth_labels"]]
        per_label[label]["end_to_end_recall"] = sum(label in r["decision"]["labels"] for r in positives) / len(positives) if positives else None
        per_label[label]["score_coverage"] = len(eligible) / len(rows) if rows else 0
    benign = [r for r in rows if not r["truth_labels"]]
    alerts = [r for r in benign if r["decision"]["decision_state"] in {"KNOWN_ATTACK", "UNKNOWN"}]
    incidents = {incident["incident_id"] for r in alerts for incident in r.get("incidents", []) if incident.get("action") == "create"}
    selective = []
    for cutoff in (0.1, 0.25, 0.5, 0.75, 1):
        accepted = [r for r in rows if r["decision"]["decision_state"] != "UNCERTAIN" and r["decision"]["uncertainty"]["overall"] <= cutoff]
        correct = sum(set(r["truth_labels"]) == (set(r["decision"]["labels"]) or ({"ANOMALOUS_UNCLASSIFIED"} if r["decision"]["decision_state"] == "UNKNOWN" else set())) for r in accepted)
        selective.append({"cutoff": cutoff, "coverage": len(accepted)/len(rows) if rows else 0, "risk": 1-correct/len(accepted) if accepted else None})
    unknown_rows = [r for r in rows if r["truth_labels"] == ["ANOMALOUS_UNCLASSIFIED"]]
    return {"per_label": per_label, "uncertain_rate": sum(r["decision"]["decision_state"] == "UNCERTAIN" for r in rows)/len(rows) if rows else None,
            "raw_benign_alerts_per_10000": len(alerts)/len(benign)*10000 if benign else None,
            "benign_incidents_per_10000": len(incidents)/len(benign)*10000 if benign else None,
            "unknown_recall": sum(r["decision"]["decision_state"] == "UNKNOWN" for r in unknown_rows)/len(unknown_rows) if unknown_rows else None,
            "selective_risk": selective, "samples": len(rows)}


def routing_comparison(full, routed, truth):
    if not (len(full) == len(routed) == len(truth)):
        raise ValueError("aligned routing audit decisions required")
    total = sum(len(labels) for labels in truth)
    full_hits = sum(len(set(t) & set(p)) for t, p in zip(truth, full))
    routed_hits = sum(len(set(t) & set(p)) for t, p in zip(truth, routed))
    loss = (full_hits-routed_hits)/total if total else None
    return {"recall_loss": loss, "gate_passed": loss is not None and loss <= .01,
            "audit_sample_misses": sum(len((set(t) & set(f))-set(r)) for t, f, r in zip(truth, full, routed))}


def latency_summary(seconds):
    return {name: float(np.percentile(seconds, percentile)) if len(seconds) else None for name, percentile in (("p50", 50), ("p95", 95), ("p99", 99), ("max", 100))}
