"""Four-state, calibrated, evidence-gated decisions with explicit abstention."""

import hashlib
import json
from statistics import pstdev
from ..contracts import LABEL_FAMILIES, OOD_SIGNALS, probability, specialist
from ..gating import gates


DEFAULT_POLICY = {
    "version": "thresholds-2.0.0-dev", "routing_version": "routing-2.0.0",
    "approved": False, "thresholds": {label: 0.85 for label in LABEL_FAMILIES},
    "review_floor": 0.4, "unknown_threshold": 0.8, "benign_ceiling": 0.2,
    "min_visibility": 0.6, "max_disagreement": 0.3,
    "required_coverage": [label for label in LABEL_FAMILIES if label not in {"BRUTE_FORCE", "WEB_ATTACK"}],
}


class DecisionEngine:
    def __init__(self, policy=None):
        self.policy = json.loads(json.dumps(policy or DEFAULT_POLICY))
        p = self.policy
        if set(p["thresholds"]) != set(LABEL_FAMILIES):
            raise ValueError("one threshold required for every label")
        for label, threshold in p["thresholds"].items():
            probability(threshold, label)
        for key in ("review_floor", "unknown_threshold", "benign_ceiling", "min_visibility", "max_disagreement"):
            probability(p[key], key)
        if not p.get("version") or not p.get("routing_version"):
            raise ValueError("policy versions required")

    def decide(self, envelope, scores=(), ood=None, context=None):
        p, context = self.policy, context or {}
        routes = gates(envelope, context)
        grouped = {}
        evidence, versions, presence, reasons = {}, {}, {}, []
        for raw in scores:
            s = specialist(raw, envelope, producer="agent2")
            identity = f"{s['model_id']}:{s['label']}"
            if identity in presence:
                raise ValueError("duplicate specialist score")
            presence[identity] = s["score_present"]
            versions[s["model_id"]] = s["model_version"]
            evidence[identity] = s.get("evidence", {})
            if not s["score_present"]:
                reasons.extend(s.get("reason_codes", []))
            elif s["calibrated"] and routes[s["label"]]["ready"]:
                grouped.setdefault(s["label"], []).append(s)
            else:
                reasons.append("UNCALIBRATED_SCORE" if not s["calibrated"] else f"{s['label']}_EVIDENCE_INCOMPLETE")
        # Approved meta output wins. Multiple base experts require learned fusion;
        # averaging or max-score override would silently resurrect V1 behavior.
        probabilities, disagreements = {}, []
        for label, members in grouped.items():
            values = [s["probability"] for s in members]
            disagreements.append(pstdev(values) if len(values) > 1 else 0.0)
            meta = [s for s in members if s["model_id"] == "meta_xgb"]
            if len(meta) == 1:
                probabilities[label] = meta[0]["probability"]
            elif len(members) == 1:
                probabilities[label] = values[0]
            else:
                reasons.append("FUSION_MODEL_REQUIRED")
        ood = ood or {}
        signals = {key: None if ood.get(key) is None else probability(ood[key], key) for key in OOD_SIGNALS}
        available = [v for v in signals.values() if v is not None]
        high_signals = sum(v >= p["unknown_threshold"] for v in available)
        ood_score = sum(available) / len(available) if available else None
        disagreement = max(disagreements, default=0.0)
        visibility = envelope["visibility"]["feature_availability_ratio"]
        mature = envelope["history"]["window_complete"] and envelope["history"]["event_count"] >= 3
        quality = visibility >= p["min_visibility"] and mature
        coverage = all(label in probabilities for label in p["required_coverage"] if routes[label]["applicable"])
        for label in ("DGA", "DNS_TUNNEL", "ENCRYPTED_MALWARE"):
            if routes[label]["applicable"] and label not in probabilities:
                coverage = False
        passed = {k: v for k, v in probabilities.items() if v >= p["thresholds"][k]}
        drift = context.get("drift_status", "NONE")
        state, confidence = "UNCERTAIN", None
        if not p["approved"]:
            reasons.append("POLICY_NOT_VALIDATED")
        elif visibility < p["min_visibility"] or disagreement > p["max_disagreement"] or drift in {"SEVERE", "UNVERIFIED"}:
            reasons.append("LOW_VISIBILITY" if visibility < p["min_visibility"] else "EXPERT_CONFLICT" if disagreement > p["max_disagreement"] else "DRIFT_REVIEW")
        elif passed:
            state, confidence = "KNOWN_ATTACK", max(passed.values())
            reasons.append("CLASS_THRESHOLD_PASSED")
        elif quality and high_signals >= 2 and ood.get("calibrated") is True and max(probabilities.values(), default=0) < p["review_floor"]:
            state, confidence = "UNKNOWN", ood_score
            reasons.append("MULTI_SIGNAL_OOD_AGREEMENT")
        elif quality and coverage and len(available) >= 2 and ood.get("calibrated") is True and max(available) <= p["benign_ceiling"] and max(probabilities.values(), default=1) <= p["benign_ceiling"]:
            state, confidence = "BENIGN", 1 - max([*probabilities.values(), *available])
            reasons.append("BENIGN_COVERAGE_COMPLETE")
        else:
            reasons.append("INCOMPLETE_OR_REVIEW_BAND")
        labels = passed if state == "KNOWN_ATTACK" else {}
        primary = max(labels, key=labels.get) if labels else "ANOMALOUS_UNCLASSIFIED" if state == "UNKNOWN" else None
        epistemic = signals["latent_distance"]
        uncertainty = {"ood": ood_score, "epistemic_proxy": epistemic,
                       "expert_disagreement": disagreement,
                       "overall": max([1 - visibility, disagreement, *([epistemic] if epistemic is not None else []), 1.0 if state == "UNCERTAIN" else 0.0])}
        identity = json.dumps([envelope["sensor_id"], envelope["event_id"], p["version"], p["routing_version"], versions], sort_keys=True)
        return {
            "schema_version": "2.0.0", "decision_id": hashlib.sha256(identity.encode()).hexdigest(),
            "event_id": envelope["event_id"], "sensor_id": envelope["sensor_id"],
            "event_time": envelope["event_time"], "entity_keys": envelope["entity_keys"],
            "protocol": envelope["protocol"], "decision_state": state, "primary_class": primary,
            "labels": labels, "label_probabilities": probabilities,
            "behavior_families": sorted({LABEL_FAMILIES[k] for k in labels}),
            "confidence": confidence, "uncertainty": uncertainty, "ood": signals,
            "visibility_ratio": visibility, "visibility": envelope["visibility"],
            "history_length": envelope["history"]["event_count"], "history": envelope["history"],
            "threshold_version": p["version"], "thresholds": p["thresholds"],
            "routing_policy_version": p["routing_version"], "routing": routes,
            "score_presence": presence, "reason_codes": sorted(set(reasons)),
            "model_versions": versions, "evidence": evidence, "drift_status": drift,
            "model_profile": context.get("model_profile", "unconfigured"),
        }
