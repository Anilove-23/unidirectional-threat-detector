"""Consumer validation; Agent 1 remains the owner of producer schemas."""

from copy import deepcopy
from datetime import datetime
import math


LABEL_FAMILIES = {
    "DDoS": "AVAILABILITY", "PORT_SCAN": "RECON", "DGA": "DNS",
    "DNS_TUNNEL": "DNS", "C2_BEACONING": "C2", "BOTNET_HOST": "BOTNET",
    "BOTNET_COORDINATION": "BOTNET", "ENCRYPTED_MALWARE": "MALWARE",
    "DATA_EXFILTRATION": "EXFILTRATION", "BRUTE_FORCE": "OTHER_KNOWN",
    "WEB_ATTACK": "OTHER_KNOWN",
}
OOD_SIGNALS = ("energy", "ae_error", "if_score", "latent_distance")


class ContractError(ValueError):
    pass


def probability(value, field):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not 0 <= value <= 1:
        raise ContractError(f"{field} must be a finite probability")
    return float(value)


def timestamp(value):
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.utcoffset() is None or parsed.utcoffset().total_seconds() != 0:
            raise ValueError("UTC required")
        return parsed.timestamp()
    except (AttributeError, TypeError, ValueError) as exc:
        raise ContractError("event_time must be an ISO-8601 UTC timestamp") from exc


def observation(raw):
    if not isinstance(raw, dict):
        raise ContractError("ObservationEnvelope must be an object")
    for field in ("event_id", "sensor_id", "event_time", "feature_schema_version", "schema_version"):
        if not isinstance(raw.get(field), str) or not raw[field]:
            raise ContractError(f"missing {field}")
    if raw["schema_version"].split(".")[0] != "2" or raw["feature_schema_version"].split(".")[0] != "2":
        raise ContractError("unsupported observation/feature major version")
    timestamp(raw["event_time"])
    for field in ("entity_keys", "features", "visibility", "history", "route_hints"):
        if not isinstance(raw.get(field), dict):
            raise ContractError(f"{field} must be an object")
    for key in ("flow_id", "source", "destination"):
        if not isinstance(raw["entity_keys"].get(key), str) or not raw["entity_keys"][key]:
            raise ContractError(f"entity_keys.{key} required")
    if raw.get("protocol") not in {"TCP", "UDP", "DNS", "TLS", "QUIC", "OTHER"}:
        raise ContractError("unsupported protocol")
    for group in ("flow", "window", "dns", "tls"):
        if not isinstance(raw["features"].get(group), dict):
            raise ContractError(f"features.{group} must be an object")
    probability(raw["visibility"].get("feature_availability_ratio"), "visibility ratio")
    for key, value in raw["visibility"].items():
        if key.endswith("_available") or key.endswith("_visible"):
            if not isinstance(value, bool):
                raise ContractError(f"visibility.{key} must be boolean")
    masks = raw.get("feature_availability", {})
    if not isinstance(masks, dict) or any(not isinstance(v, bool) for v in masks.values()):
        raise ContractError("feature_availability must map feature paths to booleans")
    for key in ("event_count", "duration_ms"):
        value = raw["history"].get(key)
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
            raise ContractError(f"invalid history.{key}")
    if not isinstance(raw["history"].get("window_complete"), bool):
        raise ContractError("history.window_complete must be boolean")
    if any(not isinstance(v, bool) for v in raw["route_hints"].values()):
        raise ContractError("route hints must be boolean")
    # Reject non-finite numeric features, including nested sequence values.
    def finite(value):
        if isinstance(value, dict):
            for v in value.values():
                finite(v)
        elif isinstance(value, list):
            for v in value:
                finite(v)
        elif isinstance(value, float) and not math.isfinite(value):
            raise ContractError("non-finite feature")
    finite(raw["features"])
    return deepcopy(raw)


def feature(envelope, path):
    """Return (value, present); absent and observed zero remain distinguishable."""
    group, key = path.split(".", 1)
    value = envelope["features"].get(group, {}).get(key)
    masks = envelope.get("feature_availability", {})
    visibility = envelope["visibility"]
    available = masks.get(path, True) and visibility.get(f"{key}_available", True)
    if key in {"nxdomain_ratio", "response_count", "rcode"}:
        available = available and visibility.get("dns_response_visible", False)
    if key in {"ja4", "ja4s", "sni"}:
        available = available and visibility.get(f"{key}_available", False)
    return (value, True) if available and value is not None else (None, False)


def specialist(raw, envelope, producer="agent1"):
    """Agent 2's expected consumer shape, pending a pinned producer release."""
    if not isinstance(raw, dict) or str(raw.get("schema_version", "")).split(".")[0] != "2":
        raise ContractError("unsupported SpecialistScore version")
    for key in ("event_id", "sensor_id"):
        if raw.get(key) != envelope[key]:
            raise ContractError(f"specialist {key} does not match observation")
    allowed = {"DGA", "DNS_TUNNEL"} if producer == "agent1" else set(LABEL_FAMILIES)
    if raw.get("label") not in allowed:
        raise ContractError("specialist label outside producer ownership")
    for key in ("score_present", "applicable", "calibrated"):
        if not isinstance(raw.get(key), bool):
            raise ContractError(f"specialist {key} must be boolean")
    if raw["score_present"]:
        if not raw["applicable"]:
            raise ContractError("inapplicable score cannot be present")
        probability(raw.get("probability"), "specialist probability")
    elif raw.get("probability") is not None or not raw.get("reason_codes"):
        raise ContractError("missing score requires null probability and reason_codes")
    if not raw.get("model_version") or not raw.get("model_id"):
        raise ContractError("specialist model identity required")
    return deepcopy(raw)


def make_score(envelope, label, value, model_id, model_version, *, calibrated=False, evidence=None, reason=None):
    return {
        "schema_version": "2.0.0", "event_id": envelope["event_id"],
        "sensor_id": envelope["sensor_id"], "label": label,
        "probability": value, "score_present": value is not None,
        "applicable": True, "calibrated": calibrated,
        "model_id": model_id, "model_version": model_version,
        "evidence": evidence or {}, "reason_codes": [reason] if reason else [],
    }
