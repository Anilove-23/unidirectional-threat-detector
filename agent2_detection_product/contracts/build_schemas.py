"""Rebuild Agent 2-owned downstream schemas; never publishes producer schemas."""
import json
from pathlib import Path
from . import LABEL_FAMILIES


def build():
    number = {"type": "number", "minimum": 0, "maximum": 1}
    nullable = {"anyOf": [number, {"type": "null"}]}
    string = {"type": "string", "minLength": 1}
    mapping = {"type": "object"}
    labels = {"type": "object", "propertyNames": {"enum": list(LABEL_FAMILIES)}, "additionalProperties": number}
    decision = {
        "$schema": "http://json-schema.org/draft-07/schema#", "title": "DecisionRecord v2", "type": "object",
        "properties": {
            "schema_version": {"const": "2.0.0"}, "decision_id": string, "event_id": string, "sensor_id": string,
            "event_time": {"type": "string", "format": "date-time"}, "entity_keys": {"type": "object", "required": ["flow_id", "source", "destination"], "properties": {k: string for k in ("flow_id", "source", "destination")}},
            "protocol": string, "decision_state": {"enum": ["BENIGN", "KNOWN_ATTACK", "UNKNOWN", "UNCERTAIN"]},
            "primary_class": {"enum": [*LABEL_FAMILIES, "ANOMALOUS_UNCLASSIFIED", None]}, "labels": labels,
            "label_probabilities": labels, "confidence": nullable,
            "uncertainty": {"type": "object", "required": ["ood", "epistemic_proxy", "expert_disagreement", "overall"], "properties": {k: nullable for k in ("ood", "epistemic_proxy", "expert_disagreement", "overall")}},
            "ood": {"type": "object", "required": ["energy", "ae_error", "if_score", "latent_distance"], "properties": {k: nullable for k in ("energy", "ae_error", "if_score", "latent_distance")}},
            "visibility_ratio": number, "visibility": mapping, "history_length": {"type": "number", "minimum": 0}, "history": mapping,
            "threshold_version": string, "thresholds": labels, "routing_policy_version": string,
            "routing": mapping, "score_presence": {"type": "object", "additionalProperties": {"type": "boolean"}},
            "reason_codes": {"type": "array", "items": string}, "model_versions": {"type": "object", "additionalProperties": string}, "evidence": mapping,
            "drift_status": string, "model_profile": string,
        },
    }
    decision["required"] = list(decision["properties"])
    decision["allOf"] = [
        {"if": {"properties": {"decision_state": {"const": "KNOWN_ATTACK"}}}, "then": {"properties": {"labels": {"type": "object", "minProperties": 1}, "primary_class": {"enum": list(LABEL_FAMILIES)}, "confidence": number}}},
        {"if": {"properties": {"decision_state": {"enum": ["BENIGN", "UNCERTAIN"]}}}, "then": {"properties": {"labels": {"type": "object", "maxProperties": 0}, "primary_class": {"type": "null"}}}},
        {"if": {"properties": {"decision_state": {"const": "UNKNOWN"}}}, "then": {"properties": {"labels": {"type": "object", "maxProperties": 0}, "primary_class": {"const": "ANOMALOUS_UNCLASSIFIED"}, "confidence": number}}},
    ]
    incident = {"$schema": decision["$schema"], "title": "IncidentUpdate v2", "type": "object", "properties": {
        "schema_version": {"const": "2.0.0"}, "incident_id": string, "sensor_id": string, "entity": string, "family": string,
        "action": {"enum": ["create", "update", "close", "reopen"]}, "status": {"enum": ["open", "closed"]},
        "first_seen": {"type": "string", "format": "date-time"}, "last_seen": {"type": "string", "format": "date-time"},
        "count": {"type": "integer", "minimum": 1}, "labels": {"type": "object", "additionalProperties": number},
        "severity": {"enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"]}, "reason_codes": {"type": "array", "items": string},
        "timeline": {"type": "array", "maxItems": 64, "items": {"type": "object", "required": ["decision_id", "event_time", "labels", "evidence"], "properties": {"decision_id": string, "event_time": {"type": "string", "format": "date-time"}, "labels": {"type": "array", "items": string}, "evidence": mapping}}}
    }}
    incident["required"] = list(incident["properties"])
    for name, schema in (("decision", decision), ("incident", incident)):
        directory = Path(__file__).parent / name
        directory.mkdir(exist_ok=True)
        (directory / "schema.json").write_text(json.dumps(schema, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    build()
