from __future__ import annotations

from dataclasses import dataclass
from copy import deepcopy
from typing import Any

from ..contracts import ContractError, observation
from .schema_checks import check_observation_versions


@dataclass(frozen=True)
class MeasurementView:
    value: Any
    available: bool
    applicable: bool
    reason: str


def unwrap_measurement(raw: Any) -> MeasurementView:
    """Normalize one Agent 1 measurement without collapsing missing to zero."""
    if isinstance(raw, dict) and "value" in raw:
        available = bool(raw.get("available", raw.get("value") is not None))
        applicable = bool(raw.get("applicable", True))
        value = raw.get("value")
        if available != (value is not None):
            raise ContractError("measurement availability disagrees with value")
        if not applicable and available:
            raise ContractError("inapplicable measurement cannot be available")
        reason = str(raw.get("reason") or ("OBSERVED" if available else "NOT_OBSERVED"))
        return MeasurementView(value, available, applicable, reason)
    if raw is None:
        return MeasurementView(None, False, True, "NOT_OBSERVED")
    return MeasurementView(raw, True, True, "OBSERVED")


@dataclass(frozen=True)
class AdaptedObservation:
    """Flattened model input plus masks and diagnostic metadata."""

    raw: dict[str, Any]
    values: dict[str, Any]
    availability: dict[str, int]
    applicability: dict[str, int]
    reasons: dict[str, str]

    def value(self, path: str):
        return self.values.get(path)

    def available(self, path: str) -> bool:
        return bool(self.availability.get(path, 0))


def _flatten(group: str, fields: dict[str, Any], *, prefix=""):
    values, availability, applicability, reasons = {}, {}, {}, {}
    for key, raw in fields.items():
        path = f"{group}.{prefix}{key}" if prefix else f"{group}.{key}"
        # A few Agent 1 window keys use dotted names. Keep them as one
        # canonical path; nested dicts are flattened only when they are not a
        # measurement wrapper.
        if isinstance(raw, dict) and "value" not in raw:
            nested = _flatten(group, raw, prefix=f"{prefix}{key}.")
            for target, source in zip((values, availability, applicability, reasons), nested):
                target.update(source)
            continue
        view = unwrap_measurement(raw)
        values[path] = view.value if view.available and view.applicable else None
        availability[path] = int(view.available and view.applicable)
        applicability[path] = int(view.applicable)
        reasons[path] = view.reason
    return values, availability, applicability, reasons


def adapt_observation(raw: dict[str, Any]) -> AdaptedObservation:
    """Validate an ObservationEnvelope v2 and expose model-ready parallel maps."""
    check_observation_versions(raw)
    validated = observation(raw)
    values, availability, applicability, reasons = {}, {}, {}, {}
    for group, fields in validated["features"].items():
        if not isinstance(fields, dict):
            raise ContractError(f"features.{group} must be an object")
        flattened = _flatten(group, fields)
        for target, source in zip((values, availability, applicability, reasons), flattened):
            target.update(source)
    return AdaptedObservation(deepcopy(validated), values, availability, applicability, reasons)


def adapt_many(rows):
    return [adapt_observation(row) for row in rows]
