import json
from pathlib import Path

import pytest

from ..adapters import adapt_observation
from ..contracts import ContractError, feature
from ..dataset.training_index import build_training_index, resolve_training_index
from ..dataset.split_validation import validate_index_splits
from .fixtures import envelope


def wrapped_envelope():
    raw = envelope(protocol="DNS")
    raw["features"]["flow"]["byte_count"] = {"value": 0, "available": True, "applicable": True, "reason": "OBSERVED"}
    raw["features"]["dns"]["query_name"] = {"value": "www.example.test", "available": True, "applicable": True, "reason": "OBSERVED"}
    raw["features"]["dns"]["nxdomain_ratio"] = {"value": None, "available": False, "applicable": True, "reason": "DNS_RESPONSE_NOT_VISIBLE"}
    raw["features"]["flow"]["fin_count"] = {"value": None, "available": False, "applicable": False, "reason": "NOT_TCP"}
    return raw


def test_adapter_preserves_zero_nan_masks_and_reasons():
    adapted = adapt_observation(wrapped_envelope())
    assert adapted.value("flow.byte_count") == 0
    assert adapted.available("flow.byte_count")
    assert adapted.value("dns.nxdomain_ratio") is None
    assert not adapted.available("dns.nxdomain_ratio")
    assert adapted.applicability["flow.fin_count"] == 0
    assert adapted.reasons["dns.nxdomain_ratio"] == "DNS_RESPONSE_NOT_VISIBLE"
    assert feature(adapted.raw, "flow.byte_count") == (0, True)
    assert feature(adapted.raw, "dns.nxdomain_ratio") == (None, False)


def test_adapter_rejects_inconsistent_measurement():
    raw = wrapped_envelope()
    raw["features"]["flow"]["byte_count"]["available"] = False
    with pytest.raises(ContractError):
        adapt_observation(raw)


def test_adapter_rejects_schema_major_mismatch():
    raw = wrapped_envelope()
    raw["feature_schema_version"] = "3.0.0"
    with pytest.raises(ContractError):
        adapt_observation(raw)


def test_index_joins_current_agent1_release(tmp_path):
    scenario_dir = tmp_path / "train" / "scenario-1"
    scenario_dir.mkdir(parents=True)
    raw = wrapped_envelope()
    raw["event_id"] = "obs-1"
    manifest = {
        "schema_version": "1.0.0", "scenario_id": "scenario-1", "generator": "sim-v2",
        "generator_family": "DGA", "seed": 7, "seed_family": "dga-family-A", "split_assignment": "train",
        "split_group": "dga-family-A", "start": raw["event_time"], "end": raw["event_time"],
        "expected_labels": ["DGA"], "attack_parameters": {"variant": "random_character"},
    }
    (scenario_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    (scenario_dir / "observations.jsonl").write_text(json.dumps(raw) + "\n", encoding="utf-8")
    result = build_training_index(tmp_path)
    assert result["record_count"] == 1
    record = result["records"][0]
    assert record["labels"]["DGA"] == 1
    assert record["labels"]["MALICIOUS"] == 1
    assert record["primary_label"] == "DGA"
    assert result["index_sha256"]
    resolved = resolve_training_index(tmp_path, result)
    assert resolved[0]["observation"]["event_id"] == "obs-1"
    assert resolved[0]["labels"] == ["DGA"]


def test_index_split_validator_rejects_cross_split_scenario():
    records = [
        {"scenario_id": "same", "generator_family": "dga", "seed": 1, "split": "train"},
        {"scenario_id": "same", "generator_family": "dga", "seed": 1, "split": "test"},
    ]
    with pytest.raises(ValueError):
        validate_index_splits(records)
