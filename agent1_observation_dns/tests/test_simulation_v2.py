import hashlib
import json
from dataclasses import replace

import pytest

from agent1_observation_dns.simulation.registry import training_scenario
from agent1_observation_dns.simulation.scheduler import schedule
from agent1_observation_dns.simulation.spec import PhaseSpec, ScenarioSpec
from agent1_observation_dns.simulation.topology import topology
from agent1_observation_dns.simulation.v2_generator import release_scenario
from agent2_detection_product.dataset.build_release import build_release
from agent2_detection_product.dataset.training_index import build_training_index
from agent2_detection_product.dataset.integrity import verify_release


def test_training_spec_has_specialist_length_and_topology():
    c2 = training_scenario("c2", seed=7, variant="jitter_15")
    botnet = training_scenario("botnet", seed=8, variant="centralized")
    assert c2.duration_s >= 3600
    assert c2.topology.name == "enterprise_small"
    assert botnet.topology.bot_hosts >= 3
    assert botnet.topology.name == "botnet_small"


def test_scheduler_is_seed_deterministic_and_mixed():
    spec = training_scenario("c2", seed=9, variant="jitter_15")
    first = schedule(spec)
    second = schedule(spec)
    assert first == second
    assert any(not event.labels for event in first)
    assert any("C2_BEACONING" in event.labels for event in first)
    assert len({event.source for event in first if event.labels}) >= 3


def test_phase_validation_rejects_overlap_or_overrun():
    with pytest.raises(ValueError):
        ScenarioSpec("bad", 10, topology("minimal"), phases=(PhaseSpec("x", 0, 11),))
    with pytest.raises(ValueError):
        ScenarioSpec("bad", 10, topology("minimal"), phases=(PhaseSpec("x", 0, 5), PhaseSpec("y", 4, 9)))


def test_v2_release_has_phase_labels_and_index(tmp_path):
    spec = replace(training_scenario("dga", seed=10, variant="random_character"), duration_s=120,
                   phases=(PhaseSpec("attack", 30, 119, ("DGA",), ("dga_random_character",)),))
    root = tmp_path / "scenario"
    manifest = release_scenario(spec, root)
    assert manifest["simulation_version"] == "2.0.0"
    assert manifest["packet_count"] > 0
    index = build_training_index(tmp_path)
    assert index["record_count"] == manifest["observation_count"]
    assert any(not record["labels"]["MALICIOUS"] for record in index["records"] if record["event_time"] < manifest["phases"][0]["start"])
    assert any(record["phase_id"] == "attack" for record in index["records"] if record["labels"]["DGA"])
    assert any(record["labels"]["DGA"] for record in index["records"] if record["event_time"] >= manifest["phases"][0]["start"])
    # Mixed background remains benign inside an attack phase.
    assert any(not record["labels"]["MALICIOUS"] for record in index["records"]
               if manifest["phases"][0]["start"] <= record["event_time"] <= manifest["phases"][0]["end"])
    observations = [json.loads(line) for line in (root / "observations.jsonl").read_text().splitlines()]
    assert max(event["features"]["flow"]["packet_count"]["value"] for event in observations) > 1
    names = [event["features"]["dns"].get("query_name", {}).get("value", "") for event in observations]
    assert any("service-" in name for name in names)


def test_release_builder_is_immutable_and_records_checksums(tmp_path):
    specs = [replace(training_scenario("dga", seed=1, variant="family_a"), duration_s=60,
                     phases=(PhaseSpec("attack", 10, 59, ("DGA",), ("dga_family_a",)),)),
             replace(training_scenario("c2", seed=2, variant="family_b"), duration_s=60,
                     phases=(PhaseSpec("attack", 10, 59, ("C2_BEACONING",), ("c2_family_b",)),))]
    # Use distinct generator families and groups so the split validator can
    # prove they remain isolated inside the release.
    root = tmp_path / "release"
    release = build_release(specs, root)
    assert release["scenario_count"] == 2
    assert release["training_started"] is False
    assert (root / "checksums.sha256").is_file()
    checked = verify_release(root)
    assert checked["release"]["training_started"] is False
    quality = json.loads((root / "scenario_quality.json").read_text(encoding="utf-8"))
    assert quality[specs[0].scenario_id]["packets"] > 0
    with pytest.raises(FileExistsError):
        build_release(specs, root)
