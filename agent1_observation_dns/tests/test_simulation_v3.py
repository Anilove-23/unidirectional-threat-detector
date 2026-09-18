import socket

from agent1_observation_dns.simulation.v3_generator import (
    AXES, _benign_events, _ddos_events, _observe, balanced_subset, cartesian_plan,
)
import random


def test_v3_plan_and_marginal_coverage():
    assert len(cartesian_plan()) == 1152
    selected = balanced_subset(26)
    assert selected == balanced_subset(26)
    assert len(selected) == 12
    for axis, values in AXES.items():
        assert {row[axis] for row in selected} == set(values)


def test_v3_packet_only_truth_and_final_flow_values(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("simulation must not use network sockets")
    monkeypatch.setattr(socket, "socket", forbidden)
    config = balanced_subset(26)[0]
    events, report = _ddos_events(config, random.Random(26))
    assert report["total_packets"] <= 768
    rows = _observe(events, "v3-test-independent", "test", 0)
    assert {tuple(r["labels"]) for r in rows} == {(), ("DDoS",)}
    assert all(r["verified"] and r["group_id"] == "test-run0" for r in rows)
    assert len({r["observation"]["event_id"] for r in rows}) == len(rows)
    assert len({r["observation"]["entity_keys"]["flow_id"] for r in rows}) == len(rows)
    destinations = {r["observation"]["entity_keys"]["destination"] for r in rows if r["labels"]}
    assert len(destinations) == report["target_count"]
    for row in rows:
        observation = row["observation"]
        assert observation["snapshot_kind"] == "final"
        for name in ("packet_count", "duration_s", "pps", "iat_s_mean", "psh_count", "rst_count"):
            value = observation["features"]["flow"][name]
            assert not value["available"] or value["value"] >= 0


def test_v3_benign_diversity_and_split_identity():
    events = _benign_events(random.Random(26), number=16)
    train = _observe(events, "v3-train-seed26", "train", 0)
    test = _observe(events, "v3-test-seed27", "test", 0)
    assert not {r["observation"]["event_id"] for r in train} & {r["observation"]["event_id"] for r in test}
    assert all(not row["labels"] for row in train + test)
    flows = [r["observation"]["features"]["flow"] for r in train]
    assert max(flow["packet_count"]["value"] for flow in flows) >= 128
    assert any(flow["pps"]["available"] and flow["pps"]["value"] > 100 for flow in flows)
    assert any(not flow["psh_count"]["available"] for flow in flows)
    assert any(flow["psh_count"]["available"] and flow["psh_count"]["value"] < flow["packet_count"]["value"] for flow in flows)
