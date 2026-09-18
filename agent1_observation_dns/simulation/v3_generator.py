"""Bounded, offline V3 packet experiments; no model or external-data access.

``rows, manifest = generate(output, seed=26)`` writes immutable split JSONL,
the full DDoS Cartesian *plan*, and the actually executed balanced subset.
Rows are equally weighted final flow snapshots, not every packet prefix.
High-rate/long-duration configurations deliberately include capture truncation;
configured duration and observed duration are recorded separately.
"""
from __future__ import annotations

from collections import Counter
import hashlib
import ipaddress
import itertools
import json
from pathlib import Path
import random

import dpkt

from agent1_observation_dns.capture.source import CapturedFrame
from agent1_observation_dns.configs import Settings
from agent1_observation_dns.normalization.packet import normalize
from agent1_observation_dns.pipeline import ObservationPipeline


AXES = {
    "rate": ["low", "medium", "high"],
    "source_count": [1, 3, 16, 64],
    "duration": ["burst", "medium", "sustained"],
    "protocol": ["TCP_SYN", "UDP"],
    "packet_sizes": ["fixed", "varied"],
    "source_timing": ["synchronized", "asynchronous"],
    "background": ["quiet", "normal", "flash_crowd", "bulk_transfer"],
}
RATES = {"low": .5, "medium": 10., "high": 1000.}
DURATIONS = {"burst": .01, "medium": 3., "sustained": 90.}
BENIGN_PROFILES = (
    "flash_crowd", "high_rate_download", "high_rate_upload", "backup_burst",
    "many_users", "load_test", "dns_burst", "interactive", "idle_keepalive",
)
SPLITS = (("train", 0), ("train", 1), ("train", 2), ("validation", 0), ("test", 0))


def cartesian_plan():
    return [dict(zip(AXES, values)) for values in itertools.product(*AXES.values())]


def balanced_subset(seed, count=12):
    """Balanced marginal coverage; not a claim of full interaction coverage."""
    if count < max(map(len, AXES.values())):
        raise ValueError("subset must cover every value on every axis")
    rng = random.Random(seed)
    columns = {}
    for name, values in AXES.items():
        column = [values[i % len(values)] for i in range(count)]
        rng.shuffle(column)
        columns[name] = column
    result = [dict((name, column[i]) for name, column in columns.items()) for i in range(count)]
    # Rare duplicates are replaced while preserving marginal coverage.
    if len({json.dumps(c, sort_keys=True) for c in result}) != len(result):
        return balanced_subset(seed + 104729, count)
    return result


def _packet(ns, source, destination, sport, protocol, size, flags, sequence, *, dns=False):
    payload = bytes(size)
    if dns:
        payload = bytes(dpkt.dns.DNS(id=sequence % 65536,
                        qd=[dpkt.dns.DNS.Q(name=f"service-{sequence % 17}.example.test")]))
    dport = 53 if dns else 8443
    if protocol == "UDP":
        transport = dpkt.udp.UDP(sport=sport, dport=dport, data=payload)
        transport.ulen = len(transport)
        proto = 17
    else:
        transport = dpkt.tcp.TCP(sport=sport, dport=dport, flags=flags,
                                 seq=sequence * max(size, 1), data=payload)
        proto = 6
    packet = dpkt.ip.IP(src=ipaddress.ip_address(source).packed,
                        dst=ipaddress.ip_address(destination).packed,
                        ttl=64, p=proto, data=transport)
    packet.len = len(packet)
    raw = bytes(dpkt.ethernet.Ethernet(src=b"\x02" * 6, dst=b"\x04" * 6,
                                      type=0x800, data=packet))
    return CapturedFrame(ns, raw, len(raw))


def _flow(rng, flow_index, count, gap, protocol, *, labels=(), start_s=0,
          source_index=0, destination_index=0, varied=True, profile="interactive",
          tcp_mode="normal", zero_gaps=False):
    """Explicit source identity and unique port keep sidecar labels unambiguous."""
    source = f"192.0.2.{10 + source_index % 200}"
    destination = f"198.51.100.{10 + destination_index % 200}"
    sport = 20000 + flow_index
    if not 0 < sport < 65536:
        raise ValueError("scenario has too many uniquely keyed flows")
    timestamp = start_s
    frames = []
    # PSH diversity is independent of benign traffic rate/count/profile.
    psh_probability = rng.choice((0., .1, .5, 1.))
    close = rng.choice((0, dpkt.tcp.TH_FIN, dpkt.tcp.TH_RST))
    for i in range(count):
        if i:
            timestamp += 0 if zero_gaps else gap * rng.uniform(.5, 1.5)
        if tcp_mode == "syn":
            flags = dpkt.tcp.TH_SYN
        else:
            flags = dpkt.tcp.TH_ACK | (dpkt.tcp.TH_PUSH if rng.random() < psh_probability else 0)
            if i == 0 and count > 2:
                flags = dpkt.tcp.TH_SYN
            if i == count - 1:
                flags |= close
        size = rng.choice((0, 40, 64, 128, 512, 1200)) if varied else 64
        frame = _packet(1_767_225_600_000_000_000 + int(timestamp * 1e9), source, destination,
                        sport, protocol, size, flags, i, dns=profile == "dns_burst")
        frames.append((frame, tuple(labels)))
    return frames


def _observe(events, scenario_id, split, run, *, flow_ttl_s=60):
    pipeline = ObservationPipeline(Settings(sensor_id=scenario_id, flow_ttl_s=flow_ttl_s,
                                           max_window_events=4096))
    labels_by_key, labels_by_flow, snapshots = {}, {}, {}
    for frame, labels in sorted(events, key=lambda item: item[0].timestamp_ns):
        key = normalize(frame).key
        if key in labels_by_key and labels_by_key[key] != labels:
            raise ValueError("conflicting truth on one five-tuple")
        labels_by_key[key] = labels
        emitted = pipeline.process(frame)
        if emitted:
            labels_by_flow[emitted[-1].entity_keys.flow_id] = labels
        snapshots.update((event.entity_keys.flow_id, event) for event in emitted
                         if event.snapshot_kind == "final")
    for flow, reason in pipeline.flows.flush():
        snapshots[flow.flow_id] = pipeline.envelope(flow, final=True, reason=reason)
    rows = []
    for event in snapshots.values():
        rows.append({"observation": event.model_dump(mode="json"),
                     "labels": list(labels_by_flow[event.entity_keys.flow_id]), "verified": True,
                     "split": split, "group_id": f"{split}-run{run}",
                     "scenario_id": scenario_id, "generator_family": "simulation_v3"})
    return rows


def _benign_events(rng, *, number=54):
    events = []
    for i in range(number):
        profile = BENIGN_PROFILES[i % len(BENIGN_PROFILES)]
        count = (1, 2, 3, 6, 16, 48, 128, 256)[i % 8]
        # Broad support fixed in source: never estimated from CICIDS rows.
        gap = 10 ** rng.uniform(-6, 1.6)
        if profile in {"high_rate_download", "high_rate_upload", "backup_burst", "dns_burst"}:
            gap = 10 ** rng.uniform(-6, -1)
        if profile == "idle_keepalive":
            count, gap = rng.choice((2, 3, 6)), rng.uniform(20, 80)
        protocol = "UDP" if profile == "dns_burst" or rng.random() < .30 else "TCP"
        events.extend(_flow(rng, i, count, gap, protocol, start_s=i * .01,
                            source_index=i % 32, destination_index=i % 5, profile=profile,
                            zero_gaps=i % 19 == 0))
    return events


def _ddos_events(config, rng):
    sources = config["source_count"]
    target_count = rng.choice([count for count in (1, 2, 4) if count <= sources])
    rate, duration = RATES[config["rate"]], DURATIONS[config["duration"]]
    intended_per_source = max(2, int(rate * duration) + 1)
    actual_per_source = min(intended_per_source, max(2, 512 // sources))
    events = []
    start_offsets = []
    for i in range(sources):
        start = 1. if config["source_timing"] == "synchronized" else 1. + rng.uniform(0, min(duration, 5))
        start_offsets.append(start)
        # When duration*rate<1, two packets bound the burst rather than extending it.
        gap = min(1 / rate, duration)
        events.extend(_flow(rng, i, actual_per_source, gap,
                            "UDP" if config["protocol"] == "UDP" else "TCP",
                            labels=("DDoS",), start_s=start, source_index=i,
                            destination_index=i % target_count,
                            varied=config["packet_sizes"] == "varied", tcp_mode="syn"))
    attack_frames = len(events)
    # Close hard negatives share target and source-count/rate ranges, with truth
    # attached to their own five-tuples. Quiet still receives a paired benign flow.
    background = config["background"]
    negative_count = min(sources, 8) if background in {"flash_crowd", "bulk_transfer"} else 1
    for i in range(negative_count):
        profile = rng.choice(BENIGN_PROFILES[:7])
        count = min(actual_per_source, 32)
        events.extend(_flow(rng, sources + i, count, min(1 / rate, duration),
                            "UDP" if profile == "dns_burst" else "TCP",
                            start_s=1., source_index=100 + i,
                            destination_index=i % target_count, profile=profile))
    times = [frame.timestamp_ns for frame, labels in events if labels]
    realized = {**config, "target_count": target_count, "configured_rate_per_source_pps": rate,
                "configured_duration_s": duration, "intended_packets_per_source": intended_per_source,
                "two_packet_minimum_overrides_rate": rate * duration < 1,
                "observed_packets_per_source": actual_per_source, "attack_packets": attack_frames,
                "total_packets": len(events), "capture_truncated": actual_per_source < intended_per_source,
                "observed_attack_span_s": (max(times) - min(times)) / 1e9,
                "source_start_offsets_s": start_offsets, "paired_benign_flows": negative_count,
                "background_note": "quiet has only paired negative; other backgrounds are bounded approximations"}
    return events, realized


def generate(output, seed=26):
    """Return ``(rows, manifest)`` and save disjoint simulation-only partitions.

    Never reads a dataset, model artifact, or external labels. Existing output
    directories are refused. The original V2 generator and models are untouched.
    """
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    plan = cartesian_plan()
    (output / "cartesian_plan.json").write_text(json.dumps(plan, indent=2) + "\n")
    rows, realized, packets = [], [], 0
    for split_index, (split, run) in enumerate(SPLITS):
        run_seed = seed + split_index * 100003
        rng = random.Random(run_seed)
        scenario = f"v3-{split}-run{run}-benign-{run_seed}"
        events = _benign_events(rng)
        packets += len(events)
        rows.extend(_observe(events, scenario, split, run,
                             flow_ttl_s=(15, 60, 120)[split_index % 3]))
        for index, config in enumerate(balanced_subset(run_seed)):
            events, config_report = _ddos_events(config, rng)
            packets += len(events)
            scenario = f"v3-{split}-run{run}-ddos{index}-{run_seed}"
            scenario_rows = _observe(events, scenario, split, run,
                                     flow_ttl_s=(15, 60, 120)[index % 3])
            rows.extend(scenario_rows)
            realized.append({**config_report, "scenario_id": scenario, "split": split,
                             "group_id": f"{split}-run{run}", "rows": len(scenario_rows)})
    partitions = {}
    for split in ("train", "validation", "test"):
        path = output / f"{split}.jsonl"
        subset = [row for row in rows if row["split"] == split]
        with path.open("x") as stream:
            for row in subset:
                stream.write(json.dumps(row, separators=(",", ":")) + "\n")
        partitions[split] = {"rows": len(subset), "path": path.name,
                             "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                             "labels": dict(Counter("+".join(r["labels"]) or "BENIGN" for r in subset))}
    manifest = {"generator": "simulation_v3", "seed": seed, "external_data_access": False,
                "sampling_unit": "one final snapshot per observed unidirectional flow segment",
                "cartesian_axes": AXES, "cartesian_plan_size": len(plan),
                "additional_target_sampling": "1/2/4 destinations, bounded by source count; sampled per realized configuration",
                "executed_configurations": len(realized), "full_cartesian_executed": False,
                "sampling": "12 deterministic configurations per run, balanced marginal axis coverage",
                "benign_profiles": BENIGN_PROFILES, "packet_count": packets, "rows": len(rows),
                "partitions": partitions, "realized_configurations": realized,
                "limitations": ["Budgeted capture truncation changes achieved duration; consult realized spans.",
                                "Packet scheduling approximates applications and contains no reverse traffic.",
                                "PSH/ACK/FIN/RST variation approximates visible TCP lifecycles, not a full TCP stack.",
                                "Window features are generated but this does not change model feature paths.",
                                "No scan rows: preserve V2 scan rows and frozen scan control separately."]}
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return rows, manifest
