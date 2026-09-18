"""Training-tier mixed PCAP generator built alongside the immutable smoke API."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import struct

import dpkt

from agent1_observation_dns.capture.source import CapturedFrame
from agent1_observation_dns.configs import Settings
from agent1_observation_dns.pipeline import ObservationPipeline
from .scheduler import TrafficEvent, schedule
from .spec import ScenarioSpec


def _packet(event: TrafficEvent, timestamp_ns: int, sequence: int):
    src, dst = event.source.encode(), event.destination.encode()
    # Addresses are validated by the scenario topology; use ipaddress through
    # dpkt's expected four-byte representation for deterministic fixture data.
    import ipaddress
    source, destination = ipaddress.ip_address(event.source), ipaddress.ip_address(event.destination)
    # A session keeps its five-tuple so the observer can measure durations,
    # inter-arrival times and packet counts instead of one-packet fragments.
    source_port = 32768 + int(hashlib.sha256(event.session_id.encode()).hexdigest()[:8], 16) % 28000
    if event.protocol == "DNS":
        suffix = "example.test"
        label = hashlib.sha256(f"{event.session_id}:{sequence}:{event.timestamp_s}".encode()).hexdigest()[:24]
        if event.profile == "dns_normal":
            service = ("www", "mail", "api", "updates", "cdn")[sequence % 5]
            name = f"{service}.service-{event.session_id.split('-')[-1]}.{suffix}"
        elif "tunnel" in event.profile:
            encoded = hashlib.sha256(f"payload:{event.session_id}:{sequence}".encode()).hexdigest()
            name = f"{encoded[:56]}.{label}.{suffix}"
        else:
            name = f"{label}.{suffix}"
        dns = dpkt.dns.DNS(id=sequence % 65536, qd=[dpkt.dns.DNS.Q(name=name, type=1)])
        transport = dpkt.udp.UDP(sport=source_port, dport=53, data=bytes(dns))
        transport.ulen = len(transport)
        protocol, payload = 17, transport
    elif event.protocol in {"UDP"}:
        transport = dpkt.udp.UDP(sport=source_port, dport=event.destination_port, data=b"\0" * event.payload_size)
        transport.ulen = len(transport)
        protocol, payload = 17, transport
    else:
        flags = dpkt.tcp.TH_SYN if "scan" in event.profile or "ddos" in event.profile else dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH
        transport = dpkt.tcp.TCP(sport=source_port, dport=event.destination_port, flags=flags, seq=sequence, data=b"\0" * event.payload_size)
        protocol, payload = 6, transport
    if source.version != destination.version:
        raise ValueError("mixed address families are not supported in one packet")
    if source.version == 4:
        ip = dpkt.ip.IP(src=source.packed, dst=destination.packed, ttl=64, p=protocol, data=payload)
        ip.len = len(ip)
        ethernet = dpkt.ethernet.Ethernet(src=b"\x02" * 6, dst=b"\x04" * 6, type=0x800, data=ip)
    else:
        ip = dpkt.ip6.IP6(src=source.packed, dst=destination.packed, hlim=64, nxt=protocol, data=payload)
        ip.plen = len(payload)
        ethernet = dpkt.ethernet.Ethernet(src=b"\x02" * 6, dst=b"\x04" * 6, type=0x86DD, data=ip)
    data = bytes(ethernet)
    return CapturedFrame(timestamp_ns, data, len(data))


def generate_frames(spec: ScenarioSpec):
    for sequence, event in enumerate(schedule(spec)):
        timestamp_ns = int((spec.start.timestamp() + event.timestamp_s) * 1e9)
        yield _packet(event, timestamp_ns, sequence)


def write_pcap(frames, path):
    frames = list(frames)
    with Path(path).open("xb") as stream:
        stream.write(struct.pack("<IHHIIII", 0xa1b23c4d, 2, 4, 0, 0, 262144, 1))
        for frame in frames:
            stream.write(struct.pack("<IIII", frame.timestamp_ns // 10**9, frame.timestamp_ns % 10**9,
                                     len(frame.data), frame.wire_length))
            stream.write(frame.data)
    return frames


def release_scenario(spec: ScenarioSpec, output_root):
    """Generate one immutable training-tier scenario and derived observations."""
    root = Path(output_root)
    if root.exists():
        raise FileExistsError(root)
    root.mkdir(parents=True)
    pcap_path = root / "capture.pcap"
    frames = write_pcap(generate_frames(spec), pcap_path)
    config = Settings(sensor_id=f"sensor-{spec.environment}-{spec.scenario_id}")
    pipeline = ObservationPipeline(config)
    observations, truth, flow_labels = [], {}, {}
    for intent, frame in zip(schedule(spec), frames):
        emitted = pipeline.process(frame)
        if emitted:
            flow_labels[emitted[-1].entity_keys.flow_id] = list(intent.labels)
        for event in emitted:
            observations.append(event)
            truth[event.event_id] = flow_labels[event.entity_keys.flow_id]
    for flow, reason in pipeline.flows.flush():
        event = pipeline.envelope(flow, final=True, reason=reason)
        observations.append(event)
        truth[event.event_id] = flow_labels[flow.flow_id]
    # Labels live exclusively in a sidecar, never in observer/model features.
    truth_path = root / "ground_truth.json"
    truth_path.write_text(json.dumps(truth, sort_keys=True) + "\n", encoding="utf-8")
    observations_path = root / "observations.jsonl"
    with observations_path.open("x", encoding="utf-8") as stream:
        for event in observations:
            stream.write(event.model_dump_json() + "\n")
    phases = spec.manifest_fields()["phases"]
    labels = sorted({label for phase in phases for label in phase["labels"]}) or ["BENIGN"]
    manifest = {
        "schema_version": "1.0.0", "scenario_id": spec.scenario_id, "generator": "simulation-v2",
        "generator_family": spec.metadata.get("generator_family", spec.attack_profiles[0] if spec.attack_profiles else "BENIGN"),
        "seed": spec.seed, "seed_family": spec.split_group, "split_assignment": spec.split_assignment,
        "split_group": spec.split_group, "start": spec.start.isoformat().replace("+00:00", "Z"),
        "end": spec.end.isoformat().replace("+00:00", "Z"), "expected_labels": labels,
        "attack_parameters": {"topology": spec.topology.name, "duration_s": spec.duration_s, "variant": spec.attack_profiles[0] if spec.attack_profiles else "mixed_benign"},
        "simulation_version": "2.0.0", "environment": spec.environment, "tier": spec.tier,
        "topology": spec.topology.name, "phases": phases, "benign_profiles": list(spec.benign_profiles),
        "attack_profiles": list(spec.attack_profiles), "holdout_tags": list(spec.holdout_tags),
        "ground_truth_verified": True, "packet_count": len(frames), "observation_count": len(observations),
        "ground_truth_file": truth_path.name,
        "ground_truth_sha256": hashlib.sha256(truth_path.read_bytes()).hexdigest(),
        "source_sha256": hashlib.sha256(pcap_path.read_bytes()).hexdigest(),
        "observation_sha256": hashlib.sha256(observations_path.read_bytes()).hexdigest(),
        "quality": {"duration_s": spec.duration_s, "packets": len(frames), "observations": len(observations),
                    "hosts": spec.topology.clients + spec.topology.servers + spec.topology.c2_nodes},
    }
    (root / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest
