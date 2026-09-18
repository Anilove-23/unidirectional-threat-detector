from __future__ import annotations

from dataclasses import dataclass, replace
import random

from .spec import ScenarioSpec


@dataclass(frozen=True)
class TrafficEvent:
    timestamp_s: float
    source: str
    destination: str
    protocol: str
    destination_port: int
    profile: str
    labels: tuple[str, ...] = ()
    payload_size: int = 64
    session_id: str = ""


def host_addresses(spec: ScenarioSpec):
    clients = tuple(f"192.0.2.{10 + i}" for i in range(spec.topology.clients))
    servers = tuple(f"198.51.100.{10 + i}" for i in range(spec.topology.servers))
    c2 = tuple(f"203.0.113.{10 + i}" for i in range(spec.topology.c2_nodes))
    dns = tuple(f"198.51.100.{240 + i}" for i in range(spec.topology.dns_servers))
    return clients, servers, c2, dns


def _periodic(rng, duration, period, jitter, start=0.0):
    current = start
    while current < duration:
        yield max(0.0, current + rng.uniform(-jitter, jitter) if jitter else current)
        current += period


def schedule(spec: ScenarioSpec):
    """Create deterministic mixed background/attack intents, without sockets."""
    rng = random.Random(spec.seed)
    clients, servers, c2_nodes, dns = host_addresses(spec)
    events = []
    # Background traffic remains present during attack phases.
    for index, client in enumerate(clients):
        if "dns_normal" in spec.benign_profiles:
            for timestamp in _periodic(rng, spec.duration_s, 30 + (index % 3) * 7, 2.0, start=index):
                events.append(TrafficEvent(timestamp, client, dns[0], "DNS", 53, "dns_normal", payload_size=80, session_id=f"dns-{index}"))
        if "machine_periodic" in spec.benign_profiles:
            for timestamp in _periodic(rng, spec.duration_s, 60 + index * 3, 3.0, start=5 + index):
                events.append(TrafficEvent(timestamp, client, servers[index % len(servers)], "TCP", 443, "machine_periodic", payload_size=120, session_id=f"health-{index}"))
        if "human_interactive" in spec.benign_profiles:
            timestamp = 12 + index * 9
            while timestamp < spec.duration_s:
                events.append(TrafficEvent(timestamp, client, servers[index % len(servers)], "TCP", 443, "human_interactive", payload_size=rng.randint(80, 1200), session_id=f"web-{index}"))
                timestamp += rng.uniform(18, 95)
        if "bulk_transfer" in spec.benign_profiles and index % 2 == 0:
            for timestamp in _periodic(rng, spec.duration_s, 300, 20, start=45 + index):
                events.append(TrafficEvent(timestamp, client, servers[(index + 1) % len(servers)], "TCP", 443, "bulk_transfer", payload_size=1200, session_id=f"bulk-{index}"))
    for phase in spec.phases:
        profile = phase.profiles[0] if phase.profiles else (spec.attack_profiles[0] if spec.attack_profiles else "")
        labels = phase.labels
        family = profile.split("_", 1)[0]
        attack_start, attack_end = phase.start_s, phase.end_s
        if family == "c2":
            period = 10.0 if "10s" in profile else 60.0 if "60s" in profile else 30.0
            jitter = period * (0.30 if "30" in profile else 0.15 if "15" in profile else 0.05)
            for index, client in enumerate(clients[:max(1, spec.topology.bot_hosts or len(clients))]):
                for timestamp in _periodic(rng, attack_end, period, jitter, attack_start + index * 1.5):
                    events.append(TrafficEvent(timestamp, client, c2_nodes[index % len(c2_nodes)], "TCP", 443, profile, labels, 160, f"c2-{index}"))
        elif family == "botnet":
            bots = clients[:spec.topology.bot_hosts]
            for index, bot in enumerate(bots):
                for timestamp in _periodic(rng, attack_end, 45, 8, attack_start + index * 2):
                    destination = c2_nodes[index % len(c2_nodes)] if index % 2 else bots[(index + 1) % len(bots)]
                    events.append(TrafficEvent(timestamp, bot, destination, "TCP", 443, profile, labels, 180, f"bot-{index}"))
        elif family in {"dga", "dns"} or "tunnel" in profile:
            for index, client in enumerate(clients[:3]):
                for timestamp in _periodic(rng, attack_end, 5 if "low" not in profile else 30, 1.0, attack_start + index):
                    events.append(TrafficEvent(timestamp, client, dns[0], "DNS", 53, profile, labels, 140, f"dns-attack-{index}"))
        elif family in {"ddos", "load"}:
            target = servers[0]
            for client in clients:
                for timestamp in _periodic(rng, attack_end, .1, .03, attack_start):
                    events.append(TrafficEvent(timestamp, client, target, "UDP", 443, profile, labels, 900, f"ddos-{client}"))
        elif family in {"port", "slow"} or "scan" in profile:
            for index, client in enumerate(clients[:3]):
                for timestamp in _periodic(rng, attack_end, 2 if "slow" not in profile else 20, .1, attack_start + index):
                    destination = servers[int(timestamp) % len(servers)]
                    events.append(TrafficEvent(timestamp, client, destination, "TCP", 1000 + int(timestamp) % 1000, profile, labels, 64, f"scan-{index}"))
        elif family in {"encrypted", "tls"}:
            for index, client in enumerate(clients[:4]):
                for timestamp in _periodic(rng, attack_end, 25, 5, attack_start + index):
                    events.append(TrafficEvent(timestamp, client, servers[index % len(servers)], "TLS", 443, profile, labels, rng.randint(80, 600), f"tls-{index}"))
        elif family in {"exfiltration", "low"} or "exfil" in profile:
            for index, client in enumerate(clients[:2]):
                for timestamp in _periodic(rng, attack_end, 3 if "low" not in profile else 45, .5, attack_start + index):
                    events.append(TrafficEvent(timestamp, client, c2_nodes[0], "TCP", 443, profile, labels, 1200 if "low" not in profile else 240, f"exfil-{index}"))
    # Seed-specific sessions also keep generated domain corpora disjoint across
    # scenario partitions without exposing seed/provenance as numeric features.
    return [replace(event, session_id=f"{event.session_id}-{spec.seed}") for event in
            sorted(events, key=lambda event: (event.timestamp_s, event.source, event.destination, event.profile))]
