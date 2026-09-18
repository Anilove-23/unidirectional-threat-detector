from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any


@dataclass(frozen=True)
class PhaseSpec:
    phase_id: str
    start_s: float
    end_s: float
    labels: tuple[str, ...] = ()
    profiles: tuple[str, ...] = ()
    source_roles: tuple[str, ...] = ()
    destination_roles: tuple[str, ...] = ()

    def __post_init__(self):
        if not self.phase_id or self.start_s < 0 or self.end_s <= self.start_s:
            raise ValueError("phase requires a positive interval")
        if any(not label for label in self.labels):
            raise ValueError("phase labels cannot be empty")


@dataclass(frozen=True)
class TopologySpec:
    name: str
    clients: int
    servers: int
    c2_nodes: int = 1
    bot_hosts: int = 0
    dns_servers: int = 1
    services: tuple[str, ...] = ("web", "api", "dns")

    def __post_init__(self):
        if min(self.clients, self.servers, self.c2_nodes, self.dns_servers) < 1 or self.bot_hosts < 0:
            raise ValueError("topology counts must be positive where applicable")
        if self.bot_hosts > self.clients:
            raise ValueError("bot hosts cannot exceed clients")


@dataclass(frozen=True)
class ScenarioSpec:
    scenario_id: str
    duration_s: float
    topology: TopologySpec
    benign_profiles: tuple[str, ...] = ("dns_normal", "machine_periodic")
    attack_profiles: tuple[str, ...] = ()
    seed: int = 0
    split_group: str = "default"
    split_assignment: str = "train"
    environment: str = "environment_A"
    tier: str = "training"
    start: datetime = datetime(2026, 1, 1, tzinfo=timezone.utc)
    phases: tuple[PhaseSpec, ...] = ()
    holdout_tags: tuple[str, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.scenario_id or self.duration_s <= 0 or self.seed < 0:
            raise ValueError("scenario requires a positive duration and non-negative seed")
        if self.tier not in {"smoke", "training", "benchmark"}:
            raise ValueError("tier must be smoke, training, or benchmark")
        if self.split_assignment not in {"train", "validation", "test"}:
            raise ValueError("split_assignment must be train, validation, or test")
        if self.start.tzinfo is None:
            raise ValueError("scenario start must be timezone-aware")
        previous = 0.0
        for phase in sorted(self.phases, key=lambda item: item.start_s):
            if phase.end_s > self.duration_s or phase.start_s < previous:
                raise ValueError("phases must be ordered and within scenario duration")
            previous = phase.end_s

    @property
    def end(self):
        return self.start + timedelta(seconds=self.duration_s)

    def phase_at(self, offset_s):
        return next((phase for phase in self.phases if phase.start_s <= offset_s <= phase.end_s), None)

    def manifest_fields(self):
        return {
            "simulation_version": "2.0.0",
            "scenario_id": self.scenario_id,
            "topology": self.topology.name,
            "environment": self.environment,
            "tier": self.tier,
            "duration_s": self.duration_s,
            "seed": self.seed,
            "split_group": self.split_group,
            "split_assignment": self.split_assignment,
            "holdout_tags": list(self.holdout_tags),
            "benign_profiles": list(self.benign_profiles),
            "attack_profiles": list(self.attack_profiles),
            "phases": [
                {"phase_id": phase.phase_id, "start": (self.start + timedelta(seconds=phase.start_s)).isoformat().replace("+00:00", "Z"),
                 "end": (self.start + timedelta(seconds=phase.end_s)).isoformat().replace("+00:00", "Z"),
                 "labels": list(phase.labels), "profiles": list(phase.profiles),
                 "source_roles": list(phase.source_roles), "destination_roles": list(phase.destination_roles)}
                for phase in self.phases
            ],
            **self.metadata,
        }
