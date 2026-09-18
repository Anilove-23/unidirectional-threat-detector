from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

from ..adapters import adapt_observation
from ..contracts import ContractError
from .index_schema import TRAINING_INDEX_SCHEMA
from .split_validation import validate_index_splits


LABELS = (
    "MALICIOUS", "DDoS", "PORT_SCAN", "DGA", "DNS_TUNNEL", "C2_BEACONING",
    "BOTNET_HOST", "BOTNET_COORDINATION", "ENCRYPTED_MALWARE", "DATA_EXFILTRATION",
)
FAMILY_MAP = {
    "BENIGN": (), "DDOS": ("DDoS",), "PORT_SCAN": ("PORT_SCAN",), "DGA": ("DGA",),
    "DNS_TUNNEL": ("DNS_TUNNEL",), "C2": ("C2_BEACONING",), "BOTNET": ("BOTNET_HOST", "BOTNET_COORDINATION"),
    "ENCRYPTED_MALWARE": ("ENCRYPTED_MALWARE",), "EXFILTRATION": ("DATA_EXFILTRATION",),
}


def _parse_time(value):
    if not isinstance(value, str):
        raise ValueError("event time must be ISO text")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("event time must be timezone-aware")
    return parsed.astimezone(timezone.utc)


def _matching_phases(manifest, event_time):
    phases = manifest.get("phases") or []
    matched = []
    for phase in phases:
        start, end = phase.get("start"), phase.get("end")
        if start and event_time < _parse_time(start):
            continue
        if end and event_time > _parse_time(end):
            continue
        matched.append(phase)
    return matched


def _labels_for(manifest, event_time):
    phases = manifest.get("phases") or []
    matched_phases = _matching_phases(manifest, event_time)
    matched = []
    for phase in matched_phases:
        matched.extend(phase.get("labels") or phase.get("expected_labels") or [])
    # A phased scenario deliberately has unlabeled background outside attack
    # intervals.  Only legacy manifests without phases use scenario-wide
    # expected_labels as a fallback.
    if not matched and not phases:
        start = _parse_time(manifest["start"])
        end = _parse_time(manifest["end"])
        if start <= event_time <= end:
            matched.extend(manifest.get("expected_labels") or [manifest.get("family", "BENIGN")])
    normalized = []
    for label in matched:
        normalized.extend(FAMILY_MAP.get(str(label).upper(), (str(label),)))
    # Preserve explicit multi-label phase labels and deduplicate deterministically.
    normalized = tuple(sorted(set(normalized)))
    return normalized


def _record(observation, manifest, observation_file, manifest_file, *, observation_line, phase_id="scenario", event_labels=None):
    event_time = _parse_time(observation["event_time"])
    labels = _labels_for(manifest, event_time) if event_labels is None else tuple(event_labels)
    matched_phases = _matching_phases(manifest, event_time)
    phase = matched_phases[0] if matched_phases else None
    if phase is not None:
        phase_id = str(phase.get("phase_id") or phase_id)
    flags = {label: int(label in labels) for label in LABELS}
    flags["MALICIOUS"] = int(bool(labels))
    primary = labels[0] if labels else "BENIGN"
    if "primary_label" in manifest:
        primary = manifest["primary_label"]
    variant = str((manifest.get("attack_parameters") or {}).get("variant", manifest.get("profile", "default")))
    return {
        # Agent 1 event IDs are stable within a release stream. Prefixing the
        # immutable scenario ID makes the derived index globally unique when
        # multiple scenarios reuse the same sensor/topology seed layout.
        "observation_id": f"{manifest['scenario_id']}:{observation['event_id']}",
        "source_observation_id": observation["event_id"], "scenario_id": manifest["scenario_id"],
        "phase_id": phase_id, "sensor_id": observation["sensor_id"], "event_time": observation["event_time"],
        "primary_label": primary, "labels": flags, "split": manifest["split_assignment"],
        "generator_family": manifest.get("generator_family", manifest.get("family", "UNKNOWN")),
        "variant": variant, "seed": manifest["seed"], "seed_family": manifest.get("seed_family", f"{manifest.get('generator', 'unknown')}:{manifest['seed']}"),
        "split_group": manifest.get("split_group", manifest["scenario_id"]),
        "group_id": manifest.get("split_group", manifest["scenario_id"]),
        "observation_file": observation_file, "observation_line": observation_line, "manifest_file": manifest_file,
        "feature_schema_version": observation.get("feature_schema_version", observation.get("schema_version")),
        "simulation_version": manifest.get("simulation_version", manifest.get("generator", "unknown")),
        "phase_start": (phase.get("start") if phase is not None else manifest.get("start")),
        "phase_end": (phase.get("end") if phase is not None else manifest.get("end")),
        "verified": bool(manifest.get("ground_truth_verified", True)),
    }


def build_training_index(release_root, *, output_root=None):
    """Join immutable scenario manifests to immutable observations.

    The result is derived data: raw observations and manifests remain the
    authoritative products and are never edited or relabelled in place.
    """
    root = Path(release_root).resolve()
    if not root.is_dir():
        raise FileNotFoundError(root)
    records, source_digests = [], {}
    manifests = sorted(root.rglob("manifest.json"))
    if not manifests:
        raise ValueError("release contains no scenario manifests")
    for manifest_path in manifests:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        for required in ("scenario_id", "start", "end", "seed", "split_assignment"):
            if required not in manifest:
                raise ContractError(f"manifest missing {required}")
        observation_path = manifest_path.parent / "observations.jsonl"
        if not observation_path.is_file():
            raise FileNotFoundError(observation_path)
        manifest_ref = manifest_path.relative_to(root).as_posix()
        observation_ref = observation_path.relative_to(root).as_posix()
        source_digests[manifest_ref] = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
        source_digests[observation_ref] = hashlib.sha256(observation_path.read_bytes()).hexdigest()
        truth = None
        if manifest.get("ground_truth_file"):
            truth_path = (manifest_path.parent / manifest["ground_truth_file"]).resolve()
            if not truth_path.is_relative_to(manifest_path.parent.resolve()):
                raise ValueError("ground truth path escapes scenario")
            truth_digest = hashlib.sha256(truth_path.read_bytes()).hexdigest()
            if truth_digest != manifest.get("ground_truth_sha256"):
                raise ValueError("ground truth digest mismatch")
            truth = json.loads(truth_path.read_text(encoding="utf-8"))
            source_digests[truth_path.relative_to(root).as_posix()] = truth_digest
        with observation_path.open(encoding="utf-8") as stream:
            for line_number, line in enumerate(stream, 1):
                if not line.strip():
                    continue
                try:
                    raw = json.loads(line)
                    adapted = adapt_observation(raw)
                except (json.JSONDecodeError, ContractError, ValueError) as exc:
                    raise ValueError(f"invalid observation {observation_ref}:{line_number}: {exc}") from exc
                records.append(_record(adapted.raw, manifest, observation_ref, manifest_ref, observation_line=line_number,
                                       event_labels=truth[raw["event_id"]] if truth is not None else None))
    records.sort(key=lambda row: (row["event_time"], row["scenario_id"], row["observation_id"]))
    ids = [row["observation_id"] for row in records]
    if len(ids) != len(set(ids)):
        raise ValueError("observation IDs must be globally unique")
    validate_index_splits(records)
    result = {
        "schema_version": "2.0.0", "records": records, "source_digests": source_digests,
        "record_count": len(records), "index_sha256": hashlib.sha256(json.dumps(records, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
    }
    if output_root is not None:
        write_training_index(result, output_root)
    return result


def write_training_index(index, output_root):
    output = Path(output_root)
    output.mkdir(parents=True, exist_ok=False)
    records_path = output / "training_index.jsonl"
    with records_path.open("x", encoding="utf-8") as stream:
        for record in index["records"]:
            stream.write(json.dumps(record, sort_keys=True) + "\n")
    (output / "index_schema.json").write_text(json.dumps(TRAINING_INDEX_SCHEMA, indent=2) + "\n", encoding="utf-8")
    metadata = {key: value for key, value in index.items() if key != "records"}
    metadata["index_file"] = records_path.name
    metadata["index_file_sha256"] = hashlib.sha256(records_path.read_bytes()).hexdigest()
    (output / "release_index.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    return output


def resolve_training_index(index_root, index):
    """Materialize index references for a loader while preserving raw products."""
    root = Path(index_root).resolve()
    resolved = []
    cache = {}
    for record in index["records"]:
        path = (root / record["observation_file"]).resolve()
        if not path.is_relative_to(root) or not path.is_file():
            raise FileNotFoundError(path)
        if path not in cache:
            cache[path] = path.read_text(encoding="utf-8").splitlines()
        lines = cache[path]
        line_number = record["observation_line"]
        if line_number > len(lines):
            raise ValueError(f"observation line outside file: {path}:{line_number}")
        raw = json.loads(lines[line_number - 1])
        row = dict(record)
        row["observation"] = raw
        row["labels"] = [label for label, enabled in record["labels"].items() if enabled and label not in {"MALICIOUS"}]
        row["group_id"] = record.get("group_id", record.get("split_group", record["scenario_id"]))
        resolved.append(row)
    return resolved
