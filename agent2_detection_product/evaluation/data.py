import hashlib
import json
from pathlib import Path
from ..contracts import observation
from ..dataset.training_index import resolve_training_index


def read_partition(path, *, split, expected_digest):
    content = Path(path).read_bytes()
    if hashlib.sha256(content).hexdigest() != expected_digest:
        raise ValueError("dataset partition digest mismatch")
    rows = [json.loads(line) for line in content.decode("utf-8").splitlines() if line.strip()]
    seen = set()
    for row in rows:
        if row.get("split") != split or not (row.get("group_id") or row.get("split_group")) or not row.get("scenario_id"):
            raise ValueError("partition requires split and scenario/group provenance")
        env = observation(row["observation"])
        key = (env["sensor_id"], env["event_id"])
        if key in seen:
            raise ValueError("duplicate event in dataset")
        seen.add(key)
        labels = row.get("labels")
        if not isinstance(labels, (list, dict)):
            raise ValueError("multi-label ground truth required")
        if isinstance(labels, dict) and any(value not in (0, 1) for value in labels.values()):
            raise ValueError("index labels must be binary")
    return rows


def assert_disjoint(*partitions):
    for i, left in enumerate(partitions):
        for right in partitions[i + 1:]:
            for field in ("scenario_id", "group_id"):
                if {(r.get(field) or r.get("split_group")) for r in left} & {(r.get(field) or r.get("split_group")) for r in right}:
                    raise ValueError(f"leakage across split {field}")
            keys = lambda rows: {(r["observation"]["sensor_id"], r["observation"]["event_id"]) for r in rows}
            if keys(left) & keys(right):
                raise ValueError("event leakage across partitions")


def read_training_index(index_root, index, *, split):
    """Resolve a derived TrainingIndex without mutating manifests/observations."""
    rows = [row for row in resolve_training_index(index_root, index) if row["split"] == split]
    if not rows:
        raise ValueError(f"training index has no {split} records")
    for row in rows:
        observation(row["observation"])
    return rows
