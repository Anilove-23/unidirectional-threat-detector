import hashlib
import json
from pathlib import Path
from ..contracts import observation


def read_partition(path, *, split, expected_digest):
    content = Path(path).read_bytes()
    if hashlib.sha256(content).hexdigest() != expected_digest:
        raise ValueError("dataset partition digest mismatch")
    rows = [json.loads(line) for line in content.decode("utf-8").splitlines() if line.strip()]
    seen = set()
    for row in rows:
        if row.get("split") != split or not row.get("group_id") or not row.get("scenario_id"):
            raise ValueError("partition requires split and scenario/group provenance")
        env = observation(row["observation"])
        key = (env["sensor_id"], env["event_id"])
        if key in seen:
            raise ValueError("duplicate event in dataset")
        seen.add(key)
        if not isinstance(row.get("labels"), list):
            raise ValueError("multi-label ground truth required")
    return rows


def assert_disjoint(*partitions):
    for i, left in enumerate(partitions):
        for right in partitions[i + 1:]:
            for field in ("scenario_id", "group_id"):
                if {r[field] for r in left} & {r[field] for r in right}:
                    raise ValueError(f"leakage across split {field}")
            keys = lambda rows: {(r["observation"]["sensor_id"], r["observation"]["event_id"]) for r in rows}
            if keys(left) & keys(right):
                raise ValueError("event leakage across partitions")
