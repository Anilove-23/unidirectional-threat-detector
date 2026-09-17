from collections import defaultdict


def validate_index_splits(records):
    """Reject scenario, split-group, seed-family, or held-out leakage."""
    seen = defaultdict(set)
    for record in records:
        split = record["split"]
        keys = {
            "scenario_id": record["scenario_id"],
            "generator_family": record["generator_family"],
            "seed_family": record.get("seed_family", f"{record['generator_family']}:{record['seed']}"),
        }
        for name, value in keys.items():
            seen[(name, value)].add(split)
            if len(seen[(name, value)]) > 1:
                raise ValueError(f"{name} crosses train/validation/test partitions: {value}")
    if not records:
        raise ValueError("training index is empty")
    return True


def assert_disjoint_groups(records):
    groups = defaultdict(set)
    for record in records:
        group = record.get("split_group") or record["scenario_id"]
        groups[group].add(record["split"])
    leaked = [group for group, splits in groups.items() if len(splits) > 1]
    if leaked:
        raise ValueError(f"split groups cross partitions: {leaked[:5]}")
