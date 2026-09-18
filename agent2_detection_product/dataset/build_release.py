"""Build an immutable simulation release; this command never trains models."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

from agent1_observation_dns.simulation.registry import training_scenario
from agent1_observation_dns.simulation.v2_generator import release_scenario
from .training_index import build_training_index, write_training_index, resolve_training_index
from .split_validation import validate_index_splits
from .quality import scenario_quality


def build_release(specs, output_root):
    output = Path(output_root)
    if output.exists():
        raise FileExistsError(output)
    output.mkdir(parents=True)
    scenario_root = output / "scenarios"
    scenario_root.mkdir()
    for spec in specs:
        manifest = release_scenario(spec, scenario_root / spec.scenario_id)
    index = build_training_index(scenario_root)
    validate_index_splits(index["records"])
    write_training_index(index, output / "training_index")
    # Add the derived quality report without changing raw observations.
    resolved_records = resolve_training_index(scenario_root, index)
    quality = {}
    for spec in specs:
        scenario_records = [record for record in resolved_records if record["scenario_id"] == spec.scenario_id]
        scenario_manifest = json.loads((scenario_root / spec.scenario_id / "manifest.json").read_text(encoding="utf-8"))
        quality[spec.scenario_id] = scenario_quality(
            scenario_records,
            packet_count=scenario_manifest.get("packet_count"),
            duration_s=spec.duration_s,
        )
    (output / "scenario_quality.json").write_text(json.dumps(quality, indent=2) + "\n", encoding="utf-8")
    checksums = {}
    for path in sorted(output.rglob("*")):
        if path.is_file() and path.name != "checksums.sha256":
            checksums[path.relative_to(output).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    (output / "checksums.sha256").write_text("\n".join(f"{digest}  {name}" for name, digest in checksums.items()) + "\n", encoding="utf-8")
    splits = {split: sorted({record.get("split_group", record["scenario_id"]) for record in index["records"] if record["split"] == split})
              for split in ("train", "validation", "test")}
    release = {
        "release_id": output.name, "simulation_version": "2.0.0", "feature_version": "2.0.0",
        "observation_schema": "2.0.0", "scenario_count": len(specs),
        "pcap_count": len(list(scenario_root.rglob("capture.pcap"))),
        "observation_count": index["record_count"], "seed_policy": "explicit ScenarioSpec seed",
        "train_groups": splits["train"], "val_groups": splits["validation"], "test_groups": splits["test"],
        "index_sha256": index["index_sha256"], "checksums_sha256": hashlib.sha256((output / "checksums.sha256").read_bytes()).hexdigest(),
        "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "training_started": False,
    }
    (output / "release.json").write_text(json.dumps(release, indent=2) + "\n", encoding="utf-8")
    return release


def main():
    parser = argparse.ArgumentParser(description="Build a deterministic SIH26145 V2 simulation release")
    parser.add_argument("output", type=Path)
    parser.add_argument("--family", action="append", help="scenario family; repeat with --seed")
    parser.add_argument("--seed", action="append", type=int, help="scenario seed; repeat with --family")
    parser.add_argument("--variant", default="default")
    parser.add_argument("--environment", default="environment_A")
    parser.add_argument("--split", choices=("train", "validation", "test"), default="train")
    parser.add_argument(
        "--spec", action="append", metavar="FAMILY:SEED:VARIANT:SPLIT",
        help="add a scenario with its own split; repeat for a mixed train/validation/test release",
    )
    args = parser.parse_args()
    specs = []
    if args.spec:
        if args.family or args.seed:
            parser.error("use --spec or --family/--seed, not both")
        for value in args.spec:
            parts = value.split(":")
            if len(parts) != 4 or parts[3] not in {"train", "validation", "test"}:
                parser.error(f"invalid --spec {value!r}; expected FAMILY:SEED:VARIANT:SPLIT")
            family, seed_text, variant, split = parts
            try:
                seed = int(seed_text)
            except ValueError:
                parser.error(f"invalid seed in --spec {value!r}")
            specs.append(training_scenario(family, seed=seed, variant=variant, environment=args.environment,
                                           split_assignment=split))
    else:
        if not args.family or not args.seed:
            parser.error("provide --spec or at least one --family and --seed")
        if len(args.family) != len(args.seed):
            parser.error("provide one --seed for each --family")
        specs = [training_scenario(family, seed=seed, variant=args.variant, environment=args.environment,
                                   split_assignment=args.split)
                 for family, seed in zip(args.family, args.seed)]
    print(json.dumps(build_release(specs, args.output), indent=2))


if __name__ == "__main__":
    main()
