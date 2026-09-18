"""Generate packet scenarios, train candidate models, and test frozen models.

Run from the repository root. CICIDS is an external test set only; no rows from
it enter fitting, calibration, threshold selection, or simulation generation.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import random
import re

import joblib
import numpy as np
import torch

from agent1_observation_dns.models.training import train_neural, train_tabular
from agent1_observation_dns.simulation.registry import training_scenario
from agent1_observation_dns.simulation.spec import PhaseSpec, TopologySpec
from agent2_detection_product.dataset.build_release import build_release
from agent2_detection_product.dataset.training_index import build_training_index, resolve_training_index
from agent2_detection_product.evaluation.train import LABELS, train
from agent2_detection_product.evaluation.metrics import binary_metrics


# These features can be derived from the observed forward packets alone. Packet
# lengths are deliberately omitted: Agent 1 counts wire bytes whereas the CSV
# exporter reports a different length layer. No reverse or combined-flow fields.
FEATURE_PATHS = ["flow.packet_count", "flow.duration_s", "flow.pps", "flow.iat_s_mean",
                 "flow.iat_s_min", "flow.iat_s_max", "flow.psh_count", "flow.urg_count", "flow.rst_count"]
FAMILIES = ("benign_mixed", "ddos", "port_scan", "exfiltration", "dga", "dns_tunnel")


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, allow_nan=False) + "\n", encoding="utf-8")


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def specifications(duration):
    specs = []
    for split, runs, offset in (("train", 3, 1000), ("validation", 1, 2000), ("test", 1, 3000)):
        for run in range(runs):
            for family_index, family in enumerate(FAMILIES):
                seed = offset + run * 100 + family_index
                spec = training_scenario(family, seed=seed, variant=f"{split}_run{run}", split_assignment=split)
                phases = tuple(PhaseSpec("attack", duration / 4, duration - 1, phase.labels, phase.profiles)
                               for phase in spec.phases)
                specs.append(replace(spec, duration_s=duration, phases=phases,
                                     topology=TopologySpec("training_compact", 3, 2),
                                     metadata={**spec.metadata, "training_run": run,
                                               "limitation": "compact synthetic scenario; not a real-world benchmark"}))
    return specs


def bounded_rows(rows, limit, seed=26):
    """Uniform reservoir per scenario/class, preserving independent splits."""
    rng = random.Random(seed)
    buckets, counts = defaultdict(list), Counter()
    for row in rows:
        key = (row["scenario_id"], tuple(row["labels"]))
        counts[key] += 1
        bucket = buckets[key]
        if len(bucket) < limit:
            bucket.append(row)
        else:
            index = rng.randrange(counts[key])
            if index < limit:
                bucket[index] = row
    return [row for key in sorted(buckets) for row in buckets[key]]


def specialist_rows(rows, label):
    result, seen = [], set()
    for row in rows:
        env = row["observation"]
        dns = env["features"].get("dns", {})
        domain = dns.get("query_name", {}).get("value")
        if not domain or (row["scenario_id"], domain) in seen:
            continue
        seen.add((row["scenario_id"], domain))
        result.append({"domain": domain, "label": int(label in row["labels"]),
                       "split_assignment": row["split"], "scenario_id": row["scenario_id"],
                       "split_group": row["group_id"], "family": row["generator_family"],
                       "tool": "simulation-v2", "event_time": env["event_time"], "context": dns,
                       "sequence": dns.get("sequence", {}).get("value", [])})
    random.Random(26).shuffle(result)
    return result


def run(args):
    torch.set_num_threads(args.threads)
    output = args.output.resolve()
    semver = r"\d+\.\d+\.\d+(?:-[\w.-]+)?"
    version = args.version or (output.name if re.fullmatch(semver, output.name) else
                               "2.0.0-" + re.sub(r"[^\w.-]", "-", output.name))
    if not re.fullmatch(semver, version):
        raise ValueError("version must be a semantic version, for example 2.0.0-simulation")
    if output.exists():
        raise FileExistsError(f"Choose a new output release: {output}")
    output.mkdir(parents=True)
    write_json(output / "run_config.json", {"version": version, "seed": 26, "epochs": args.epochs,
               "trees": args.trees, "duration_s": args.duration, "max_rows_per_scenario_class": args.max_rows,
               "threads": args.threads, "cicids": str(args.cicids.resolve()),
               "split_policy": "scenario, run, seed and domain disjoint; same generator algorithms across splits",
               "cicids_usage": "external test only", "numeric_feature_paths": FEATURE_PATHS})
    print("Generating 30 independent packet scenarios...", flush=True)
    simulation = build_release(specifications(args.duration), output / "simulation")
    index = build_training_index(output / "simulation/scenarios")
    rows = resolve_training_index(output / "simulation/scenarios", index)
    # Each OOF group contains all core families from one independent run.
    for row in rows:
        row["group_id"] = row["generator_family"].split("_run")[1]
        row["group_id"] = f"{row['split']}-run{row['group_id']}"
    print(f"Generated {len(rows)} observations; training five Agent 1 DNS branches...", flush=True)
    dns_reports, model_paths = {}, {}
    for label, architectures in (("DGA", ("dga_context_xgb", "dga_char_attention")),
                                 ("DNS_TUNNEL", ("dns_tunnel_fast_gbdt", "dns_tunnel_bytecnn", "dns_tunnel_sequence"))):
        corpus = specialist_rows(rows, label)
        corpus_path = output / "agent1" / f"{label.lower()}_rows.jsonl"
        corpus_path.parent.mkdir(parents=True, exist_ok=True)
        with corpus_path.open("x", encoding="utf-8") as stream:
            for row in corpus:
                stream.write(json.dumps(row) + "\n")
        for architecture in architectures:
            print(f"Training {architecture} on {len(corpus)} partitioned DNS rows", flush=True)
            path = output / "agent1" / (architecture + (".json" if architecture.endswith(("xgb", "gbdt")) else ".pt"))
            options = {"architecture": architecture, "model_version": version, "seed": 26}
            dns_reports[architecture] = (train_tabular(corpus, path, estimators=args.trees, **options)
                                        if path.suffix == ".json" else
                                        train_neural(corpus, path, epochs=args.epochs, **options))
            # Relative to the repository root: portable to the Windows launchers.
            model_paths[architecture] = path.relative_to(Path.cwd()).as_posix() if path.is_relative_to(Path.cwd()) else str(path)
    write_json(output / "agent1/config.json", {"model_paths": model_paths})
    write_json(output / "agent1/training_report.json", dns_reports)
    core_rows = bounded_rows([row for row in rows if not set(row["labels"]) - set(LABELS)], args.max_rows)
    partitions = {split: [r for r in core_rows if r["split"] == split] for split in ("train", "validation", "test")}
    consumer_index = {"numeric_feature_paths": FEATURE_PATHS, "partitions": {}}
    for split, subset in partitions.items():
        path = output / "agent2_dataset" / f"{split}.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("x", encoding="utf-8") as stream:
            for row in subset:
                stream.write(json.dumps(row) + "\n")
        consumer_index["partitions"][split] = {"path": path.name, "sha256": sha256(path), "rows": len(subset)}
    write_json(output / "agent2_dataset/index.json", consumer_index)
    print(f"Training Agent 2 on {len(partitions['train'])} rows with 3 group-held-out folds...", flush=True)
    bundle, policy, report = train(partitions["train"], partitions["validation"], FEATURE_PATHS,
                                   version=version, epochs=args.epochs, trees=args.trees, folds=3)
    agent2 = output / "agent2"
    agent2.mkdir()
    joblib.dump(bundle, agent2 / "bundle.joblib")
    write_json(agent2 / "policy.json", policy)
    write_json(agent2 / "training_report.json", report)
    write_json(agent2 / "manifest.json", {"schema_version": "2.0.0", "version": version,
               "status": "candidate", "bundle": "bundle.joblib", "policy": "policy.json",
               "dataset_index_sha256": sha256(output / "agent2_dataset/index.json"),
               "artifacts": {name: sha256(agent2 / name) for name in ("bundle.joblib", "policy.json", "training_report.json")}})
    from agent2_detection_product.orchestration.registry import verify_manifest
    verify_manifest(agent2 / "manifest.json")
    test_rows = partitions["test"]
    probabilities = bundle.predict_probabilities([r["observation"] for r in test_rows])
    synthetic_metrics = {label: binary_metrics([int(label in r["labels"]) for r in test_rows], probabilities[:, i], policy["thresholds"][label])
                         for i, label in enumerate(LABELS)}
    write_json(output / "synthetic_test_metrics.json", {"samples": len(test_rows), "per_label": synthetic_metrics,
               "scope": "candidate score quality on held-out simulator scenarios; not production decisions",
               "class_counts": dict(Counter(label for r in test_rows for label in (r["labels"] or ["BENIGN"])) )})
    print("Testing frozen Agent 2 candidate on every CICIDS CSV row...", flush=True)
    from agent2_detection_product.evaluation.cicids import evaluate
    external = evaluate(bundle, policy, args.cicids, output / "cicids", batch_size=args.batch_size)
    summary = {"status": "candidate", "simulation": simulation, "agent1": dns_reports,
               "agent2_synthetic": synthetic_metrics, "cicids": external,
               "limitations": ["Synthetic generation is compact and idealized; held-out seeds are not held-out attack mechanisms.",
                               "Agent 2 baseline learns DDoS, PORT_SCAN and DATA_EXFILTRATION only.",
                               "Agent 1 DNS branches cannot be tested on CICIDS flow CSVs without DNS queries.",
                               "GraphSAGE, temporal C2, botnet, encrypted-malware and OOD production gates remain unvalidated.",
                               "Candidate scores are not approved production decisions; threshold failures remain reported."],
               "completed_at": datetime.now(timezone.utc).isoformat()}
    write_json(output / "summary.json", summary)
    portable = lambda path: path.relative_to(Path.cwd()).as_posix() if path.is_relative_to(Path.cwd()) else str(path)
    pointer = {"agent1_config": portable(output / "agent1/config.json"),
               "agent2_release": portable(output / "agent2/manifest.json"),
               "summary": portable(output / "summary.json"), "status": "candidate"}
    write_json(output.parent / "current.json", pointer)
    print(json.dumps({"output": str(output), "cicids_rows": external["total_rows"], "status": "candidate"}), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("artifacts/pipeline") / datetime.now().strftime("sim-%Y%m%d-%H%M%S"))
    parser.add_argument("--version", help="semantic model version; defaults to 2.0.0-<output-name>")
    parser.add_argument("--cicids", type=Path, default=Path("ingestion/dataset/CICIDS2017_improved"))
    parser.add_argument("--epochs", type=int, default=8)
    parser.add_argument("--trees", type=int, default=60)
    parser.add_argument("--duration", type=float, default=90)
    parser.add_argument("--max-rows", type=int, default=180)
    parser.add_argument("--threads", type=int, default=2)
    parser.add_argument("--batch-size", type=int, default=8192)
    args = parser.parse_args()
    if min(args.epochs, args.trees, args.duration, args.max_rows, args.threads, args.batch_size) <= 0:
        parser.error("numeric settings must be positive")
    run(args)


if __name__ == "__main__":
    main()
