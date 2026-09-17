"""Reproducible candidate training. Final test files are never opened here."""

import argparse
import json
from pathlib import Path
import numpy as np
import torch
import joblib
from ..contracts import make_score
from ..models.shared_ssl_encoder import MaskedPreprocessor, SSLEncoder
from ..models.anomaly_autoencoder import BenignAutoencoder
from ..models.anomaly_iforest import LatentIsolationForest
from ..models.open_set_energy import EnergyHead, PrototypeDistance, ReferencePercentiles
from ..models.tabular_known_xgb import KnownXGBoost
from ..models.meta_xgb import MetaXGBoost, generate_oof, context_vector
from ..calibration import LabelCalibrator, select_threshold
from ..multilabel_decision import DEFAULT_POLICY
from ..orchestration.registry import sha256
from .data import read_partition, assert_disjoint


LABELS = ("DDoS", "PORT_SCAN", "DATA_EXFILTRATION")


class BaseStack:
    def __init__(self, paths, epochs=20, trees=80):
        self.paths, self.epochs, self.trees = paths, epochs, trees

    def fit(self, envelopes, targets, *, split):
        if split != "train":
            raise ValueError("base stack requires training data")
        torch.manual_seed(26)
        self.preprocessor = MaskedPreprocessor(self.paths).fit(envelopes, split=split)
        values, masks = self.preprocessor.transform(envelopes)
        self.ssl = SSLEncoder(len(self.paths)).fit(values, masks, split=split, epochs=self.epochs)
        embeddings = self.ssl.embed(values, masks)
        benign = np.asarray(targets).sum(axis=1) == 0
        if benign.sum() < 2:
            raise ValueError("verified benign training examples required")
        self.ae = BenignAutoencoder(32).fit(embeddings[benign], split=split, verified_benign=True, epochs=self.epochs)
        self.iforest = LatentIsolationForest().fit(embeddings[benign], split=split)
        # A deterministic primary index is used only to train the energy head;
        # independent known heads preserve the original multi-label targets.
        energy_targets = np.where(benign, 0, np.argmax(targets, axis=1) + 1)
        self.energy = EnergyHead(32, len(LABELS) + 1).fit(embeddings, energy_targets, split=split, epochs=self.epochs)
        self.prototypes = PrototypeDistance().fit(embeddings, energy_targets, split=split)
        self.known = KnownXGBoost(LABELS, n_estimators=self.trees).fit(np.column_stack((values, masks, embeddings, self.auxiliary(embeddings))), targets, split=split)
        return self

    def auxiliary(self, embeddings):
        return np.column_stack((self.energy.energy(embeddings), self.ae.error(embeddings), self.iforest.anomaly(embeddings), self.prototypes.distance(embeddings)))

    def outputs(self, envelopes):
        values, masks = self.preprocessor.transform(envelopes)
        embeddings = self.ssl.embed(values, masks)
        auxiliary = self.auxiliary(embeddings)
        scores = self.known.predict(np.column_stack((values, masks, embeddings, auxiliary)))
        return scores, auxiliary

    def predict(self, envelopes):
        scores, auxiliary = self.outputs(envelopes)
        return np.asarray([context_vector(env, row.tolist()) + aux.tolist() for env, row, aux in zip(envelopes, scores, auxiliary)])


class CandidateBundle:
    def __init__(self, base, meta, calibrators, references, version):
        self.base, self.meta = base, meta
        self.calibrators, self.references, self.version = calibrators, references, version
        self.specialists = []
        self.ood_validated = False

    def score(self, envelope, context):
        features = self.base.predict([envelope])
        predictions = self.meta.predict(features)[0]
        scores = [make_score(envelope, label, float(self.calibrators[label].predict([predictions[i]])[0]), "meta_xgb", self.version, calibrated=True, evidence={"base_stack": "SSL+XGB+AE+IF+energy+prototype", "feature_paths": self.base.paths}) for i, label in enumerate(LABELS)]
        _, auxiliary = self.base.outputs([envelope])
        ood = {key: float(self.references[key].transform([auxiliary[0, i]])[0]) for i, key in enumerate(("energy", "ae_error", "if_score", "latent_distance"))}
        ood["calibrated"] = self.ood_validated
        for provider in self.specialists:
            scores.extend(provider.score(envelope, context).get("scores", []))
        return {"scores": scores, "ood": ood, "profile": self.version,
                "drift_values": {"latent_distance": float(auxiliary[0, 3]), "known_confidence": float(max(predictions))}}


def train(train_rows, validation_rows, paths, *, version, epochs=20, trees=80, folds=3):
    assert_disjoint(train_rows, validation_rows)
    # Unknown/other attacks must never be silently re-labelled verified benign.
    for row in train_rows + validation_rows:
        if row.get("verified") is not True or set(row["labels"]) - set(LABELS):
            raise ValueError("this baseline trainer requires verified benign/core-known rows; train specialists separately")
    envs = [r["observation"] for r in train_rows]
    val_envs = [r["observation"] for r in validation_rows]
    targets = np.asarray([[int(label in r["labels"]) for label in LABELS] for r in train_rows])
    val_targets = np.asarray([[int(label in r["labels"]) for label in LABELS] for r in validation_rows])
    factory = lambda: BaseStack(paths, epochs, trees)
    oof, provenance = generate_oof(factory, envs, targets, [r["group_id"] for r in train_rows], folds=folds)
    meta = MetaXGBoost(LABELS, n_estimators=trees).fit_oof(oof, targets, provenance)
    base = factory().fit(envs, targets, split="train")
    predicted = meta.predict(base.predict(val_envs))
    calibrators, thresholds, rejected = {}, {}, []
    for i, label in enumerate(LABELS):
        calibrators[label] = LabelCalibrator().fit(predicted[:, i], val_targets[:, i], split="validation")
        calibrated = calibrators[label].predict(predicted[:, i])
        try:
            thresholds[label] = select_threshold(calibrated, val_targets[:, i], split="validation")
        except ValueError as exc:
            rejected.append(f"{label}: {exc}")
    _, auxiliary = base.outputs(val_envs)
    benign = val_targets.sum(axis=1) == 0
    references = {key: ReferencePercentiles().fit(auxiliary[benign, i], split="validation") for i, key in enumerate(("energy", "ae_error", "if_score", "latent_distance"))}
    bundle = CandidateBundle(base, meta, calibrators, references, version)
    _, train_auxiliary = base.outputs(envs)
    bundle.drift_reference = {"visibility": [e["visibility"]["feature_availability_ratio"] for e in envs], "latent_distance": train_auxiliary[:, 3].tolist()}
    policy = json.loads(json.dumps(DEFAULT_POLICY))
    policy["version"] = f"thresholds-{version}"
    policy["thresholds"].update(thresholds)
    # Approval additionally requires DNS/temporal/graph/OOD evaluation and frozen
    # full-system gates. Training never approves its own output.
    return bundle, policy, {"oof_rows": len(oof), "folds": folds, "threshold_rejections": rejected, "provenance": provenance, "status": "candidate", "test_opened": False}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", required=True, type=Path, help="consumer dataset index with train/validation paths and SHA-256 digests")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--version", required=True)
    parser.add_argument("--epochs", type=int, default=20)
    args = parser.parse_args()
    index = json.loads(args.dataset.read_text())
    partitions = {}
    for split in ("train", "validation"):
        entry = index["partitions"][split]
        data_path = (args.dataset.parent / entry["path"]).resolve()
        if not data_path.is_relative_to(args.dataset.parent.resolve()):
            raise ValueError("dataset path escapes release")
        partitions[split] = read_partition(data_path, split=split, expected_digest=entry["sha256"])
    bundle, policy, report = train(partitions["train"], partitions["validation"], index["numeric_feature_paths"], version=args.version, epochs=args.epochs)
    args.output.mkdir(parents=True, exist_ok=False)
    joblib.dump(bundle, args.output / "bundle.joblib")
    (args.output / "policy.json").write_text(json.dumps(policy, indent=2))
    (args.output / "training_report.json").write_text(json.dumps(report, indent=2))
    manifest = {"schema_version": "2.0.0", "version": args.version, "status": "candidate", "bundle": "bundle.joblib", "policy": "policy.json", "agent1_manifest_sha256": index.get("agent1_manifest_sha256"), "dataset_index_sha256": sha256(args.dataset), "artifacts": {name: sha256(args.output / name) for name in ("bundle.joblib", "policy.json", "training_report.json")}}
    (args.output / "manifest.json").write_text(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
