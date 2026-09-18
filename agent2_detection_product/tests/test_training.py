"""Exercises actual optimization on tiny fixtures, not a detection benchmark."""
import numpy as np
import joblib
import pytest
from ..evaluation.train import train
from ..orchestration.registry import verify_manifest, sha256
from .fixtures import envelope


def rows(split, groups):
    result = []
    for group in range(groups):
        for index in range(16):
            label = ([], ["DDoS"], ["PORT_SCAN"], ["DATA_EXFILTRATION"])[index % 4]
            env = envelope(f"{split}-{group}-{index}", group * 100 + index)
            env["features"]["flow"]["byte_count"] = (index % 4 + 1) * 100 + group
            env["features"]["flow"]["packet_count"] = index + 1
            result.append({"observation": env, "labels": label, "split": split, "group_id": f"{split}-{group}", "scenario_id": f"{split}-{group}", "verified": True})
    return result


def test_complete_fold_training_serialization_and_inference(tmp_path):
    bundle, policy, report = train(rows("train", 4), rows("validation", 1), ["flow.byte_count", "flow.packet_count"], version="2.0.0-test", epochs=1, trees=2, folds=2)
    assert report["oof_rows"] == 64
    assert not report["test_opened"]
    assert not policy["approved"]
    path = tmp_path / "bundle.joblib"
    joblib.dump(bundle, path)
    restored = joblib.load(path)
    output = restored.score(envelope(), {})
    assert len(output["scores"]) == 3
    assert all(0 <= s["probability"] <= 1 for s in output["scores"])
    assert not output["ood"]["calibrated"]
    envs = [row["observation"] for row in rows("validation", 1)]
    raw = restored.base.preprocessor.raw(envs)
    batch = restored.predict_forward_matrix(raw,
        visibility=np.asarray([env["visibility"]["feature_availability_ratio"] for env in envs]),
        event_count=np.asarray([env["history"]["event_count"] for env in envs]),
        duration_ms=np.asarray([env["history"]["duration_ms"] for env in envs]))
    np.testing.assert_allclose(batch, restored.predict_probabilities(envs), atol=1e-7)


def test_release_rejects_tampering_and_unapproved_candidate(tmp_path):
    import json
    artifact = tmp_path / "bundle.bin"
    artifact.write_bytes(b"test only")
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"schema_version": "2.0.0", "version": "2.0.0", "status": "candidate", "artifacts": {"bundle.bin": sha256(artifact)}}))
    verify_manifest(manifest)
    with pytest.raises(ValueError):
        verify_manifest(manifest, approved=True)
    artifact.write_bytes(b"tampered")
    with pytest.raises(ValueError):
        verify_manifest(manifest)
