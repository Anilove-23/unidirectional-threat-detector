"""Digest-checked immutable artifacts. Only load trusted local model releases."""

import hashlib
import json
import re
from pathlib import Path


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def verify_manifest(path, *, approved=False):
    path = Path(path).resolve()
    manifest = json.loads(path.read_text(encoding="utf-8"))
    if manifest.get("schema_version") != "2.0.0" or not re.fullmatch(r"\d+\.\d+\.\d+(?:-[\w.-]+)?", manifest.get("version", "")):
        raise ValueError("invalid release schema/version")
    if approved and manifest.get("status") != "approved":
        raise ValueError("production requires an approved model release")
    artifacts = manifest.get("artifacts", {})
    if not artifacts:
        raise ValueError("release contains no artifacts")
    for relative, digest in artifacts.items():
        artifact = (path.parent / relative).resolve()
        if not artifact.is_relative_to(path.parent) or not artifact.is_file():
            raise ValueError("artifact path outside immutable release or missing")
        if sha256(artifact) != digest:
            raise ValueError(f"artifact digest mismatch: {relative}")
    return manifest


def verify_agent1_release(path, expected_digest):
    if not expected_digest or sha256(path) != expected_digest:
        raise ValueError("Agent 1 release digest does not match integration pin")
    # Producer release layout stays producer-owned. Consumer checks exact bytes.
    manifest = json.loads(Path(path).read_text(encoding="utf-8"))
    if not manifest.get("feature_schema_version", "").startswith("2."):
        raise ValueError("incompatible Agent 1 feature release")
    return manifest
