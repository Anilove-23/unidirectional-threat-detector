from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .training_index import build_training_index


def verify_checksums(release_root):
    root = Path(release_root).resolve()
    checksum_file = root / "checksums.sha256"
    if not checksum_file.is_file():
        raise FileNotFoundError(checksum_file)
    checked = {}
    for line in checksum_file.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        digest, relative = line.split("  ", 1)
        path = (root / relative).resolve()
        if not path.is_relative_to(root) or not path.is_file():
            raise ValueError(f"checksum path missing/outside release: {relative}")
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != digest:
            raise ValueError(f"checksum mismatch: {relative}")
        checked[relative] = digest
    return checked


def verify_release(release_root):
    root = Path(release_root).resolve()
    manifest = json.loads((root / "release.json").read_text(encoding="utf-8"))
    checked = verify_checksums(root)
    index = build_training_index(root / "scenarios")
    if index["record_count"] != manifest["observation_count"]:
        raise ValueError("release observation count differs from derived index")
    if len(list((root / "scenarios").rglob("capture.pcap"))) != manifest["pcap_count"]:
        raise ValueError("release PCAP count differs from release manifest")
    return {"release": manifest, "checked_files": len(checked), "index_sha256": index["index_sha256"]}
