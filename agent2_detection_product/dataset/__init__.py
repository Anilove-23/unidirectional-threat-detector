"""Release products derived from immutable Agent 1 scenario outputs."""

from .training_index import build_training_index, write_training_index, resolve_training_index
from .integrity import verify_release, verify_checksums

__all__ = ["build_training_index", "write_training_index", "resolve_training_index", "verify_release", "verify_checksums"]
