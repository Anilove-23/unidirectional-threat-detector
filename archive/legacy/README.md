# Archived legacy pipeline

These components are retained for recovery and provenance after the Agent 1
and Agent 2 pipeline became the active implementation. They are not started by
the current launchers. Their datasets, model files, historical reports, and
the legacy ingestion operator utilities are preserved byte-for-byte.

The active external dataset remains at `ingestion/dataset/CICIDS2017_improved`.
Use `pipeline_runtime.py`, `train_pipeline.py`, and `start_all.sh` from the
repository root for the current pipeline.
