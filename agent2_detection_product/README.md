# Agent 2 Detection and Product Plane

This package implements the SIH26145 V2 Agent 2 boundary: detection, open-set decisioning, bounded state, incident correlation, product transport, evaluation, and release verification. It consumes versioned Agent 1 `ObservationEnvelope v2`, `SpecialistScore v2`, and `ScenarioRelease v1` records. It does not capture packets, generate scenarios, extract DNS features, or write Agent 1 state.

The same `DetectionPipeline` is used for JSONL replay and Redis Streams. Every event is validated before state mutation. A stable `(sensor_id, event_id)` key makes retries idempotent; duplicate payloads return the original decision and a changed payload is rejected. Missing fields retain a presence mask and are never converted to observed zero.

Development replay is intentionally abstaining until approved model and threshold releases are pinned:

```powershell
.venv/Scripts/python.exe -m agent2_detection_product replay `
  --development `
  --input replay.v2.jsonl `
  --output decisions.v2.jsonl
```

Production requires both release manifests and the exact Agent 1 SHA-256 pin:

```powershell
.venv/Scripts/python.exe -m agent2_detection_product redis `
  --release releases/agent2/2.0.0/manifest.json `
  --agent1-release releases/agent1/2.0.0/manifest.json `
  --agent1-sha256 <agent1-manifest-sha256>
```

The Redis worker consumes `observation.v2` through a consumer group and publishes `decision.v2`, `decision.new`, `incident.v2`, and `incident.update`. Invalid records go to `observation.v2.dead`; processing state and the outbox are checkpointed in SQLite before acknowledgement.

Model training is in `evaluation/train.py`. It requires scenario/group-disjoint train and validation partitions, fits transforms on training data only, creates GroupKFold out-of-fold scores for Meta-XGBoost, calibrates and selects thresholds on validation only, and publishes a candidate manifest. Candidate artifacts are never self-approved.

The dashboard receives V2 decisions and incident timelines through the existing WebSocket. It displays all passing labels, four-state status, OOD and uncertainty evidence, visibility limitations, model/routing/threshold versions, drift state, and correlated incident history.
