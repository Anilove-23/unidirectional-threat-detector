# V2 simulation releases and training index

The release builder consumes `ScenarioSpec` objects from Agent 1’s simulation layer and writes PCAPs, production replay observations, manifests, checksums, quality reports, and a derived `TrainingIndex`. Raw PCAP and observation files remain immutable authorities; the index only joins them.

Build a release without training:

```powershell
.venv/Scripts/python.exe -m agent2_detection_product.dataset.build_release `
  D:/releases/simulation-v2.0.0 `
  --family dga --seed 101 --variant family_a
```

For multi-scenario releases, call `build_release()` with explicitly split-assigned `ScenarioSpec` objects. `verify_release()` validates checksums, PCAP/manifest/index counts, and split isolation. `resolve_training_index()` materializes observation references for a loader while retaining the original paths and hashes.

The CLI also accepts a mixed split release directly:

```powershell
.venv/Scripts/python.exe -m agent2_detection_product.dataset.build_release `
  D:/releases/simulation-v2.0.0 `
  --spec dga:101:family_a:train `
  --spec dga:202:family_b:validation `
  --spec dga:303:family_c:test
```

The command does not import Agent 1 or Agent 2 training modules and writes `training_started: false` into `release.json`. The existing smoke scenario remains available through the original `scenario` command and is recorded as `simulation-baseline-v1`.
