# Training and external evaluation

From the repository root, with dependencies installed:

```sh
python train_pipeline.py --output artifacts/pipeline/my-new-release --epochs 8 --trees 60
```

The command creates 30 independent, compact packet scenarios (90 seconds each),
replays them through Agent 1, trains five Agent 1 DNS branches and the Agent 2
SSL/autoencoder/isolation-forest/energy/prototype/XGBoost/meta-XGBoost stack, and
evaluates the frozen candidate on every CSV in
`ingestion/dataset/CICIDS2017_improved`. Existing release directories are never
overwritten. `artifacts/pipeline/current.json` points the development runtime to
the completed candidate. On Windows, the root `train_models.bat` launcher performs
the same workflow.

The corpus contains benign, DDoS, port-scan, exfiltration, DGA and DNS-tunnel
traffic. Packet session ports remain stable. Benign domains, DGA domains and
tunnel query encodings have distinct generator behavior. Labels come from a
separate per-event ground-truth file: benign background inside an attack phase
remains benign, and labels never enter observer features.

Scenario/run/seed/domain partitions are independent. All three training folds
hold out an entire run, including every core attack class. Preprocessing and
models fit training rows only; calibration and thresholds use validation only.
The test scenarios and CICIDS data never fit a model or select a threshold.
Held-out seeds use the same generator algorithms, so this tests reproducibility
and behavior within the simulator, not generalization to unseen attack tools.

## Artifacts

- `simulation/`: immutable packet captures, observations, ground truth, source
  manifests, indexes and checksums.
- `agent1/config.json`: portable checkpoint paths for all five trained branches.
- `agent1/training_report.json`: per-branch validation/test log loss and Brier loss.
- `agent2_dataset/index.json`: digest-pinned train/validation/test partitions.
- `agent2/manifest.json`: candidate bundle, threshold policy and artifact hashes.
- `synthetic_test_metrics.json`: held-out simulation classification metrics.
- `cicids/metrics.json`: complete CSV evaluation with per-file metrics and hashes.
- `cicids/predictions.csv.gz`: probabilities and threshold crossings for each
  evaluated CSV row, linked by filename and one-based CSV line number.
- `summary.json`: counts, results and limitations.

The trained baseline covers DDoS, PORT_SCAN and DATA_EXFILTRATION in Agent 2;
DGA and DNS_TUNNEL remain Agent 1 specialists. GraphSAGE, temporal C2, botnet and
encrypted-malware specialists are not trained by this command. OOD calibration
and production release gates remain unvalidated. Models and policies stay
unapproved candidates.

## CICIDS interpretation

The evaluation reads only forward packet count, forward IAT total/mean/min/max,
forward PSH/URG/RST flags and protocol. It converts microseconds to seconds,
derives packet rate from forward count/duration, and preserves missingness.
Combined `Flow Duration`, reverse statistics, combined rates, addresses, IDs,
ports, timestamps and labels never become model features. Wire-byte features
are omitted because the CSV packet-length layer does not match Agent 1 wire
lengths. Invalid forward counts/durations are excluded and counted explicitly.

Candidate batch inference uses the same fitted transforms/models/calibrators
as envelope inference, with a regression test establishing equality. The CSV
visibility ratio describes the mapped forward subset; unlike a live observer,
the CSV provides no DNS/TLS/window history. This distribution shift is part of
the external result, not corrected by fitting the external test data.

DDoS and Portscan (including `Infiltration - Portscan`) map to corresponding
heads. Other dataset classes retain their names and count as attacks for the
binary any-head result. An alert on an unknown class is not proof of correct
attack-family classification. DATA_EXFILTRATION has no matching CSV ground-truth
class. Agent 1 DNS models cannot be evaluated from CSVs without query names.
These reports measure candidate score quality, not production decisions,
streaming latency, incident correlation or alert-policy approval.

To repeat only the full external test into a new directory:

```sh
python -m agent2_detection_product.evaluation.cicids \
  --release artifacts/pipeline/my-new-release/agent2 \
  --output artifacts/pipeline/my-new-release/cicids-repeat
```
