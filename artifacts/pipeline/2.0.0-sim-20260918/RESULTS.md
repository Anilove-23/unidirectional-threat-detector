# Simulator training and CICIDS2017 improved evaluation

Completed using `python train_pipeline.py --output artifacts/pipeline/2.0.0-sim-20260918 --epochs 8 --trees 60`.

The run generated 12,750 observations across 30 packet scenarios. Five Agent 1
DNS branches each used a 542-row partitioned corpus (328 training, 107 validation,
107 test). Agent 2 trained on 1,862 observations using three run-held-out folds.
Held-out simulation evaluation used 620 observations.

| Agent 2 label | Simulation test F1 | CICIDS precision | CICIDS recall | CICIDS F1 |
| --- | ---: | ---: | ---: | ---: |
| DDoS | 99.72% | 0.23% | 2.52% | 0.43% |
| PORT_SCAN | 100.00% | 74.33% | 99.46% | 85.08% |
| DATA_EXFILTRATION | 97.83% | Not measurable | Not measurable | Not measurable |

All five CICIDS files were read: 2,099,976 rows total, 2,099,943 evaluated and 33
excluded for invalid forward counts/durations. No CICIDS row was used for
training, calibration or threshold selection. Only forward traffic features
were used; reverse and combined statistics were excluded.

The any-known-head binary result had precision 31.51%, recall 98.80%, F1 47.79%
and accuracy 46.80%. Its benign false-positive rate was 70.20%. The high recall
therefore does not indicate a usable detector. Performance drops substantially
outside this simple simulator, particularly for DDoS classification.

These artifacts remain unapproved candidates. DNS models cannot be tested on
CICIDS flow CSVs without query names; exfiltration has no matching ground-truth
class. Graph, temporal C2, botnet, encrypted-malware and OOD production gates are
not validated. The development UI may display candidate evidence, but these
results do not support production deployment.

`summary.json` and `cicids/metrics.json` contain exact metrics, per-file results,
input SHA-256 digests and limitations. `cicids/predictions.csv.gz` contains every
evaluated row's candidate probabilities and threshold crossings.
