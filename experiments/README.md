# Domain-transfer experiments

The V2 release is frozen at `artifacts/pipeline/2.0.0-sim-20260918`. The
experiments use its bundle without replacing the deployed artifact. Run the
analysis with:

```bash
uv pip install --python .venv_linux/bin/python -r requirements-experiments.txt
.venv_linux/bin/python -m experiments.domain_shift --stage audit
.venv_linux/bin/python -m experiments.domain_shift --stage ablation
.venv_linux/bin/python -m experiments.domain_shift --stage adaptation
.venv_linux/bin/python -m experiments.domain_shift --stage v3
.venv_linux/bin/python -m experiments.domain_shift --stage plots
.venv_linux/bin/python -m experiments.domain_shift --stage thresholds
```

Results are written to `artifacts/experiments/domain-shift-20260918`.

The six requested experiments are represented as follows:

- A: `A_scores.json`, `A_stage_metrics.json`, `A_agent1_scores.json`, and the
  score histogram figures. It records benign, matching-positive, and
  other-attack distributions for base, meta, and calibrated scores.
- B: `B_feature_drift.csv` and `B_feature_drift.json`. Statistics are computed
  on finite values with missingness reported separately. PSI uses simulation
  benign decile bins and Jeffreys smoothing. Protocol uses categorical bins.
- C: `C_tree_shap.csv`, `C_end_to_end_shap.csv`, and `C_exact_tree_rules.json`.
  TreeSHAP additivity is checked. End-to-end attribution uses 32 random
  interventional permutations on 128 flows per population.
- D: `D_ablation.csv` and `D_method.json`. Each variant retrains the unchanged
  stack on the same simulation partitions. Duration and packet count aliases
  are removed from metadata context as well as direct inputs.
- E: `E_summary.json`, `E_partitions.json`, and `E/`. Monday benign rows are
  used without attack labels for representation and normality adaptation.
  Tuesday through Friday are evaluation-only. A benign-only quantile threshold
  is reported as a diagnostic and is not called a calibrated attack threshold.
- F: `F_summary.json` and `F/`. V3 uses simulation-only packet generation,
  diverse benign traffic, DDoS configurations, hard negatives, multiple
  sources/destinations, and one final observation per flow segment. The full
  1,152-point Cartesian plan is recorded; 60 balanced configurations are
  executed under a bounded packet budget.

The additional threshold sweep is `G_threshold_sweep.csv` and
`G_threshold_summary.json`. It is diagnostic only. The timing ablation reaches
DDoS F1 0.541 at an externally selected threshold of 0.9853, with 99.97% recall
and 1.20% benign FPR, while the frozen V2 operating point remains unusable.

The external benchmark has already guided V3 design, so it is a development
benchmark rather than a fresh unbiased claim. A new untouched capture is needed
for a final transfer result.
