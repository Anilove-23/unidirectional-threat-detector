# All-attack simulation results

Release: 2.0.0-sim-20260918. Policy approved: False.

| Class | Positive observations | Recall | Precision | F1 | Status |
|---|---:|---:|---:|---:|---|
| BOTNET_COORDINATION | 9 | N/A | N/A | N/A | MODEL_UNAVAILABLE |
| BOTNET_HOST | 9 | N/A | N/A | N/A | MODEL_UNAVAILABLE |
| C2_BEACONING | 12 | N/A | N/A | N/A | MODEL_UNAVAILABLE |
| DATA_EXFILTRATION | 53 | 84.91% | 100.00% | 91.84% | CANDIDATE_ONLY |
| DDoS | 2001 | 99.85% | 100.00% | 99.92% | CANDIDATE_ONLY |
| DGA | 44 | 36.36% | 100.00% | 53.33% | CANDIDATE_ONLY |
| DNS_TUNNEL | 56 | 0.00% | 0.00% | 0.00% | CANDIDATE_ONLY |
| ENCRYPTED_MALWARE | 12 | N/A | N/A | N/A | MODEL_UNAVAILABLE |
| PORT_SCAN | 224 | 100.00% | 100.00% | 100.00% | CANDIDATE_ONLY |

Candidate exact-label match: **95.49%** across 2,841 observations; final-flow snapshots: **94.10%** across 305 snapshots.

Supported-class macro recall: **64.22%**; macro F1: **69.02%**. DDoS dominates the sample count.

All final decisions were UNCERTAIN (0% coverage); final project accuracy is **not measurable** on this run.

## Overall

```json
{
  "observations": 2841,
  "candidate_exact_label_accuracy": 0.9549454417458642,
  "candidate_binary_attack_accuracy": 0.9549454417458642,
  "decision_states": {
    "UNCERTAIN": 2841
  },
  "final_decision_coverage": 0.0,
  "final_selective_accuracy": null,
  "benign_observations": 430,
  "benign_candidate_false_positive_rate": 0.0
}
```

## Limitations

- Fresh seeds from the same simulator algorithms; not a real-world benchmark.
- 12 compact scenarios, one seed each, three clients and two servers, 90 seconds each.
- Partial snapshots are correlated; final-flow snapshot metrics are reported separately.
- Candidate threshold crossings ignore final calibration and policy approval gates; they are not actual alerts.
- C2, botnet and encrypted-malware heads unavailable: no class accuracy claimed.
- Encrypted-malware simulation emits dummy opaque bytes, not genuine malware TLS sessions.
- No fitting, threshold tuning or adaptation performed on this evaluation.
- Offline model path exercised; Redis/backend/dashboard delivery not tested.
- Windows XGBoost cannot load the original Linux memory snapshot; six unchanged trees were exported with Linux and verified against Linux predictions.
