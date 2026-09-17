# Agent 2 release and deployment runbook

1. Validate the immutable Agent 1 manifest and record its SHA-256 digest.
2. Train Agent 2 candidates from a released train/validation index. The command must produce OOF provenance, threshold/calibration reports, and `status: candidate`.
3. Run within-domain, held-out family/tool, cross-dataset, public-to-lab, OOD, adversarial, routing shadow, load, recovery, and UI checks. Include old-class regression and calibration results.
4. An independent release step changes the manifest to `status: approved`, records the Agent 1 manifest digest, and freezes bundle, policy, dataset index, and report hashes. Production refuses candidate or digest-mismatched artifacts.
5. Start one Redis consumer group per model profile. Horizontal workers must partition by sensor and never share a mutable checkpoint.
6. On a bad release, stop consumers, select the previous compatible Agent 1/Agent 2 digest pair, and start with a new checkpoint profile. Do not reuse a checkpoint across model profiles.

The passive boundary is preserved by construction: this plane only consumes observation records and publishes decisions. It has no packet socket, DNS client, transmit route, payload decryption path, or automated mitigation hook.
