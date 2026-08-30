# Person 2 — Unsupervised & Sequential Deep Learning Engine

This module builds the anomaly-detection and sequence-modeling layer for
SIH26145, and owns the final ensemble scoring that produces the alert
published to Redis `alert.new`.

## Status
🚧 Scaffolding — no trained models yet.

## Planned components
- Isolation Forest + Autoencoder — zero-day / unseen-threat anomaly scoring
- PyTorch LSTM — low-and-slow Botnet C2 beaconing detection from
  packet_sizes / inter_arrival_times sequences
- JA3/JA4 + cipher-suite-ordering features from FlowObject.tls_meta
- Ensemble scoring — fuses Person 1's supervised probabilities
  (xgboost_train/scripts/infer.py) with anomaly + sequence scores into
  one confidence_score and threat_class per flow

## Input
Subscribes to Redis channel `flow.raw` (FlowObject v1.0.0 —
see ingestion/docs/FLOW_OBJECT_SCHEMA.md)

## Output
Publishes to Redis channel `alert.new`, conforming to the Standardized
JSON Alert Schema (SIH26145 spec Section 6).

## Handoff
- Consumes: `xgboost_train/scripts/infer.py` (predict_flow_proba, predict_dns_proba)
- Produces for Person 4: alert.new messages including confidence_score,
  severity, and model_source breakdown (supervised_score, anomaly_score,
  sequence_score, fired_models)
