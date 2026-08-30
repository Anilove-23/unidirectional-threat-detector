# Person 1 — Supervised Machine Learning Engine

This module contains the offline training scripts and live inference bridge for the two supervised XGBoost classifiers responsible for detecting volumetric and lexical network threats.

The final outputs of these models are **class-probability dictionaries**. These probabilities are subsequently consumed by Person 2's ensemble layer (which combines them with PyTorch LSTMs and Isolation Forest anomaly scores).

---

## 🧠 Models Overview

### Model A: Flow Attack Classifier (`flow_model.json`)
Detects volumetric and connection-layer threats based on network flow statistics.
- **Algorithm**: XGBoost (`objective="multi:softprob"`)
- **Classes (4)**: `BENIGN`, `VOLUMETRIC_DDOS`, `PORT_SCAN`, `DATA_EXFILTRATION`
- **Input Dimension**: 60 numeric features.
- **Feature Source**: Derives CICIDS-equivalent aggregates (e.g., `Flow IAT Mean`, `Fwd Packet Length Std`, `Flow Packets/s`) in real-time from the raw lists (`packet_sizes`, `inter_arrival_times`) and scalars (`duration_s`, `bytes_in`) provided in the live `FlowObject`.

### Model B: DNS Lexical Classifier (`dns_model.json`)
Detects DNS-layer threats based purely on the domain name string.
- **Algorithm**: XGBoost (`objective="multi:softprob"`)
- **Classes (3)**: `BENIGN`, `DGA`, `DNS_TUNNEL`
- **Input Dimension**: 55 numeric features.
- **Feature Source**: 5 scalar lexical features (e.g., Shannon entropy, length, digit ratio) + 50 character n-gram features (generated via `sklearn.feature_extraction.text.CountVectorizer` fitting 2-3 char n-grams).

---

## 🔌 API Endpoints (`scripts/infer.py`)

For downstream integration (e.g., Person 2's ensemble layer), this module exposes two primary API functions. Models and preprocessing artifacts are lazy-loaded securely on the first call.

### 1. `predict_flow_proba(record)`
Generates probabilities for Model A.

**Expected Input:**
A single `FlowObject` dictionary (as defined in `FLOW_OBJECT_SCHEMA.md`), or a Pandas DataFrame for batch inference.

**Expected Output:**
A dictionary of threat classes mapped to float probabilities, sorted in descending order of confidence.
```python
from scripts.infer import predict_flow_proba

result = predict_flow_proba(flow_obj)
# Example Output:
# {
#   "VOLUMETRIC_DDOS": 0.9412,
#   "BENIGN": 0.0341,
#   "PORT_SCAN": 0.0147,
#   "DATA_EXFILTRATION": 0.0100
# }
```

### 2. `predict_dns_proba(domain)`
Generates probabilities for Model B.

**Expected Input:**
A single domain name string (e.g., `"test.c2.example.com"`).

**Expected Output:**
A dictionary of threat classes mapped to float probabilities, sorted in descending order of confidence.
```python
from scripts.infer import predict_dns_proba

result = predict_dns_proba("test.c2.example.com")
# Example Output:
# {
#   "DGA": 0.9521,
#   "DNS_TUNNEL": 0.0312,
#   "BENIGN": 0.0167
# }
```

---

## ⚡ Live Inference Bridge (`scripts/live_inference.py`)

To run the models against live capture data from Person 3, run the live inference engine. This script subscribes to the Redis Pub/Sub channel `flow.raw`.

### How to Run
```bash
# From the project root:
uv run python xgboost_train/scripts/live_inference.py
```

### Data Flow
1. **Listen:** Blocks and listens on Redis `127.0.0.1:6379` channel `flow.raw`.
2. **Ingest:** Parses the incoming JSON `FlowObject` payload.
3. **Feature Extraction:** Calls `extract_flow_features` to map the `FlowObject` properties (like `bytes_in`, `duration_s`, and the `packet_sizes` array) into the exact 60 CICIDS column headers the XGBoost model expects.
4. **Scoring:** Passes the features to Model A. If a `dns_meta` block is present with a `query_name`, it also passes the domain to Model B.
5. **Output:** Prints the resulting human-readable probability dictionaries in real-time.

---

## 📁 Artifacts & Dimensions

The `models/` directory contains all stateful elements required for inference:

| Artifact | Purpose | Dimension / Size |
|---|---|---|
| `flow_model.json` | Model A XGBoost weights | 60 features → 4 classes |
| `dns_model.json` | Model B XGBoost weights | 55 features → 3 classes |
| `flow_label_encoder.pkl` | sklearn LabelEncoder for Model A | 4 target strings |
| `dns_label_encoder.pkl` | sklearn LabelEncoder for Model B | 3 target strings |
| `dns_vectorizer.pkl` | sklearn CountVectorizer | `max_features=50` n-grams |
| `flow_feature_columns.json` | Ordered list of exactly 60 feature column names Model A expects | List[str] length 60 |
