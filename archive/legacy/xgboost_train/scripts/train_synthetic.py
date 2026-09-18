"""
xgboost_train/scripts/train_synthetic.py
========================================
Person 1 — Supervised Feature Analytics Engineer

Trains robust XGBoost Flow and DNS models using the synthetic FlowObject
dataset (`p1_synthetic_evaluation.jsonl`), avoiding the CICIDS2017 overfitting.

Usage:
    uv run python xgboost_train/scripts/train_synthetic.py
"""

import sys
import json
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

import pandas as pd
import xgboost as xgb
import joblib
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split

from features import extract_flow_features, extract_dns_features

ROOT = Path(__file__).resolve().parent.parent
MODELS_DIR = ROOT / "models"
DATA_FILE = ROOT / "dataset" / "p1_synthetic_evaluation.jsonl"

def _banner(msg: str):
    print(f"\n{'='*60}\n  {msg}\n{'='*60}")

def main():
    MODELS_DIR.mkdir(exist_ok=True, parents=True)
    
    _banner("Loading Dataset")
    if not DATA_FILE.exists():
        print(f"[!] Dataset not found: {DATA_FILE}")
        print("Run generate_p1_dataset.py first.")
        sys.exit(1)
        
    df = pd.read_json(DATA_FILE, lines=True)
    print(f"[*] Loaded {len(df)} total flows.")

    # Split into Flow and DNS domains
    df_dns = df[df["dns_meta"].notnull()].copy()
    df_flow = df[df["dns_meta"].isnull()].copy()
    
    # -------------------------------------------------------------------------
    # 1. TRAIN FLOW MODEL (BENIGN, VOLUMETRIC_DDOS, PORT_SCAN, DATA_EXFILTRATION)
    # -------------------------------------------------------------------------
    _banner("Training Flow Model")
    print(f"[*] Extracting features for {len(df_flow)} flows...")
    X_flow = extract_flow_features(df_flow)
    
    le_flow = LabelEncoder()
    y_flow = le_flow.fit_transform(df_flow["collected_label"])
    
    # Save column ordering so inference always matches
    train_cols = list(X_flow.columns)
    (MODELS_DIR / "flow_feature_columns.json").write_text(json.dumps(train_cols), encoding="utf-8")
    
    X_train, X_test, y_train, y_test = train_test_split(X_flow, y_flow, test_size=0.2, random_state=42)
    
    print("[*] Training XGBoost Flow Model...")
    flow_model = xgb.XGBClassifier(
        n_estimators=100,
        max_depth=6,
        learning_rate=0.1,
        objective="multi:softprob",
        eval_metric="mlogloss",
        use_label_encoder=False,
    )
    flow_model.fit(X_train, y_train)
    
    print("[*] Evaluating on 20% test split:")
    preds = flow_model.predict(X_test)
    print(classification_report(y_test, preds, target_names=le_flow.classes_))
    
    flow_model.save_model(MODELS_DIR / "flow_model.json")
    joblib.dump(le_flow, MODELS_DIR / "flow_label_encoder.pkl")
    print("[+] Flow model and encoder saved.")

    # -------------------------------------------------------------------------
    # 2. TRAIN DNS MODEL (BENIGN, DGA, DNS_TUNNELING)
    # -------------------------------------------------------------------------
    _banner("Training DNS Model")
    # Flatten dns_meta to extract query_name for the text vectorizer
    df_dns["domain"] = df_dns["dns_meta"].apply(lambda x: x["query_name"])
    
    print(f"[*] Extracting features for {len(df_dns)} DNS flows...")
    X_dns, dns_vec = extract_dns_features(df_dns, fit=True)
    
    le_dns = LabelEncoder()
    y_dns = le_dns.fit_transform(df_dns["collected_label"])
    
    X_train_d, X_test_d, y_train_d, y_test_d = train_test_split(X_dns, y_dns, test_size=0.2, random_state=42)
    
    print("[*] Training XGBoost DNS Model...")
    dns_model = xgb.XGBClassifier(
        n_estimators=100,
        max_depth=6,
        learning_rate=0.1,
        objective="multi:softprob",
        eval_metric="mlogloss",
        use_label_encoder=False,
    )
    dns_model.fit(X_train_d, y_train_d)
    
    print("[*] Evaluating on 20% test split:")
    preds_d = dns_model.predict(X_test_d)
    print(classification_report(y_test_d, preds_d, target_names=le_dns.classes_))
    
    dns_model.save_model(MODELS_DIR / "dns_model.json")
    joblib.dump(le_dns, MODELS_DIR / "dns_label_encoder.pkl")
    joblib.dump(dns_vec, MODELS_DIR / "dns_vectorizer.pkl")
    print("[+] DNS model, encoder, and vectorizer saved.")

if __name__ == "__main__":
    main()
