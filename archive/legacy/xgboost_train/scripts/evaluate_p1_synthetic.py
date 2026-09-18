"""
xgboost_train/scripts/evaluate_p1_synthetic.py
==============================================
Evaluates Person 1's flow and DNS models on the synthetic, totally unseen data.
"""

import sys
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

import pandas as pd
import xgboost as xgb
import joblib
from sklearn.metrics import classification_report
from features import extract_flow_features, extract_dns_features
import json

ROOT = Path(__file__).resolve().parent.parent
MODELS_DIR = ROOT / "models"
DATA_FILE = ROOT / "dataset" / "p1_synthetic_evaluation.jsonl"

def main():
    print("[*] Loading synthetic flows...")
    df = pd.read_json(DATA_FILE, lines=True)
    
    # Split into Flow (TCP/ICMP etc) and DNS (UDP 53)
    df_dns = df[df["dns_meta"].notnull()].copy()
    df_flow = df[df["dns_meta"].isnull()].copy()

    # --- 1. Evaluate Flow Model ---
    print(f"\n[*] Evaluating Flow Model on {len(df_flow)} entirely unseen flows...")
    flow_model = xgb.XGBClassifier()
    flow_model.load_model(MODELS_DIR / "flow_model.json")
    flow_le = joblib.load(MODELS_DIR / "flow_label_encoder.pkl")
    
    X_flow = extract_flow_features(df_flow)
    train_cols = json.loads((MODELS_DIR / "flow_feature_columns.json").read_text(encoding="utf-8"))
    X_flow = X_flow.reindex(columns=train_cols, fill_value=0)
    
    flow_preds = flow_model.predict(X_flow)
    df_flow["predicted_class"] = flow_le.inverse_transform(flow_preds)
    
    print(classification_report(df_flow["collected_label"], df_flow["predicted_class"], zero_division=0))

    # --- 2. Evaluate DNS Model ---
    print(f"\n[*] Evaluating DNS Model on {len(df_dns)} entirely unseen flows...")
    dns_model = xgb.XGBClassifier()
    dns_model.load_model(MODELS_DIR / "dns_model.json")
    dns_le = joblib.load(MODELS_DIR / "dns_label_encoder.pkl")
    dns_vec = joblib.load(MODELS_DIR / "dns_vectorizer.pkl")

    # The dns dataset generator creates nested json; we need to flatten `dns_meta` to match what extract_dns_features expects: `domain` column.
    df_dns["domain"] = df_dns["dns_meta"].apply(lambda x: x["query_name"])
    
    X_dns, _ = extract_dns_features(df_dns, dns_vec)
    dns_preds = dns_model.predict(X_dns)
    df_dns["predicted_class"] = dns_le.inverse_transform(dns_preds)
    
    print(classification_report(df_dns["collected_label"], df_dns["predicted_class"], zero_division=0))

if __name__ == "__main__":
    main()
