"""
xgboost_train/scripts/test_p1_on_raw_flows.py
=============================================
Evaluates the newly trained XGBoost models against `ensemble_engine/data/raw_flows.jsonl`,
which contains 703 real flows captured from the live ingestion pipeline simulation.
"""

import sys
import json
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

import pandas as pd
import xgboost as xgb
import joblib
from sklearn.metrics import classification_report
from features import extract_flow_features, extract_dns_features

ROOT = Path(__file__).resolve().parent.parent
MODELS_DIR = ROOT / "models"
RAW_FLOWS_FILE = Path(__file__).resolve().parents[2] / "ensemble_engine" / "data" / "raw_flows.jsonl"

def main():
    if not RAW_FLOWS_FILE.exists():
        print(f"[!] File not found: {RAW_FLOWS_FILE}")
        sys.exit(1)

    print(f"[*] Loading real simulation data from: {RAW_FLOWS_FILE.name}")
    df = pd.read_json(RAW_FLOWS_FILE, lines=True)
    print(f"[*] Total flows loaded: {len(df)}")
    
    # We only want to evaluate classes that Person 1 is responsible for.
    # Person 1 handles: BENIGN, VOLUMETRIC_DDOS, PORT_SCAN, DATA_EXFILTRATION, DGA, DNS_TUNNELING
    # The raw_flows dataset might have classes like "C2_BEACON" (Person 2's domain).
    
    # Let's map DDOS to VOLUMETRIC_DDOS and DNS_TUNNEL to DNS_TUNNELING 
    label_map = {
        "BENIGN": "BENIGN",
        "VOLUMETRIC_DDOS": "VOLUMETRIC_DDOS",
        "PORT_SCAN": "PORT_SCAN",
        "DATA_EXFILTRATION": "DATA_EXFILTRATION",
        "DGA": "DGA",
        "DNS_TUNNELING": "DNS_TUNNELING",
    }
    
    df["true_class"] = df["collected_label"].map(label_map)
    df_eval = df[df["true_class"].notnull()].copy()
    print(f"[*] Flows within Person 1's scope: {len(df_eval)}")

    df_dns = df_eval[df_eval["dns_meta"].notnull()].copy()
    df_flow = df_eval[df_eval["dns_meta"].isnull()].copy()

    # --- 1. Evaluate Flow Model ---
    if len(df_flow) > 0:
        print(f"\n[*] Evaluating Flow Model on {len(df_flow)} flows...")
        flow_model = xgb.XGBClassifier()
        flow_model.load_model(MODELS_DIR / "flow_model.json")
        flow_le = joblib.load(MODELS_DIR / "flow_label_encoder.pkl")
        
        X_flow = extract_flow_features(df_flow)
        train_cols = json.loads((MODELS_DIR / "flow_feature_columns.json").read_text(encoding="utf-8"))
        X_flow = X_flow.reindex(columns=train_cols, fill_value=0)
        
        flow_preds = flow_model.predict(X_flow)
        df_flow["predicted_class"] = flow_le.inverse_transform(flow_preds)
        
        print(classification_report(df_flow["true_class"], df_flow["predicted_class"], zero_division=0))
    else:
        print("\n[*] No Flow (TCP/ICMP) records found in this subset.")

    # --- 2. Evaluate DNS Model ---
    if len(df_dns) > 0:
        print(f"\n[*] Evaluating DNS Model on {len(df_dns)} flows...")
        dns_model = xgb.XGBClassifier()
        dns_model.load_model(MODELS_DIR / "dns_model.json")
        dns_le = joblib.load(MODELS_DIR / "dns_label_encoder.pkl")
        dns_vec = joblib.load(MODELS_DIR / "dns_vectorizer.pkl")

        df_dns["domain"] = df_dns["dns_meta"].apply(lambda x: x.get("query_name", ""))
        
        X_dns, _ = extract_dns_features(df_dns, dns_vec)
        dns_preds = dns_model.predict(X_dns)
        df_dns["predicted_class"] = dns_le.inverse_transform(dns_preds)
        
        print(classification_report(df_dns["true_class"], df_dns["predicted_class"], zero_division=0))
    else:
        print("\n[*] No DNS records found in this subset.")

if __name__ == "__main__":
    main()
