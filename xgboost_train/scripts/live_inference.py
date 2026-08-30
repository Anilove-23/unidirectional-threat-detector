"""
scripts/live_inference.py
=========================
Person 1 — Supervised Feature Analytics Engineer

Bridge script that subscribes to the Redis 'flow.raw' channel (populated by Person 3),
ingests the live JSON FlowObjects, extracts features in real-time, and outputs 
soft probabilities using the trained XGBoost models (Model A for flow stats, Model B for DNS).

Usage:
  uv run python xgboost_train/scripts/live_inference.py
"""

import json
import redis
import sys
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

# Make scripts directory importable
SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))

# Use the infer.py helpers which handle all model/vectorizer/encoder loading
# and cleanly wrap the extract_flow_features / extract_dns_features calls.
from infer import predict_flow_proba, predict_dns_proba

def main():
    print("[*] Initialising XGBoost inference engine...")
    
    # Connect to Person 3's Redis queue
    try:
        r = redis.Redis(host='127.0.0.1', port=6379, decode_responses=True)
        r.ping()
        print("[+] Redis connection successful.")
    except redis.ConnectionError:
        print("[-] Could not connect to Redis on 127.0.0.1:6379. Make sure Redis is running.")
        sys.exit(1)
        
    pubsub = r.pubsub()
    pubsub.subscribe('flow.raw')

    print("[*] Person 1 Inference Engine listening on 'flow.raw'...")

    # The Live Loop
    try:
        for message in pubsub.listen():
            if message['type'] == 'message':
                flow_obj = json.loads(message['data'])
                
                print(f"\n[+] Received FlowObject ID: {flow_obj.get('flow_id')}")
                
                # 1. Model A: Score network flow stats
                flow_prob_dict = predict_flow_proba(flow_obj)
                print(f"[*] Flow Scored (Model A): {json.dumps(flow_prob_dict)}")
                
                # 2. Model B: Score DNS lexical features if present
                dns_prob_dict = None
                dns_meta = flow_obj.get("dns_meta")
                if dns_meta and dns_meta.get("query_name"):
                    query = dns_meta["query_name"]
                    dns_prob_dict = predict_dns_proba(query)
                    print(f"[*] DNS Scored (Model B) for '{query}': {json.dumps(dns_prob_dict)}")
                
                # Save output to a persistent log file
                log_entry = {
                    "flow_id": flow_obj.get("flow_id"),
                    "timestamp": flow_obj.get("last_seen"),
                    "model_a_flow_probs": flow_prob_dict,
                    "model_b_dns_probs": dns_prob_dict
                }
                
                results_dir = SCRIPTS_DIR.parent / "results"
                results_dir.mkdir(parents=True, exist_ok=True)
                with open(results_dir / "live_inference.jsonl", "a", encoding="utf-8") as f:
                    f.write(json.dumps(log_entry) + "\n")
                
                # Next: Hand these prob_dicts to Person 2!
                
    except KeyboardInterrupt:
        print("\n[*] Stopping Inference Engine.")

if __name__ == "__main__":
    main()
