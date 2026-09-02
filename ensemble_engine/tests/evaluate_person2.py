import json
import sys
from pathlib import Path
from collections import defaultdict

# Add ensemble_engine/scripts to path to import infer
sys.path.insert(0, str(Path(__file__).resolve().parent / "ensemble_engine" / "scripts"))
from infer import anomaly_score, beacon_likelihood

def evaluate():
    data_file = Path("ensemble_engine/data/raw_flows.jsonl")
    if not data_file.exists():
        print(f"[-] Data file {data_file} not found.")
        return
        
    print(f"[*] Evaluating Person 2 Models on {data_file}")
    
    # Track metrics per label
    stats = defaultdict(lambda: {"count": 0, "anomaly_sum": 0, "beacon_sum": 0, "beacon_alerts": 0, "anomaly_alerts": 0})
    
    with open(data_file, "r") as f:
        for line in f:
            try:
                flow_obj = json.loads(line)
            except json.JSONDecodeError:
                continue
                
            label = flow_obj.get("collected_label", "UNKNOWN")
            
            a_score = anomaly_score(flow_obj)
            b_score = beacon_likelihood(flow_obj)
            
            stats[label]["count"] += 1
            stats[label]["anomaly_sum"] += a_score
            stats[label]["beacon_sum"] += b_score
            
            if b_score > 0.8:
                stats[label]["beacon_alerts"] += 1
            if a_score > 0.8:
                stats[label]["anomaly_alerts"] += 1

    print("\n" + "="*80)
    print(f"{'THREAT CLASS':<25} | {'COUNT':<8} | {'AVG ANOMALY':<12} | {'AVG BEACON':<12} | {'BEACON ALERTS':<15}")
    print("="*80)
    for label, metrics in stats.items():
        count = metrics["count"]
        avg_a = metrics["anomaly_sum"] / count
        avg_b = metrics["beacon_sum"] / count
        b_alerts = metrics["beacon_alerts"]
        a_alerts = metrics["anomaly_alerts"]
        print(f"{label:<25} | {count:<8} | {avg_a:<12.4f} | {avg_b:<12.4f} | {b_alerts:<15}")
    print("="*80)

if __name__ == "__main__":
    evaluate()
