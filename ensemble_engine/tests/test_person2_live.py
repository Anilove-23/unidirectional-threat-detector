import json
import redis
import sys
import time
from pathlib import Path
import threading
import subprocess

# Add ensemble_engine/scripts to path to import infer
sys.path.insert(0, str(Path(__file__).resolve().parent / "ensemble_engine" / "scripts"))
from infer import anomaly_score, beacon_likelihood

def listen_and_score(duration=40):
    r = redis.Redis(host="127.0.0.1", port=6379, decode_responses=True)
    pubsub = r.pubsub()
    pubsub.subscribe("flow.raw")
    
    print("[*] Listening on flow.raw for generated traffic...")
    
    start_time = time.time()
    
    results = []
    
    for message in pubsub.listen():
        if time.time() - start_time > duration:
            break
            
        if message["type"] == "message":
            try:
                flow_obj = json.loads(message["data"])
            except json.JSONDecodeError:
                continue
                
            # Exclude redis loopback noise
            src_port = flow_obj.get("five_tuple", {}).get("src_port")
            dst_port = flow_obj.get("five_tuple", {}).get("dst_port")
            if src_port == 6379 or dst_port == 6379:
                continue
                
            a_score = anomaly_score(flow_obj)
            b_score = beacon_likelihood(flow_obj)
            
            print(f"[+] Flow {src_port}->{dst_port} | Anomaly: {a_score:.4f} | Beacon: {b_score:.4f}")
            results.append({
                "flow": f"{src_port}->{dst_port}",
                "anomaly": a_score,
                "beacon": b_score
            })
            
    print(f"[*] Done. Scored {len(results)} flows.")

def main():
    # Start SIMULATION mode in ingestion
    print("[*] Starting main.py SIMULATION mode...")
    ingest_proc = subprocess.Popen(
        [sys.executable, "ingestion/main.py"], 
        stdin=subprocess.PIPE, 
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
        cwd=str(Path(__file__).resolve().parent)
    )
    # Send '2' to select SIMULATION mode
    ingest_proc.stdin.write("2\n")
    ingest_proc.stdin.flush()
    time.sleep(3) # Wait for it to initialize
    
    # Start the subscriber thread
    t = threading.Thread(target=listen_and_score, args=(40,))
    t.start()
    
    # Run benign generator
    print("[*] Generating BENIGN traffic...")
    subprocess.run([sys.executable, "ingestion/dataset/generators/benign_gen.py", "--target", "127.0.0.1", "--duration", "15"])
    
    # Run beacon generator
    print("[*] Generating C2 BEACON traffic...")
    subprocess.run([sys.executable, "ingestion/dataset/generators/c2_beacon_gen.py", "--target", "127.0.0.1", "--duration", "15", "--interval", "2"])
    
    t.join()
    
    # Kill ingestion
    ingest_proc.terminate()
    print("[*] Test complete.")

if __name__ == "__main__":
    main()
