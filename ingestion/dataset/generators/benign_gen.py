"""
dataset/generators/benign_gen.py
==================================
Generates normal (benign) baseline traffic using iperf3.
Also does HTTP/HTTPS requests to well-known public endpoints.

Usage:
  python benign_gen.py --target 192.168.1.10 --duration 60
"""
import argparse
import subprocess
import sys
import threading
import time
import urllib.request


def iperf3_tcp(target: str, duration: int, bandwidth: str = "10M"):
    print(f"[benign] iperf3 TCP → {target}  bw={bandwidth}  dur={duration}s")
    try:
        subprocess.run(
            ["iperf3", "-c", target, "-t", str(duration), "-b", bandwidth],
            timeout=duration + 10,
        )
    except FileNotFoundError:
        print("[benign] iperf3 not found. Install: sudo apt install iperf3")
    except subprocess.TimeoutExpired:
        pass


def iperf3_udp(target: str, duration: int, bandwidth: str = "5M"):
    print(f"[benign] iperf3 UDP → {target}  bw={bandwidth}  dur={duration}s")
    try:
        subprocess.run(
            ["iperf3", "-c", target, "-u", "-t", str(duration), "-b", bandwidth],
            timeout=duration + 10,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass


def http_traffic(duration: int):
    """Make periodic HTTP/HTTPS requests to simulate normal web browsing."""
    urls = [
        "http://httpbin.org/get",
        "https://httpbin.org/get",
        "http://example.com",
    ]
    start = time.time()
    count = 0
    while time.time() - start < duration:
        url = urls[count % len(urls)]
        try:
            with urllib.request.urlopen(url, timeout=5) as resp:
                _ = resp.read(1024)
            print(f"[benign] HTTP {url} → {resp.status}")
        except Exception as e:
            print(f"[benign] HTTP {url} failed: {e}")
        count += 1
        time.sleep(2)


def run(target: str, duration: int):
    print(f"[benign] Generating normal traffic to {target} for {duration}s")
    threads = [
        threading.Thread(target=iperf3_tcp, args=(target, duration), daemon=True),
        threading.Thread(target=iperf3_udp, args=(target, duration), daemon=True),
        threading.Thread(target=http_traffic, args=(duration,),       daemon=True),
    ]
    for t in threads:
        t.start()
    time.sleep(duration)
    print("[benign] Done.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--target",   required=True)
    parser.add_argument("--duration", type=int, default=60)
    args = parser.parse_args()
    try:
        run(args.target, args.duration)
    except KeyboardInterrupt:
        print("\n[benign] Stopped.")
