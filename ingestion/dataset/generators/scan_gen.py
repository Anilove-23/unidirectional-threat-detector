"""
dataset/generators/scan_gen.py
================================
Port scan traffic generator using hping3.
Simulates sequential TCP SYN sweeps across ports.

Usage:
  python scan_gen.py --target 192.168.1.10 --duration 60 --sub sequential
"""
import argparse
import subprocess
import sys
import time

SCENARIOS = {
    "sequential": {
        "cmd": lambda t, start, end: [
            "hping3", "--syn", "-p", f"++{start}", "--count", str(end - start),
            "-i", "u500", t
        ],
        "desc": "Sequential SYN sweep port 1–1024 (1 pkt per 500µs)",
    },
    "full": {
        "cmd": lambda t, start, end: [
            "hping3", "--syn", "-p", "++1", "--count", "65535", "-i", "u200", t
        ],
        "desc": "Full port sweep 1–65535",
    },
    "common_ports": {
        "cmd": lambda t, start, end: [
            "hping3", "--syn", "-p", "80", "--count", "1", t,
        ],
        "desc": "Common service ports only (80,443,22,21,3306,...)",
    },
}


def run(target: str, duration: int, sub: str):
    if sub not in SCENARIOS:
        print(f"[scan_gen] ERROR: Unknown sub: {sub}")
        sys.exit(1)

    s = SCENARIOS[sub]
    cmd = s["cmd"](target, 1, 1024)
    print(f"[scan_gen] Scenario : {sub} — {s['desc']}")
    print(f"[scan_gen] Target   : {target}")
    print(f"[scan_gen] Duration : {duration}s")
    print(f"[scan_gen] Command  : {' '.join(cmd)}")

    try:
        proc = subprocess.Popen(cmd)
        time.sleep(duration)
        proc.terminate()
        proc.wait(timeout=5)
    except FileNotFoundError:
        print("[scan_gen] ERROR: hping3 not found. Install: sudo apt install hping3")
        sys.exit(1)
    except KeyboardInterrupt:
        proc.terminate()

    print(f"[scan_gen] Done.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--target",   required=True)
    parser.add_argument("--duration", type=int, default=60)
    parser.add_argument("--sub",      default="sequential", choices=list(SCENARIOS))
    args = parser.parse_args()
    run(args.target, args.duration, args.sub)
