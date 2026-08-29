"""
dataset/generators/dga_gen.py
==============================
Domain Generation Algorithm (DGA) traffic generator.

Implements two real DGA families and makes DNS queries for the generated
domains. The queries appear on the wire even if they NXDOMAIN-fail —
that's the observable signal. NXDOMAIN failures are expected and normal.

Families:
  conficker  — arithmetic seed from date, 8–11 random lowercase chars + TLD
  cryptolocker — 2 dictionary words + 2–4 random digits + unusual TLD

Usage:
  python dga_gen.py --family conficker --count 200 --duration 60
"""
import argparse
import datetime
import hashlib
import random
import socket
import sys
import time


# ── DGA Implementations ───────────────────────────────────────────────────────

CONFICKER_TLDS = [".com", ".net", ".org", ".info", ".biz", ".name", ".mobi"]
CONFICKER_CHARS = "abcdefghijklmnopqrstuvwxyz"

def conficker_dga(seed_date: datetime.date = None, count: int = 250) -> list[str]:
    """
    Simplified Conficker-variant DGA.
    Uses date-based seed to generate pseudo-random domain names.
    """
    if seed_date is None:
        seed_date = datetime.date.today()

    seed = (seed_date.year * seed_date.month * seed_date.day) % (2**31)
    domains = []

    for _ in range(count):
        seed = (seed * 214013 + 2531011) & 0x7FFFFFFF   # LCG
        length = 8 + (seed % 4)                          # 8–11 chars
        name   = ""
        for _ in range(length):
            seed   = (seed * 214013 + 2531011) & 0x7FFFFFFF
            name  += CONFICKER_CHARS[seed % 26]
        tld  = CONFICKER_TLDS[seed % len(CONFICKER_TLDS)]
        domains.append(name + tld)

    return domains


CRYPTO_WORDS = [
    "sun", "moon", "cloud", "bridge", "mirror", "shadow", "storm", "wind",
    "fire", "stone", "iron", "silver", "golden", "black", "blue", "red",
    "fast", "slow", "deep", "high", "cold", "warm", "sharp", "soft",
]
CRYPTO_TLDS = [".ru", ".biz", ".info", ".cc", ".pw", ".top", ".xyz"]

def cryptolocker_dga(seed: int = None, count: int = 250) -> list[str]:
    """
    Simplified Cryptolocker-variant DGA.
    Concatenates two dictionary words + 2–4 random digits.
    """
    rng = random.Random(seed or int(time.time()))
    domains = []
    for _ in range(count):
        word1  = rng.choice(CRYPTO_WORDS)
        word2  = rng.choice(CRYPTO_WORDS)
        digits = "".join(str(rng.randint(0, 9)) for _ in range(rng.randint(2, 4)))
        tld    = rng.choice(CRYPTO_TLDS)
        domains.append(f"{word1}{word2}{digits}{tld}")
    return domains


# ── DNS Query Sender ──────────────────────────────────────────────────────────

def send_dns_queries(domains: list[str], delay_s: float = 0.5):
    """
    Make DNS queries for each domain.
    NXDOMAIN / connection refused is expected and ignored.
    The query itself is the observable signal on the wire.
    """
    for domain in domains:
        try:
            socket.getaddrinfo(domain, None, socket.AF_INET)
        except (socket.gaierror, OSError):
            pass   # NXDOMAIN or unreachable — expected
        print(f"[dga_gen] Queried: {domain}")
        time.sleep(delay_s)


def run(family: str, count: int, duration: int, delay: float):
    print(f"[dga_gen] Family   : {family}")
    print(f"[dga_gen] Count    : {count} domains")
    print(f"[dga_gen] Duration : {duration}s")
    print(f"[dga_gen] Delay    : {delay}s between queries")

    start = time.time()

    if family == "conficker":
        domains = conficker_dga(count=count)
    elif family == "cryptolocker":
        domains = cryptolocker_dga(count=count)
    elif family == "all":
        domains  = conficker_dga(count=count // 2)
        domains += cryptolocker_dga(count=count // 2)
        random.shuffle(domains)
    else:
        print(f"[dga_gen] ERROR: Unknown family: {family}")
        sys.exit(1)

    # Cap to duration
    while time.time() - start < duration and domains:
        send_dns_queries(domains[:10], delay_s=delay)
        domains = domains[10:]
        if not domains:
            # Regenerate with new seed
            domains = conficker_dga(count=count) if family == "conficker" \
                      else cryptolocker_dga(count=count)

    print(f"[dga_gen] Done — elapsed {time.time()-start:.0f}s")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DGA domain generator for SIH26145 dataset")
    parser.add_argument("--family",   default="all",
                        choices=["conficker", "cryptolocker", "all"], help="DGA family")
    parser.add_argument("--count",    type=int,   default=200,  help="Domains to generate")
    parser.add_argument("--duration", type=int,   default=60,   help="Max run duration (seconds)")
    parser.add_argument("--delay",    type=float, default=0.3,  help="Seconds between queries")
    parser.add_argument("--target",   default="", help="(Unused — DNS goes to system resolver)")
    args = parser.parse_args()

    try:
        run(args.family, args.count, args.duration, args.delay)
    except KeyboardInterrupt:
        print("\n[dga_gen] Stopped by user.")
