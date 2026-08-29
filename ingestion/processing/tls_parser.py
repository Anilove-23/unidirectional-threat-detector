"""
processing/tls_parser.py
========================
Builds JA3 raw strings and computes JA3 fingerprints from
TLS ClientHello field data supplied by tshark_extractor.py.

JA3 algorithm:
  raw = "{tls_version},{cipher_suites},{extensions},{ec_curves},{ec_point_formats}"
  fingerprint = MD5(raw)

All values are comma-separated integers (decimal), dash-separated between groups.
GREASE values (RFC 8701) are filtered out before hashing.

Reference: https://github.com/salesforce/ja3
"""
from __future__ import annotations
import hashlib
from typing import List, Optional

# GREASE values to filter out (RFC 8701)
# These are placeholder values browsers insert to test server tolerance.
# Filtering them gives a stable fingerprint regardless of browser.
GREASE_VALUES = {
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a,
    0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa,
}


def _parse_hex_list(hex_list: List[str]) -> List[int]:
    """Convert list of hex strings like ['0x1301', '0x1302'] → [4865, 4866]."""
    result = []
    for item in (hex_list or []):
        item = item.strip()
        if not item:
            continue
        try:
            val = int(item, 16) if item.startswith("0x") else int(item)
            result.append(val)
        except ValueError:
            continue
    return result


def _filter_grease(values: List[int]) -> List[int]:
    return [v for v in values if v not in GREASE_VALUES]


def build_ja3_raw(
    tls_version:   Optional[str],
    cipher_suites: Optional[List[str]],
    extensions:    Optional[List[str]],
    ec_curves:     Optional[List[str]],
    ec_point_fmts: Optional[List[str]] = None,
) -> str:
    """
    Build the raw JA3 string from tshark-extracted TLS ClientHello fields.

    tls_version:   e.g. "0x0303" (TLS 1.2) or "0x0304" (TLS 1.3)
    cipher_suites: ordered list of hex strings (order matters — it's a fingerprint signal)
    extensions:    ordered list of extension type numbers as hex strings
    ec_curves:     supported groups / elliptic curves
    ec_point_fmts: EC point format list (often just [0])
    """
    # ── TLS version (decimal integer) ─────────────────────────────────────────
    version_int = 0
    if tls_version:
        try:
            version_int = int(tls_version, 16) if tls_version.startswith("0x") else int(tls_version)
        except ValueError:
            pass

    # ── Cipher suites (filter GREASE, keep order) ─────────────────────────────
    ciphers = _filter_grease(_parse_hex_list(cipher_suites or []))

    # ── Extensions (filter GREASE, keep order) ────────────────────────────────
    exts = _filter_grease(_parse_hex_list(extensions or []))

    # ── EC Curves (filter GREASE) ──────────────────────────────────────────────
    curves = _filter_grease(_parse_hex_list(ec_curves or []))

    # ── EC Point formats ──────────────────────────────────────────────────────
    point_fmts = _parse_hex_list(ec_point_fmts or [])

    raw = (
        f"{version_int},"
        f"{'-'.join(str(c) for c in ciphers)},"
        f"{'-'.join(str(e) for e in exts)},"
        f"{'-'.join(str(c) for c in curves)},"
        f"{'-'.join(str(p) for p in point_fmts)}"
    )
    return raw


def compute_ja3(raw_string: str) -> str:
    """Return the MD5 hash (hex digest) of the JA3 raw string."""
    return hashlib.md5(raw_string.encode("utf-8")).hexdigest()


def build_ja3_fingerprint(
    tls_version:   Optional[str],
    cipher_suites: Optional[List[str]],
    extensions:    Optional[List[str]],
    ec_curves:     Optional[List[str]],
    ec_point_fmts: Optional[List[str]] = None,
) -> tuple[str, str]:
    """
    Returns (ja3_raw_string, ja3_fingerprint).
    Convenience wrapper used by TsharkExtractor.
    """
    raw = build_ja3_raw(tls_version, cipher_suites, extensions, ec_curves, ec_point_fmts)
    fingerprint = compute_ja3(raw)
    return raw, fingerprint
