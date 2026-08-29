"""
processing/discard.py
=====================
ACK / Response Frame Discard Logic
====================================
★ MOST SECURITY-CRITICAL FILE IN THIS CODEBASE ★

Every downstream component (Person 1, 2, 4, and the dashboard) trusts that
whatever arrives on flow.raw has already passed this gate. A missed discard
(false negative) would let a response/ACK frame imply two-way communication,
breaking the core NTRO data-diode guarantee.

Design principle: CONSERVATIVE — when in doubt, discard.
  - False positive (discarding a valid observation) = acceptable
  - False negative (passing an ACK/response)        = security violation

All checks are fast bitfield operations with NO:
  - DNS lookups
  - state table lookups
  - blocking I/O
"""
from __future__ import annotations
import structlog

log = structlog.get_logger()

# Lazy imports so this module loads even without Scapy (e.g. during unit tests
# that mock packets as simple objects)
try:
    from scapy.all import IP, IPv6, TCP, UDP, ICMP, ARP
    from scapy.layers.inet6 import ICMPv6DestUnreach
    _SCAPY_AVAILABLE = True
except ImportError:
    _SCAPY_AVAILABLE = False


# TCP flag bitmasks
_SYN = 0x02
_RST = 0x04
_FIN = 0x01
_ACK = 0x10
_PSH = 0x08
_URG = 0x20


def should_discard(pkt) -> bool:
    """
    Returns True  → packet is silently dropped before FlowAssembler sees it.
    Returns False → packet is a valid one-way observation, pass to assembler.

    Called once per packet in the hot path. Must be fast.
    """
    try:
        # ── Rule 1: ARP ───────────────────────────────────────────────────────
        # Capture NIC has no IP address. ARP is irrelevant and could
        # theoretically trigger a reply from a buggy driver.
        if _has_layer(pkt, "ARP"):
            return True

        # ── Rule 2: Must have an IP layer ─────────────────────────────────────
        has_ip  = _has_layer(pkt, "IP")
        has_ip6 = _has_layer(pkt, "IPv6")
        if not (has_ip or has_ip6):
            return True

        # ── Rule 3: TCP analysis ──────────────────────────────────────────────
        if _has_layer(pkt, "TCP"):
            tcp   = pkt["TCP"] if _SCAPY_AVAILABLE else pkt.tcp
            flags = int(tcp.flags)

            # 3a. Pure ACK — ACK set, no payload, no SYN, no FIN, no PSH
            #     This is a TCP acknowledgement only — not an observation.
            #
            #     ⚠️  IMPORTANT: A bare SYN (ACK=0, no payload) is NOT a pure ACK.
            #         hping3 --syn --flood packets are SYN only.
            #         They MUST pass through so DDoS detection works.
            is_pure_ack = (
                bool(flags & _ACK)       and
                not bool(flags & _SYN)   and
                not bool(flags & _RST)   and
                not bool(flags & _FIN)   and
                not bool(flags & _PSH)   and
                _payload_len(tcp) == 0
            )
            if is_pure_ack:
                return True

            # 3b. RST — implies OS generated a TCP reset.
            #     Shouldn't happen on a purely RX-only NIC but discard defensively.
            #     Log a WARNING so ops can investigate.
            if flags & _RST:
                src = _src_ip(pkt)
                dst = _dst_ip(pkt)
                log.warning(
                    "rst_frame_observed",
                    msg="TCP RST seen — possible OS-generated response on capture NIC",
                    src=src, dst=dst,
                )
                return True

        # ── Rule 4: ICMP ──────────────────────────────────────────────────────
        if _has_layer(pkt, "ICMP"):
            icmp_type = int(pkt["ICMP"].type) if _SCAPY_AVAILABLE else pkt.icmp.type

            # Echo Reply (0) — implies we sent an Echo Request
            if icmp_type == 0:
                return True
            # Destination Unreachable (3) — response to an outbound attempt
            if icmp_type == 3:
                return True
            # Time Exceeded (11) — response to traceroute from this enclave
            if icmp_type == 11:
                return True
            # Redirect (5) — router telling us to use a different path
            if icmp_type == 5:
                return True

        # ── Rule 5: ICMPv6 Destination Unreachable ────────────────────────────
        if _SCAPY_AVAILABLE and _has_layer(pkt, "ICMPv6DestUnreach"):
            return True

        # ── Packet survives — valid one-way observation ───────────────────────
        return False

    except Exception as e:
        # If we cannot parse the packet for any reason, discard conservatively.
        # Never let a malformed packet crash the capture loop.
        log.debug("discard_parse_error", error=str(e))
        return True


def discard_reason(pkt) -> str:
    """
    Debug helper. Returns a human-readable string explaining why a packet
    would be discarded.

    ⚠️  DO NOT call this in the production hot path — only use in tests or
        debug mode because it duplicates the discard logic less efficiently.
    """
    try:
        if _has_layer(pkt, "ARP"):
            return "ARP_NO_IP_ON_CAPTURE_NIC"
        if not (_has_layer(pkt, "IP") or _has_layer(pkt, "IPv6")):
            return "NO_IP_LAYER"
        if _has_layer(pkt, "TCP"):
            flags = int(pkt["TCP"].flags)
            if (
                bool(flags & _ACK) and not bool(flags & _SYN) and
                not bool(flags & _RST) and not bool(flags & _FIN) and
                not bool(flags & _PSH) and _payload_len(pkt["TCP"]) == 0
            ):
                return "PURE_TCP_ACK"
            if flags & _RST:
                return "TCP_RST"
        if _has_layer(pkt, "ICMP"):
            t = int(pkt["ICMP"].type)
            mapping = {0: "ICMP_ECHO_REPLY", 3: "ICMP_DEST_UNREACHABLE",
                       5: "ICMP_REDIRECT",   11: "ICMP_TIME_EXCEEDED"}
            if t in mapping:
                return mapping[t]
        return "PASSES_ALL_CHECKS"
    except Exception as e:
        return f"PARSE_ERROR:{e}"


# ── Private helpers ───────────────────────────────────────────────────────────

def _has_layer(pkt, layer_name: str) -> bool:
    """Works whether pkt is a real Scapy packet or a mock object in tests."""
    try:
        if _SCAPY_AVAILABLE:
            return pkt.haslayer(layer_name)
        return hasattr(pkt, layer_name.lower())
    except Exception:
        return False


def _payload_len(tcp_layer) -> int:
    try:
        return len(tcp_layer.payload)
    except Exception:
        return 0


def _src_ip(pkt) -> str:
    try:
        if _has_layer(pkt, "IP"):
            return pkt["IP"].src
        if _has_layer(pkt, "IPv6"):
            return pkt["IPv6"].src
    except Exception:
        pass
    return "unknown"


def _dst_ip(pkt) -> str:
    try:
        if _has_layer(pkt, "IP"):
            return pkt["IP"].dst
        if _has_layer(pkt, "IPv6"):
            return pkt["IPv6"].dst
    except Exception:
        pass
    return "unknown"
