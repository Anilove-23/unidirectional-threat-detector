"""
tests/unit/test_discard.py
===========================
Unit tests for the ACK/response frame discard logic.

Tests use Scapy to craft real packet objects — no mocking.
Each test validates one specific discard rule.

Run with:  pytest tests/unit/test_discard.py -v
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

import pytest
from scapy.all import IP, IPv6, TCP, UDP, ICMP, ARP, Ether, Raw
from processing.discard import should_discard, discard_reason


# ══════════════════════════════════════════════════════════════════════
# Helpers
# ══════════════════════════════════════════════════════════════════════

def make_tcp(flags: int, payload: bytes = b"") -> IP:
    pkt = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(flags=flags, sport=12345, dport=80)
    if payload:
        pkt = pkt / Raw(payload)
    return pkt


# ══════════════════════════════════════════════════════════════════════
# Rule 1: ARP
# ══════════════════════════════════════════════════════════════════════

def test_arp_is_discarded():
    """ARP packets must always be dropped — NIC has no IP address."""
    pkt = Ether() / ARP()
    assert should_discard(pkt) is True


# ══════════════════════════════════════════════════════════════════════
# Rule 2: Non-IP
# ══════════════════════════════════════════════════════════════════════

def test_non_ip_frame_is_discarded():
    """Frames without an IP layer must be dropped."""
    pkt = Ether()   # pure ethernet, no IP
    assert should_discard(pkt) is True


# ══════════════════════════════════════════════════════════════════════
# Rule 3a: Pure TCP ACK
# ══════════════════════════════════════════════════════════════════════

def test_pure_ack_is_discarded():
    """ACK=1, no SYN, no FIN, no PSH, no payload → discard."""
    pkt = make_tcp(flags=0x10)   # ACK only
    assert should_discard(pkt) is True


def test_pure_ack_reason():
    pkt = make_tcp(flags=0x10)
    assert discard_reason(pkt) == "PURE_TCP_ACK"


# ══════════════════════════════════════════════════════════════════════
# Preserved packets (must NOT be discarded)
# ══════════════════════════════════════════════════════════════════════

def test_syn_is_kept():
    """TCP SYN (ACK=0) must pass — core DDoS observation."""
    pkt = make_tcp(flags=0x02)   # SYN only
    assert should_discard(pkt) is False


def test_syn_ack_is_kept():
    """SYN+ACK is a valid observed handshake from the monitored side."""
    pkt = make_tcp(flags=0x12)   # SYN + ACK
    assert should_discard(pkt) is False


def test_syn_flood_packet_is_kept():
    """
    hping3 --syn --flood packet: SYN=1, ACK=0, no payload.
    MUST pass through — this is the DDoS signal.
    Rule 3a only drops ACK=1 packets.
    """
    pkt = make_tcp(flags=0x02)   # bare SYN — exactly what hping3 sends
    assert should_discard(pkt) is False, (
        "SYN-flood packet was incorrectly discarded! "
        "This would make DDoS detection impossible."
    )


def test_psh_ack_with_data_is_kept():
    """PSH+ACK with payload is data transfer — must pass."""
    pkt = make_tcp(flags=0x18, payload=b"GET / HTTP/1.1\r\n")  # PSH + ACK + data
    assert should_discard(pkt) is False


def test_fin_ack_is_kept():
    """FIN+ACK signals flow close — must pass so assembler can emit the FlowObject."""
    pkt = make_tcp(flags=0x11)   # FIN + ACK
    assert should_discard(pkt) is False


def test_udp_dns_is_kept():
    """UDP DNS queries must pass — core for DGA/tunnel detection."""
    pkt = IP(src="10.0.0.1", dst="8.8.8.8") / UDP(sport=12345, dport=53)
    assert should_discard(pkt) is False


def test_icmp_echo_request_is_kept():
    """ICMP Echo Request (type 8) is an observed ping — must pass."""
    pkt = IP(src="10.0.0.1", dst="10.0.0.2") / ICMP(type=8)
    assert should_discard(pkt) is False


# ══════════════════════════════════════════════════════════════════════
# Rule 3b: TCP RST
# ══════════════════════════════════════════════════════════════════════

def test_rst_is_discarded():
    """RST implies OS generated a reset — drop defensively."""
    pkt = make_tcp(flags=0x04)   # RST
    assert should_discard(pkt) is True


def test_rst_ack_is_discarded():
    """RST+ACK is also a reset response."""
    pkt = make_tcp(flags=0x14)   # RST + ACK
    assert should_discard(pkt) is True


# ══════════════════════════════════════════════════════════════════════
# Rule 4 & 5: ICMP responses
# ══════════════════════════════════════════════════════════════════════

def test_icmp_echo_reply_is_discarded():
    """ICMP Echo Reply (type 0) implies we sent a ping — drop."""
    pkt = IP(src="8.8.8.8", dst="10.0.0.1") / ICMP(type=0, code=0)
    assert should_discard(pkt) is True


def test_icmp_dest_unreachable_is_discarded():
    """ICMP type 3 = response to an outbound attempt — drop."""
    pkt = IP(src="10.0.0.2", dst="10.0.0.1") / ICMP(type=3, code=1)
    assert should_discard(pkt) is True


def test_icmp_time_exceeded_is_discarded():
    """ICMP type 11 = traceroute response — drop."""
    pkt = IP(src="10.0.0.2", dst="10.0.0.1") / ICMP(type=11, code=0)
    assert should_discard(pkt) is True


# ══════════════════════════════════════════════════════════════════════
# Edge cases
# ══════════════════════════════════════════════════════════════════════

def test_ack_with_data_is_kept():
    """ACK=1 but with PSH and a data payload — this is real traffic."""
    pkt = make_tcp(flags=0x18, payload=b"some data")   # PSH+ACK
    assert should_discard(pkt) is False


def test_fin_only_is_kept():
    """Bare FIN (no ACK) should pass — flow termination observation."""
    pkt = make_tcp(flags=0x01)   # FIN only
    assert should_discard(pkt) is False


def test_ipv6_tcp_syn_is_kept():
    """IPv6 TCP SYN must pass — same rules apply to IPv6."""
    pkt = IPv6(src="::1", dst="::2") / TCP(flags=0x02, sport=12345, dport=443)
    assert should_discard(pkt) is False
