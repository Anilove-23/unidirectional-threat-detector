# Discard Logic Reference
## SIH26145 — processing/discard.py
### The Most Security-Critical File in This Codebase

---

## Purpose

Every downstream component (Person 1, Person 2, Person 4, the dashboard)
trusts that whatever arrives on `flow.raw` is a valid one-way observation.

This file is the only gate between raw captured frames and the pipeline.

**A false negative (passing an ACK/response) = NTRO security invariant violation.**
**A false positive (dropping a valid observation) = reduced detection accuracy (acceptable).**

---

## Discard Rules (applied in order)

### Rule 1: ARP
Drop all ARP packets.
Reason: The capture NIC has no IP address. ARP is irrelevant and could
        trigger a response from a buggy driver.

### Rule 2: Non-IP frames
Drop if no IP or IPv6 layer is present.
Reason: We only analyse IP flows.

### Rule 3a: Pure TCP ACK
Drop if: ACK=1, SYN=0, RST=0, FIN=0, PSH=0, payload_length=0
Reason: This is a pure TCP acknowledgement — not an observation of monitored traffic.

CRITICAL EDGE CASE: A bare TCP SYN (SYN=1, ACK=0, no payload) is NOT a pure ACK.
hping3 --syn --flood sends exactly this. It MUST pass through.
Rule 3a only triggers when ACK=1.

### Rule 3b: TCP RST
Drop all TCP RST frames.
Reason: RST implies the OS generated a reset — should not happen on RX-only NIC.
        Also log a WARNING when this is seen (indicates possible misconfiguration).

### Rule 4: ICMP Echo Reply (type 0)
Drop ICMP type 0.
Reason: Echo Reply means we sent an Echo Request (a ping). Impossible on RX-only NIC.

### Rule 5: ICMP Destination Unreachable (type 3)
Drop ICMP type 3.
Reason: Destination Unreachable is a response to an outbound packet attempt.

### Rule 6: ICMP Time Exceeded (type 11)
Drop ICMP type 11.
Reason: Time Exceeded is a response to a traceroute from our enclave.

### Rule 7: ICMP Redirect (type 5)
Drop ICMP type 5.
Reason: Redirect tells us to use a different path — implies outbound routing.

### Rule 8: ICMPv6 Destination Unreachable
Drop ICMPv6DestUnreach.
Reason: Same as Rule 5 but for IPv6.

### Rule 9: Parse error
Drop if any exception occurs during packet parsing.
Reason: Conservative fallback — never let a malformed packet crash the capture loop.

---

## What is Kept (explicitly)

| Frame | Reason |
|---|---|
| TCP SYN (ACK=0) | New connection — core DDoS/scan observation |
| TCP SYN+ACK | Observed handshake from monitored side |
| TCP PSH+ACK with data | Data transfer — features Person 1/2 need |
| TCP FIN | Flow close — triggers FlowAssembler to emit FlowObject |
| TCP FIN+ACK | Flow close with acknowledgement |
| All UDP | DNS queries (DGA/tunnel), QUIC |
| ICMP Echo Request (type 8) | Observed ping/scan from monitored network |

---

## Unit Tests

18 tests in tests/unit/test_discard.py:

```
test_arp_is_discarded
test_non_ip_frame_is_discarded
test_pure_ack_is_discarded
test_pure_ack_reason
test_syn_is_kept
test_syn_ack_is_kept
test_syn_flood_packet_is_kept          <- most important edge case
test_psh_ack_with_data_is_kept
test_fin_ack_is_kept
test_udp_dns_is_kept
test_icmp_echo_request_is_kept
test_rst_is_discarded
test_rst_ack_is_discarded
test_icmp_echo_reply_is_discarded
test_icmp_dest_unreachable_is_discarded
test_icmp_time_exceeded_is_discarded
test_ack_with_data_is_kept
test_fin_only_is_kept
test_ipv6_tcp_syn_is_kept
```

Run: pytest tests/unit/test_discard.py -v

---

## Performance Notes

- All checks are bitfield operations on already-parsed packet objects
- No DNS lookups, no state table lookups, no blocking I/O
- Average cost per packet: < 1 microsecond
- Called in the Scapy hot path — must never block
