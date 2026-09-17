"""Readiness and reliability features; never hand-written final fusion weights."""

import hashlib
from ..contracts import LABEL_FAMILIES, feature


def audit_sample(sensor, event_id, rate=0.01):
    value = int(hashlib.sha256(f"{sensor}:{event_id}".encode()).hexdigest()[:16], 16)
    return value / 2**64 < rate


def gates(envelope, context=None):
    context = context or {}
    history = envelope["history"]
    complete = history["window_complete"]
    def present(path):
        return feature(envelope, path)[1]
    dns = envelope["protocol"] == "DNS" or envelope["route_hints"].get("dns", False)
    encrypted = envelope["protocol"] in {"TLS", "QUIC"} or envelope["route_hints"].get("tls", False)
    temporal = context.get("c2_count", 0) >= 6 and context.get("c2_duration", 0) >= 30
    graph = context.get("graph_nodes", 0) >= 3 and context.get("graph_edges", 0) >= 3 and context.get("graph_duration", 0) >= 30
    flow_packets, packets_present = feature(envelope, "flow.packet_count")
    rules = {
        "DDoS": (True, complete and present("window.packets_per_second") and present("window.destination_concentration")),
        "PORT_SCAN": (True, complete and history["event_count"] >= 3 and (present("window.unique_dst_ports") or present("window.unique_dst_ips"))),
        "DGA": (dns, present("dns.query_name")),
        "DNS_TUNNEL": (dns, history["event_count"] >= 5 and (present("dns.query_name") or present("dns.query_length_mean"))),
        "C2_BEACONING": (envelope["protocol"] in {"TCP", "TLS", "QUIC", "UDP"}, temporal),
        "BOTNET_HOST": (True, graph), "BOTNET_COORDINATION": (True, graph),
        "ENCRYPTED_MALWARE": (encrypted, envelope["visibility"].get("tls_handshake_visible", False) or (packets_present and isinstance(flow_packets, (int, float)) and flow_packets >= 16)),
        "DATA_EXFILTRATION": (True, complete and (context.get("baseline_mature", False) or (present("window.bytes_total") and present("window.new_destination_ratio")))),
        "BRUTE_FORCE": (True, complete), "WEB_ATTACK": (True, complete),
    }
    result = {}
    for label in LABEL_FAMILIES:
        applicable, ready = rules[label]
        result[label] = {"applicable": bool(applicable), "ready": bool(applicable and ready),
                         "reason": "READY" if applicable and ready else "INSUFFICIENT_EVIDENCE" if applicable else "NOT_APPLICABLE"}
    return result
