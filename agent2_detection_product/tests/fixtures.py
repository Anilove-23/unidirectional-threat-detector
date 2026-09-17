"""Contract fixtures only; never evidence of model accuracy."""
from datetime import datetime, timezone, timedelta
from copy import deepcopy
from ..multilabel_decision import DEFAULT_POLICY
from ..contracts import make_score


def envelope(event="event-1", seconds=0, protocol="TCP"):
    return {"schema_version": "2.0.0", "feature_schema_version": "2.0.0", "event_id": event, "sensor_id": "sensor-1",
            "event_time": (datetime(2026, 9, 17, tzinfo=timezone.utc) + timedelta(seconds=seconds)).isoformat(),
            "entity_keys": {"flow_id": event, "source": "192.0.2.1", "destination": "198.51.100.1"},
            "protocol": protocol,
            "features": {"flow": {"packet_count": 32, "byte_count": 2000}, "window": {"packets_per_second": 20, "destination_concentration": .8, "unique_dst_ports": 5, "bytes_total": 2000, "new_destination_ratio": .8}, "dns": {"query_name": "example.test"} if protocol == "DNS" else {}, "tls": {}},
            "visibility": {"feature_availability_ratio": 1.0, "dns_response_visible": False, "nxdomain_ratio_available": False, "tls_handshake_visible": protocol == "TLS"},
            "history": {"event_count": 10, "duration_ms": 60000, "window_complete": True}, "route_hints": {"flow": True, "dns": protocol == "DNS", "tls": protocol == "TLS"}}


def policy():
    value = deepcopy(DEFAULT_POLICY)
    value["approved"] = True
    value["version"] = "test-policy-only"
    return value


def score(env, label, probability, model="test-model"):
    return make_score(env, label, probability, model, "test-1.0.0", calibrated=True)


def mature_context():
    return {"c2_count": 8, "c2_duration": 120, "graph_nodes": 4, "graph_edges": 4, "graph_duration": 60}
