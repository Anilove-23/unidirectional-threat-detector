"""Bounded event-time incidents, retry dedupe and host-chain correlation."""

from copy import deepcopy
import hashlib
from ..contracts import timestamp
from ..state_detection import TTLStore


class IncidentCorrelator:
    def __init__(self, capacity=10000, timeline_size=64):
        self.incidents = TTLStore(ttl=1800, capacity=capacity)
        self.seen = TTLStore(ttl=86400, capacity=capacity * 4)
        self.timeline_size = timeline_size

    def process(self, decision):
        now = timestamp(decision["event_time"])
        if self.seen.get(decision["decision_id"], now):
            return []
        self.seen.put(decision["decision_id"], True, now)
        if decision["decision_state"] not in {"KNOWN_ATTACK", "UNKNOWN"}:
            return []
        labels = decision["labels"] or {"ANOMALOUS_UNCLASSIFIED": decision["confidence"]}
        keys = decision["entity_keys"]
        groups = {}
        for label in labels:
            family = "DDoS" if label == "DDoS" else "PORT_SCAN" if label == "PORT_SCAN" else "HOST_CHAIN"
            entity = keys["destination"] if family == "DDoS" else keys["source"]
            groups.setdefault((decision["sensor_id"], entity, family), {})[label] = labels[label]
        updates = []
        for key, passing in groups.items():
            incident = self.incidents.get(key, now)
            ttl = 60 if key[2] == "DDoS" else 300 if key[2] == "PORT_SCAN" else 1800
            if incident and now - timestamp(incident["last_seen"]) > ttl:
                incident = None
            action = "update" if incident else "create"
            if incident is None:
                incident = {"schema_version": "2.0.0", "incident_id": hashlib.sha256(f"{key}:{decision['decision_id']}".encode()).hexdigest(),
                            "sensor_id": decision["sensor_id"], "entity": key[1], "family": key[2], "status": "open",
                            "first_seen": decision["event_time"], "last_seen": decision["event_time"], "count": 0,
                            "labels": {}, "timeline": [], "severity": "HIGH", "reason_codes": []}
            else:
                incident = deepcopy(incident)
            incident["count"] += 1
            incident["first_seen"] = min(incident["first_seen"], decision["event_time"], key=timestamp)
            incident["last_seen"] = max(incident["last_seen"], decision["event_time"], key=timestamp)
            for label, value in passing.items():
                incident["labels"][label] = max(value, incident["labels"].get(label, 0))
            incident["timeline"].append({"event_time": decision["event_time"], "decision_id": decision["decision_id"], "labels": sorted(passing), "evidence": decision["evidence"]})
            incident["timeline"] = sorted(incident["timeline"], key=lambda e: timestamp(e["event_time"]))[-self.timeline_size:]
            recent = {label for event in incident["timeline"] if now - 900 <= timestamp(event["event_time"]) <= now for label in event["labels"]}
            reasons = set(incident["reason_codes"])
            if len(recent & {"DGA", "C2_BEACONING", "DNS_TUNNEL"}) >= 2:
                reasons.add("SUSPECTED_COMPROMISE_CHAIN")
            if "C2_BEACONING" in recent and recent & {"BOTNET_HOST", "BOTNET_COORDINATION"}:
                reasons.add("BOTNET_TEMPORAL_GRAPH_CORRELATION")
            if "DATA_EXFILTRATION" in passing and any(timestamp(e["event_time"]) <= now and now - timestamp(e["event_time"]) <= 1800 and set(e["labels"]) & {"DGA", "C2_BEACONING", "BOTNET_HOST", "BOTNET_COORDINATION"} for e in incident["timeline"]):
                reasons.add("EXFILTRATION_AFTER_COMPROMISE_EVIDENCE")
            incident["reason_codes"] = sorted(reasons)
            if reasons or "DDoS" in passing:
                incident["severity"] = "CRITICAL"
            incident["action"] = action
            self.incidents.put(key, incident, max(now, timestamp(incident["last_seen"])))
            updates.append(deepcopy(incident))
        return updates

    def close_expired(self, now):
        updates = []
        for key, (_, record) in list(self.incidents.data.items()):
            ttl = 60 if key[2] == "DDoS" else 300 if key[2] == "PORT_SCAN" else 1800
            if now - timestamp(record["last_seen"]) > ttl:
                updates.append({**deepcopy(record), "action": "close", "status": "closed"})
                del self.incidents.data[key]
        return updates
