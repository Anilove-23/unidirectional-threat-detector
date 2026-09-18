from collections import Counter, defaultdict
from datetime import datetime
import math


def scenario_quality(records, *, packet_count=None, duration_s=None):
    """Return measurable scenario quality fields for release review."""
    flows = {row["observation"]["entity_keys"]["flow_id"] for row in records if "observation" in row}
    hosts = set()
    labels = Counter()
    times = defaultdict(list)
    for row in records:
        observation = row.get("observation")
        if not observation:
            continue
        keys = observation["entity_keys"]
        hosts.update((keys["source"], keys["destination"]))
        ground_truth = row.get("labels", {})
        if isinstance(ground_truth, dict):
            for label, enabled in ground_truth.items():
                if enabled:
                    labels[label] += 1
        else:
            for label in ground_truth:
                labels[label] += 1
        if (row.get("labels", {}).get("C2_BEACONING") if isinstance(row.get("labels", {}), dict)
                else "C2_BEACONING" in row.get("labels", [])):
            times[keys["source"]].append(datetime.fromisoformat(row["event_time"].replace("Z", "+00:00")).timestamp())
    intervals = [right - left for values in times.values() for left, right in zip(sorted(values), sorted(values)[1:]) if right > left]
    malicious = sum(value for label, value in labels.items() if label != "BENIGN")
    total = len(records)
    return {
        "duration_s": duration_s,
        "packets": packet_count,
        "observation_count": total,
        "flows": len(flows),
        "hosts": len(hosts),
        "benign_fraction": float(max(total - malicious, 0) / total) if total else None,
        "malicious_fraction": float(malicious / total) if total else None,
        "label_counts": dict(labels),
        "c2_events": sum(len(values) for values in times.values()),
        "observed_mean_interval": sum(intervals) / len(intervals) if intervals else None,
        "observed_interval_cv": (math.sqrt(sum((value - sum(intervals) / len(intervals)) ** 2 for value in intervals) / len(intervals)) /
                                 (sum(intervals) / len(intervals))) if intervals and sum(intervals) else None,
    }
