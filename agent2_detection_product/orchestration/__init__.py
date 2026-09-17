"""One inference path for JSONL replay and durable Redis consumption."""

from collections import deque
from copy import deepcopy
import hashlib
import json
import time
from ..contracts import observation, specialist, feature, timestamp
from ..state_detection import TTLStore, TemporalHistory, CommunicationGraph
from ..multilabel_decision import DecisionEngine
from ..correlation import IncidentCorrelator
from ..adaptation import BenignBaselines
from ..gating import audit_sample


class DetectionPipeline:
    def __init__(self, *, policy=None, providers=(), drift=None, capacity=10000, audit_rate=0.01):
        self.engine = DecisionEngine(policy)
        self.providers = list(providers)
        self.drift = drift
        self.history = TemporalHistory(capacity=capacity)
        self.graph = CommunicationGraph(capacity=capacity * 2)
        self.baselines = BenignBaselines(capacity)
        self.correlator = IncidentCorrelator(capacity)
        self.cache = TTLStore(capacity=capacity)
        self.audit_rate = audit_rate
        self.metrics = {"processed_total": 0, "duplicates_total": 0, "alerts_total": 0, "errors_total": 0}
        self.latencies = deque(maxlen=2048)
        self.started = time.monotonic()
        self.last_drift = "NONE"

    def process(self, raw, dns_scores=(), *, queue_age=0):
        start = time.perf_counter()
        env = observation(raw)
        now = timestamp(env["event_time"])
        # Validate external scores before any state changes.
        scores = [specialist(s, env) for s in dns_scores]
        key = (env["sensor_id"], env["event_id"])
        digest = hashlib.sha256(json.dumps([env, scores], sort_keys=True).encode()).hexdigest()
        previous = self.cache.get(key, now)
        if previous:
            if previous["digest"] != digest:
                raise ValueError("stable event_id reused with different payload")
            self.metrics["duplicates_total"] += 1
            return {**deepcopy(previous["result"]), "duplicate": True}
        keys = env["entity_keys"]
        pair = (env["sensor_id"], keys["source"], keys["destination"])
        timestamps = self.history.observe(pair, now)
        byte_count, _ = feature(env, "flow.byte_count")
        self.graph.observe(*pair, now, byte_count=byte_count)
        graph = self.graph.snapshot(env["sensor_id"], now)
        nodes = {n for source, dest, _ in graph for n in (source, dest)}
        baseline_key = (env["sensor_id"], keys["source"])
        baseline = self.baselines.state.get(baseline_key, now, {})
        context = {
            "c2_count": len(timestamps), "c2_duration": timestamps[-1] - timestamps[0],
            "timestamps": timestamps, "graph": graph, "graph_nodes": len(nodes), "graph_edges": len(graph),
            "graph_duration": now - min((v["first_seen"] for _, _, v in graph), default=now),
            "baseline_mature": baseline.get("count", 0) >= 20, "baseline": baseline,
            "queue_age": max(queue_age, 0), "audit": audit_sample(env["sensor_id"], env["event_id"], self.audit_rate),
            "drift_status": "NONE", "model_profile": "unconfigured",
        }
        drift_values = {"visibility": env["visibility"]["feature_availability_ratio"]}
        ood = {}
        errors = []
        for provider in self.providers:
            try:
                output = provider.score(env, context)
                scores.extend(output.get("scores", []))
                if output.get("ood"):
                    ood = output["ood"]
                context["model_profile"] = output.get("profile", context["model_profile"])
                drift_values.update(output.get("drift_values", {}))
            except Exception as exc:
                # A failed model becomes missing evidence, never benign evidence.
                errors.append(f"{type(provider).__name__}:{type(exc).__name__}")
                self.metrics["errors_total"] += 1
        if self.drift:
            report = self.drift.observe(drift_values)
            context["drift_status"] = report["status"]
            self.last_drift = report["status"]
        decision = self.engine.decide(env, scores, ood, context)
        if errors:
            decision["reason_codes"].append("MODEL_INFERENCE_FAILED")
            decision["evidence"]["model_failures"] = errors
        decision["audit_sample"] = context["audit"]
        decision["queue_age_seconds"] = context["queue_age"]
        self.baselines.update(baseline_key, {"bytes": byte_count}, decision, now)
        incidents = self.correlator.close_expired(now) + self.correlator.process(decision)
        result = {"decision": decision, "incidents": incidents, "duplicate": False}
        self.cache.put(key, {"digest": digest, "result": deepcopy(result)}, now)
        self.metrics["processed_total"] += 1
        self.metrics["alerts_total"] += int(decision["decision_state"] in {"KNOWN_ATTACK", "UNKNOWN"})
        self.latencies.append((time.perf_counter() - start) * 1000)
        return result

    def stats(self):
        latency = sorted(self.latencies)
        elapsed = max(time.monotonic() - self.started, 0.001)
        return {**self.metrics, "uptime_s": elapsed, "flows_per_sec": self.metrics["processed_total"] / elapsed,
                "inference_p95_ms": latency[min(int(len(latency) * .95), len(latency)-1)] if latency else None,
                "state_sizes": {"c2": len(self.history.store), "graph_edges": len(self.graph.edges), "incidents": len(self.correlator.incidents), "dedupe": len(self.cache)},
                "model_profile": [getattr(p, "version", "unversioned") for p in self.providers], "drift_status": self.last_drift}

    def checkpoint(self):
        stores = {"history": self.history.store, "graph": self.graph.edges, "baselines": self.baselines.state,
                  "incidents": self.correlator.incidents, "seen": self.correlator.seen, "cache": self.cache}
        return {"stores": {name: {"watermark": store.watermark if store.watermark != float('-inf') else None,
                 "items": [[key, t, list(value) if name == "history" else value] for key, (t, value) in store.data.items()]}
                 for name, store in stores.items()}, "metrics": self.metrics,
                "drift": {k: list(v) for k, v in self.drift.current.items()} if self.drift else None}

    def restore(self, checkpoint):
        stores = {"history": self.history.store, "graph": self.graph.edges, "baselines": self.baselines.state,
                  "incidents": self.correlator.incidents, "seen": self.correlator.seen, "cache": self.cache}
        for name, saved in checkpoint["stores"].items():
            store = stores[name]
            store.data.clear()
            store.watermark = saved["watermark"] if saved["watermark"] is not None else float('-inf')
            for key, t, value in saved["items"]:
                if isinstance(key, list):
                    key = tuple(key)
                if name == "history":
                    value = deque(value, maxlen=self.history.samples)
                store.data[key] = (t, value)
        self.metrics.update(checkpoint["metrics"])
        if self.drift and checkpoint.get("drift"):
            for key, values in checkpoint["drift"].items():
                self.drift.current[key].extend(values)
