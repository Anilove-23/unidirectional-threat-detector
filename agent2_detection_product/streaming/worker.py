import json
import sqlite3
import time
from pathlib import Path


class DurableOutbox:
    def __init__(self, path, pipeline, profile="development"):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path)
        self.pipeline = pipeline
        self.db.executescript("CREATE TABLE IF NOT EXISTS outbox (id TEXT PRIMARY KEY, payload TEXT NOT NULL); CREATE TABLE IF NOT EXISTS checkpoint (id INTEGER PRIMARY KEY, profile TEXT NOT NULL, payload TEXT NOT NULL);")
        saved = self.db.execute("SELECT profile, payload FROM checkpoint WHERE id=1").fetchone()
        if saved:
            if saved[0] != profile:
                raise ValueError("checkpoint profile differs; use a new checkpoint for a model release")
            pipeline.restore(json.loads(saved[1]))
        self.profile = profile

    def prepare(self, message_id, message):
        cached = self.db.execute("SELECT payload FROM outbox WHERE id=?", (message_id,)).fetchone()
        if cached:
            return json.loads(cached[0])
        before = self.pipeline.checkpoint()
        # JSON round trip takes a snapshot; mutable state must not leak into rollback.
        before = json.loads(json.dumps(before))
        try:
            result = self.pipeline.process(message["observation"], message.get("specialist_scores", []), queue_age=message.get("queue_age_seconds", 0))
            payload = json.dumps(result, allow_nan=False)
            checkpoint = json.dumps(self.pipeline.checkpoint(), allow_nan=False)
            with self.db:
                self.db.execute("INSERT INTO outbox VALUES (?,?)", (message_id, payload))
                self.db.execute("INSERT OR REPLACE INTO checkpoint VALUES (1,?,?)", (self.profile, checkpoint))
            return result
        except Exception:
            self.pipeline.restore(before)
            raise

    def delivered(self, message_id):
        with self.db:
            self.db.execute("DELETE FROM outbox WHERE id=?", (message_id,))


def run_worker(client, pipeline, *, checkpoint, stream="observation.v2", group="agent2-v2", consumer="worker-1", profile="development", max_messages=None):
    """One active worker owns this state profile. Horizontal partition by sensor."""
    from redis.exceptions import ResponseError, ConnectionError, TimeoutError
    from ..contracts import ContractError
    outbox = DurableOutbox(checkpoint, pipeline, profile)
    try:
        client.xgroup_create(stream, group, id="0", mkstream=True)
    except ResponseError as exc:
        if "BUSYGROUP" not in str(exc):
            raise
    processed = 0
    try:
        while max_messages is None or processed < max_messages:
            try:
                # Drain our unacknowledged deliveries before new traffic.
                batches = client.xreadgroup(group, consumer, {stream: "0"}, count=32)
                messages = batches[0][1] if batches else []
                if not messages:
                    claimed = client.xautoclaim(stream, group, consumer, min_idle_time=60000, start_id="0-0", count=32)
                    messages = claimed[1]
                if not messages:
                    batches = client.xreadgroup(group, consumer, {stream: ">"}, count=32, block=1000)
                    messages = batches[0][1] if batches else []
                for message_id, fields in messages:
                    try:
                        payload = json.loads(fields["payload"])
                        result = outbox.prepare(message_id, payload)
                    except (ContractError, ValueError, KeyError, TypeError) as exc:
                        with client.pipeline(transaction=True) as tx:
                            tx.xadd("observation.v2.dead", {"input_id": message_id, "error": str(exc), "payload": fields.get("payload", "")}, maxlen=10000)
                            tx.xack(stream, group, message_id)
                            tx.execute()
                        continue
                    with client.pipeline(transaction=True) as tx:
                        if not result["duplicate"]:
                            decision = result["decision"]
                            serialized = json.dumps(decision, allow_nan=False)
                            tx.xadd("decision.v2", {"payload": serialized}, maxlen=100000)
                            tx.publish("decision.new", serialized)
                            for incident in result["incidents"]:
                                serialized_incident = json.dumps(incident, allow_nan=False)
                                tx.xadd("incident.v2", {"payload": serialized_incident}, maxlen=100000)
                                tx.publish("incident.update", serialized_incident)
                        tx.xack(stream, group, message_id)
                        stats = pipeline.stats()
                        groups = client.xinfo_groups(stream)
                        stats["queue_lag"] = next((g.get("lag") for g in groups if g["name"] == group), None)
                        stats["queue_pending"] = next((g.get("pending") for g in groups if g["name"] == group), None)
                        tx.set("pipeline.stats", json.dumps(stats), ex=60)
                        tx.execute()
                    outbox.delivered(message_id)
                    processed += 1
            except (ConnectionError, TimeoutError):
                time.sleep(1)
    finally:
        outbox.db.close()
