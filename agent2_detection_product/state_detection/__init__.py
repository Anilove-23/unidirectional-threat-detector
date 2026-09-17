"""Bounded event-time state. Retry handling happens before state mutation."""

from collections import OrderedDict, deque


class TTLStore:
    def __init__(self, ttl=86400, capacity=10000):
        if ttl <= 0 or capacity < 1:
            raise ValueError("positive state limits required")
        self.ttl, self.capacity = ttl, capacity
        self.data = OrderedDict()
        self.watermark = float("-inf")

    def expire(self, now):
        self.watermark = max(self.watermark, now)
        expired = [k for k, (t, _) in self.data.items() if t < self.watermark - self.ttl]
        for key in expired:
            del self.data[key]

    def get(self, key, now, default=None):
        self.expire(now)
        item = self.data.get(key)
        return item[1] if item else default

    def put(self, key, value, now):
        self.expire(now)
        if now < self.watermark - self.ttl:
            return
        self.data.pop(key, None)
        self.data[key] = (now, value)
        while len(self.data) > self.capacity:
            self.data.popitem(last=False)

    def __len__(self):
        return len(self.data)


class TemporalHistory:
    def __init__(self, ttl=86400, capacity=10000, samples=512):
        self.store = TTLStore(ttl, capacity)
        self.samples = samples

    def observe(self, key, now):
        history = self.store.get(key, now, deque(maxlen=self.samples))
        # Late observations never create negative or duplicate inter-arrival times.
        if history and now <= history[-1]:
            return list(history)
        while history and history[0] < now - self.store.ttl:
            history.popleft()
        history.append(now)
        self.store.put(key, history, now)
        return list(history)


class CommunicationGraph:
    def __init__(self, ttl=300, capacity=20000, max_degree=256):
        self.edges = TTLStore(ttl, capacity)
        self.max_degree = max_degree

    def observe(self, sensor, source, destination, now, byte_count=None):
        key = (sensor, source, destination)
        old = self.edges.get(key, now)
        if old is None:
            degree = sum(k[:2] == key[:2] for k in self.edges.data)
            if degree >= self.max_degree:
                return
        value = dict(old) if old else {"first_seen": now, "count": 0, "bytes": None}
        value["count"] += 1
        if byte_count is not None:
            value["bytes"] = (value["bytes"] or 0) + byte_count
        self.edges.put(key, value, now)

    def snapshot(self, sensor, now):
        self.edges.expire(now)
        return [(s, d, dict(v)) for (sid, s, d), (_, v) in self.edges.data.items() if sid == sensor]
