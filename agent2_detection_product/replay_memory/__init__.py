import hashlib
import json
from pathlib import Path


class ReplayMemory:
    def __init__(self, version="replay-2.0.0", per_task=64, max_tasks=32):
        self.version, self.per_task, self.max_tasks = version, per_task, max_tasks
        self.tasks = {}

    def add(self, task, sample):
        if sample.get("split") != "train" or sample.get("verified") is not True:
            raise ValueError("replay permits verified training exemplars only")
        if task not in self.tasks and len(self.tasks) >= self.max_tasks:
            raise ValueError("replay task capacity reached")
        bank = self.tasks.setdefault(task, {})
        key = hashlib.sha256(json.dumps(sample, sort_keys=True).encode()).hexdigest()
        bank[key] = sample
        # Stable hash selection provides deterministic bounded task coverage.
        if len(bank) > self.per_task:
            del bank[max(bank)]

    def publish(self, path):
        data = json.dumps({"version": self.version, "tasks": self.tasks}, sort_keys=True, indent=2).encode()
        with Path(path).open("xb") as handle:
            handle.write(data)
        return hashlib.sha256(data).hexdigest()
