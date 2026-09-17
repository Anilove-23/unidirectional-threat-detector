"""Bounded reference/current distribution comparisons; no automatic fitting."""

from collections import deque
import numpy as np
from scipy.stats import ks_2samp
from scipy.spatial.distance import jensenshannon


def distribution_drift(reference, current, bins=10):
    reference, current = np.asarray(reference), np.asarray(current)
    if len(reference) < 20 or len(current) < 20:
        return {"status": "INSUFFICIENT_HISTORY", "psi": None, "ks": None, "jsd": None}
    edges = np.unique(np.quantile(reference, np.linspace(0, 1, bins + 1)))
    if len(edges) < 2:
        center = float(reference[0])
        edges = np.array([center - 1e-6, center + 1e-6])
    edges = np.r_[-np.inf, edges, np.inf]
    p, q = np.histogram(reference, edges)[0].astype(float) + 1e-6, np.histogram(current, edges)[0].astype(float) + 1e-6
    p, q = p / p.sum(), q / q.sum()
    psi = float(np.sum((q-p) * np.log(q/p)))
    ks = float(ks_2samp(reference, current).statistic)
    jsd = float(jensenshannon(p, q) ** 2)
    status = "SEVERE" if psi >= 0.5 else "MODERATE" if psi >= 0.25 else "MILD" if psi >= 0.1 else "NONE"
    return {"status": status, "psi": psi, "ks": ks, "jsd": jsd}


class DriftMonitor:
    def __init__(self, reference, window=512):
        self.reference = {k: list(v)[-window:] for k, v in reference.items()}
        self.current = {key: deque(maxlen=window) for key in reference}

    def observe(self, values):
        report = {}
        for key, samples in self.current.items():
            value = values.get(key)
            if value is not None and np.isfinite(value):
                samples.append(float(value))
            report[key] = distribution_drift(self.reference[key], list(samples))
        ranks = {"INSUFFICIENT_HISTORY": 0, "NONE": 0, "MILD": 1, "MODERATE": 2, "SEVERE": 3}
        status = max((r["status"] for r in report.values()), key=lambda s: ranks[s], default="NONE")
        return {"status": status, "groups": report}
