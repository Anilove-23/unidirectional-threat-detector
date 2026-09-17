import numpy as np


def periodicity(timestamps):
    gaps = np.diff(np.asarray(timestamps, dtype=float))
    gaps = gaps[gaps > 0]
    if len(gaps) < 5:
        return {"score_present": False, "reason": "INSUFFICIENT_C2_HISTORY"}
    mean, median = gaps.mean(), np.median(gaps)
    cv = float(gaps.std() / max(mean, 1e-9))
    mad = float(np.median(abs(gaps - median)) / max(median, 1e-9))
    centered = gaps - mean
    spectrum = abs(np.fft.rfft(centered)) ** 2
    concentration = float(spectrum[1:].max() / spectrum[1:].sum()) if spectrum[1:].sum() else 0.0
    autocorrelation = float(np.dot(centered[:-1], centered[1:]) / np.dot(centered, centered)) if np.dot(centered, centered) else 1.0
    return {"score_present": True, "iat_cv": cv, "iat_mad": mad,
            "interval_seconds": float(median), "spectral_concentration": concentration,
            "lag1_autocorrelation": autocorrelation, "periodicity_strength": float(np.exp(-cv - mad)),
            "event_count": len(timestamps), "duration_seconds": float(timestamps[-1] - timestamps[0])}
