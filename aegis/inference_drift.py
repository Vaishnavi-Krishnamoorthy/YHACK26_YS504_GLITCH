"""
Module 3: Inference Drift & Output Authenticity Engine
1. Distribution drift / Out-of-Distribution (OOD) detection.
2. Inference output record tampering verification (catches post-generation modifications).
"""

import json
import hashlib
import numpy as np


def detect_confidence_drift(recent_confidences, baseline_mean=0.82, baseline_std=0.08, z_threshold=2.5):
    """
    Detects operational distribution shift by monitoring prediction confidence.
    Significant drop indicates out-of-distribution (OOD) camera feeds or environmental changes.
    """
    if not recent_confidences:
        return {"drift_detected": False, "score": 0.0}

    current_mean = float(np.mean(recent_confidences))
    current_std = float(np.std(recent_confidences))

    z_score = abs(current_mean - baseline_mean) / (baseline_std + 1e-6)
    drift_detected = z_score > z_threshold

    return {
        "baseline_mean": baseline_mean,
        "observed_mean": round(current_mean, 3),
        "z_score": round(z_score, 2),
        "drift_detected": drift_detected,
        "status": "DISTRIBUTION_DRIFT_DETECTED" if drift_detected else "STABLE"
    }


def verify_inference_records(records_file, expected_digest=None):
    """
    Verifies that saved inference outputs (bounding boxes, detected classes)
    have not been tampered with or replaced after generation.
    """
    with open(records_file, "r", encoding="utf-8") as f:
        content = f.read()

    current_digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
    records = json.loads(content)

    if expected_digest:
        match = (current_digest == expected_digest)
        return {
            "records_count": len(records),
            "tamper_detected": not match,
            "digest": current_digest,
            "status": "AUTHENTIC" if match else "OUTPUT_TAMPER_DETECTED"
        }

    return {
        "records_count": len(records),
        "digest": current_digest,
        "status": "REGISTERED"
    }
