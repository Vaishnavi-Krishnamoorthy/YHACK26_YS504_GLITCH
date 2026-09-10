"""
Module 2: Model Integrity Engine
1. Layer-wise SHA-256 weight fingerprinting (detects layer substitution).
2. Black-box behavioral trigger sensitivity probe.
"""

import hashlib
import json
import os


def fingerprint_layers(layer_dict):
    """
    Computes per-layer SHA-256 digests from a dictionary of layer bytes/arrays.
    Allows pinpointing exact layers that were swapped or fine-tuned.
    """
    fingerprints = {}
    for layer_name, weight_data in layer_dict.items():
        if isinstance(weight_data, str):
            data_bytes = weight_data.encode("utf-8")
        elif isinstance(weight_data, bytes):
            data_bytes = weight_data
        else:
            data_bytes = str(weight_data).encode("utf-8")
        
        layer_hash = hashlib.sha256(data_bytes).hexdigest()
        fingerprints[layer_name] = layer_hash

    return fingerprints


def verify_model_layers(current_layers, baseline_fingerprints):
    """
    Compares current model layer fingerprints against a known-good baseline.
    Returns which layers are intact and which were altered/substituted.
    """
    current_fp = fingerprint_layers(current_layers)
    mismatches = []
    intact = []

    for name, expected_hash in baseline_fingerprints.items():
        actual_hash = current_fp.get(name)
        if actual_hash != expected_hash:
            mismatches.append({
                "layer": name,
                "expected": expected_hash,
                "actual": actual_hash
            })
        else:
            intact.append(name)

    is_clean = len(mismatches) == 0
    return {
        "is_clean": is_clean,
        "intact_layers": intact,
        "tampered_layers": mismatches,
        "status": "PASS" if is_clean else "LAYER_SUBSTITUTION_DETECTED"
    }


def blackbox_behavioral_probe(predict_fn, clean_samples, trigger_samples):
    """
    Fallback method when internal weights are inaccessible (black-box).
    Measures if adding a trigger pattern causes unexpected prediction flips.
    """
    clean_preds = [predict_fn(s) for s in clean_samples]
    trigger_preds = [predict_fn(s) for s in trigger_samples]

    flips = sum(1 for c, t in zip(clean_preds, trigger_preds) if c != t)
    flip_rate = flips / len(clean_samples) if clean_samples else 0.0

    suspicious = flip_rate > 0.40  # If trigger consistently forces misclassification
    return {
        "samples_probed": len(clean_samples),
        "prediction_flips": flips,
        "flip_rate": round(flip_rate, 3),
        "suspicious_backdoor_behavior": suspicious,
        "status": "SUSPECTED_BACKDOOR" if suspicious else "NORMAL"
    }


def verify_onnx_integrity(model_path, baseline_fingerprints):
    """
    Verifies ONNX model against known layer fingerprints (Module 2).
    Delegates to aegis.formats.onnx_inspector.
    """
    from aegis.formats.onnx_inspector import verify_onnx_layers
    return verify_onnx_layers(model_path, baseline_fingerprints)

