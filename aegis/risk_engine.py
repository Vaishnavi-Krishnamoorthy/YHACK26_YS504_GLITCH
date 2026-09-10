"""
Module 5: Risk Scoring & Triage Decision Engine
Aggregates findings from Modules 1-4 into a unified risk score (0-100)
and assigns actionable recommendations: ACCEPT / REVIEW / QUARANTINE.
"""

import json
from datetime import datetime, timezone


def evaluate_risk(provenance_result, data_result, model_result, drift_result):
    """
    Computes composite risk score (0-100) based on module findings.
    Weights:
      - Provenance Chain: 35%
      - Model Integrity: 30%
      - Data Assurance: 20%
      - Inference Drift: 15%
    """
    risk_score = 0
    flags = []

    # 1. Provenance check (Weight: 35)
    if not provenance_result.get("is_clean", True):
        risk_score += 35
        flags.append("Cryptographic Merkle chain broken (unauthorized file modification)")

    # 2. Model Integrity check (Weight: 30)
    if not model_result.get("is_clean", True):
        risk_score += 30
        flags.append("Model layer substitution detected (weight hash mismatch)")
    if model_result.get("suspicious_backdoor_behavior", False):
        risk_score += 25
        flags.append("Suspicious backdoor sensitivity detected in behavioral probe")

    # 3. Data Assurance check (Weight: 20)
    if data_result.get("poison_detected", False):
        risk_score += 20
        flags.append("High-frequency FFT trigger pattern detected in training data")
    if data_result.get("duplicates_count", 0) > 0:
        risk_score += 10
        flags.append(f"{data_result.get('duplicates_count')} duplicate/near-duplicate image pair(s) found")

    # 4. Inference Drift check (Weight: 15)
    if drift_result.get("drift_detected", False):
        risk_score += 15
        flags.append("Distribution shift detected in operational confidence scores")
    if drift_result.get("record_tampered", False):
        risk_score += 25
        flags.append("Inference record hash mismatch (post-generation modification)")

    # Bound risk score between 0 and 100
    risk_score = min(100, max(0, risk_score))

    # Triage decision logic
    if risk_score <= 30:
        recommendation = "ACCEPT"
        color = "GREEN"
    elif risk_score <= 65:
        recommendation = "REVIEW"
        color = "YELLOW"
    else:
        recommendation = "QUARANTINE"
        color = "RED"

    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "composite_risk_score": risk_score,
        "recommendation": recommendation,
        "status_color": color,
        "flags_raised": flags,
        "module_breakdown": {
            "provenance": "PASS" if provenance_result.get("is_clean", True) else "FAIL",
            "model_integrity": "PASS" if model_result.get("is_clean", True) else "FAIL",
            "data_assurance": "POISON_DETECTED" if data_result.get("poison_detected") else "CLEAN",
            "inference_drift": "DRIFT_DETECTED" if drift_result.get("drift_detected") else "STABLE"
        },
        "limitations": [
            "Evaluated in air-gapped mode using local signatures.",
            "Black-box probing is probabilistic and requires representative test probes."
        ]
    }

    return report
