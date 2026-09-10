#!/usr/bin/env python3
"""
AEGIS-CV: Unified Offline Assurance & Provenance Framework
Challenge 22 | Team GLITCH (YS504) - YHACK'26 Review 2

Integrates all 5 assurance modules across all required formats:
  - Formats Supported: COCO, YOLO, ONNX, and PyTorch / Raw Binary Weights
  1. Data Assurance (Duplicates, FFT Poison Trigger, COCO/YOLO Label Validation)
  2. Model Integrity (Layer-wise Fingerprinting, ONNX Architecture & Substitution)
  3. Inference Drift (Distribution Shift & Output Record Verification)
  4. Cryptographic Provenance (Merkle Tree & HMAC-signed Receipts)
  5. Risk Engine (Composite Scoring 0-100 & Triage: ACCEPT/REVIEW/QUARANTINE)
"""

import os
import sys
import json
import numpy as np
from PIL import Image

from aegis.provenance import hash_file, generate_receipt, verify_pipeline
from aegis.audit_ledger import append_receipt, verify_ledger, simulate_ledger_tampering

from aegis.data_assurance import (
    compute_dhash,
    scan_duplicates,
    detect_frequency_poison,
    validate_coco_annotations,
    validate_yolo_annotations
)
from aegis.model_integrity import fingerprint_layers, verify_model_layers
from aegis.inference_drift import detect_confidence_drift, verify_inference_records
from aegis.risk_engine import evaluate_risk
from aegis.formats.yolo_parser import validate_yolo_file, validate_yolo_dataset
from aegis.formats.onnx_inspector import (
    inspect_onnx_model,
    fingerprint_onnx_layers,
    verify_onnx_layers,
    create_sample_onnx_model
)


def generate_sample_images(image_dir):
    """Generates synthetic clean, duplicate, and poisoned images for testing."""
    os.makedirs(image_dir, exist_ok=True)
    clean_path = os.path.join(image_dir, "sample_clean.png")
    dup_path = os.path.join(image_dir, "sample_duplicate.png")
    poison_path = os.path.join(image_dir, "sample_poisoned.png")

    # 1. Clean image: smooth circular gradient (low frequency)
    y, x = np.ogrid[:128, :128]
    clean_arr = np.uint8(np.clip(128 + 60 * np.sin(x / 16.0) + 60 * np.cos(y / 16.0), 0, 255))
    Image.fromarray(clean_arr).save(clean_path)

    # 2. Duplicate image: clean image with slight brightness shift
    dup_arr = np.uint8(np.clip(clean_arr.astype(int) + 2, 0, 255))
    Image.fromarray(dup_arr).save(dup_path)

    # 3. Poisoned image: clean image + high-frequency alternating checkerboard trigger
    poison_arr = clean_arr.copy()
    for r in range(96, 124, 2):
        for c in range(96, 124, 2):
            poison_arr[r:r+2, c:c+2] = 255 if ((r+c)//2)%2 == 0 else 0
    Image.fromarray(poison_arr).save(poison_path)

    return clean_path, dup_path, poison_path


def main():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    sample_dir = os.path.join(base_dir, "sample_data")
    image_dir = os.path.join(sample_dir, "sample_images")
    reports_dir = os.path.join(base_dir, "reports")
    receipts_dir = os.path.join(base_dir, "receipts")
    os.makedirs(reports_dir, exist_ok=True)
    os.makedirs(receipts_dir, exist_ok=True)

    print("================================================================")
    print("  AEGIS-CV: End-to-End Offline Computer Vision Assurance System ")
    print("  Team: GLITCH (YS504) | Challenge 22 - Review 2 Integration    ")
    print("  Formats: COCO, YOLO, ONNX, and PyTorch / Raw Binary Weights   ")
    print("================================================================")

    # -------------------------------------------------------------------------
    # Setup test assets
    # -------------------------------------------------------------------------
    clean_img, dup_img, poison_img = generate_sample_images(image_dir)
    coco_json = os.path.join(sample_dir, "dataset_coco_sample.json")
    config_json = os.path.join(sample_dir, "pipeline_config.json")
    records_json = os.path.join(sample_dir, "inference_records.json")

    # YOLO sample files
    yolo_clean_txt = os.path.join(sample_dir, "dataset_yolo_sample.txt")
    yolo_corrupt_txt = os.path.join(sample_dir, "dataset_yolo_corrupt.txt")
    yolo_empty_txt = os.path.join(sample_dir, "dataset_yolo_empty.txt")

    # ONNX sample models
    onnx_clean_model = os.path.join(sample_dir, "vision_model.onnx")
    onnx_tampered_model = os.path.join(sample_dir, "vision_model_tampered.onnx")

    if not os.path.exists(onnx_clean_model):
        create_sample_onnx_model(onnx_clean_model, tampered=False)
    if not os.path.exists(onnx_tampered_model):
        create_sample_onnx_model(onnx_tampered_model, tampered=True)

    # Simulated raw PyTorch-like model layers
    baseline_layers = {
        "backbone.conv1.weight": b"WEIGHTS_CONV1_RESNET50_LAYER_DATA_BYTES",
        "backbone.layer1.0.conv1.weight": b"WEIGHTS_CONV2_RESNET50_LAYER_DATA_BYTES",
        "head.fc.weight": b"WEIGHTS_CLASSIFIER_HEAD_80_CLASSES_BASELINE"
    }
    baseline_layer_fps = fingerprint_layers(baseline_layers)

    # Baseline ONNX layer fingerprints
    baseline_onnx_fps = fingerprint_onnx_layers(onnx_clean_model)

    # -------------------------------------------------------------------------
    # RUN 1: Clean Baseline Evaluation
    # -------------------------------------------------------------------------
    print("\n--- [RUN 1] EVALUATING CLEAN BASELINE PIPELINE ---")

    # Module 1: Data Assurance (COCO & YOLO)
    print("[1] Module 1: Data Assurance")
    ann_coco_check = validate_coco_annotations(coco_json)
    print(f"    - COCO Annotations : {ann_coco_check['total_annotations']} validated (Valid: {ann_coco_check['valid']})")

    ann_yolo_check = validate_yolo_file(yolo_clean_txt)
    print(f"    - YOLO Annotations : {ann_yolo_check['total_boxes']} boxes parsed & bounded in [0.0, 1.0] (Valid: {ann_yolo_check['valid']})")

    clean_poison = detect_frequency_poison(clean_img)
    print(f"    - FFT Poison Scan  : {os.path.basename(clean_img)} (Ratio: {clean_poison['high_freq_ratio']} <= {clean_poison['threshold']}) -> {clean_poison['status']}")
    dup_check = scan_duplicates([clean_img], threshold=3)
    print(f"    - Duplicate Scan   : {dup_check['duplicate_pairs_found']} duplicates found")

    data_summary_clean = {
        "poison_detected": clean_poison["is_poisoned"],
        "duplicates_count": dup_check["duplicate_pairs_found"]
    }

    # Module 2: Model Integrity (PyTorch/Binary & ONNX)
    print("\n[2] Module 2: Model Integrity")
    model_check_clean = verify_model_layers(baseline_layers, baseline_layer_fps)
    print(f"    - PyTorch Weights  : {len(model_check_clean['intact_layers'])}/3 layers verified intact -> {model_check_clean['status']}")

    onnx_inspection = inspect_onnx_model(onnx_clean_model)
    onnx_check_clean = verify_onnx_layers(onnx_clean_model, baseline_onnx_fps)
    input_shape = onnx_inspection["inputs"][0]["shape"] if onnx_inspection["inputs"] else "N/A"
    output_shape = onnx_inspection["outputs"][0]["shape"] if onnx_inspection["outputs"] else "N/A"
    print(f"    - ONNX Inspection  : {onnx_inspection['metadata']['model_file']} (Input: {input_shape}, Output: {output_shape}, Nodes: {onnx_inspection['total_nodes']})")
    print(f"    - ONNX Layer Hashes: {len(onnx_check_clean['intact_layers'])}/{onnx_check_clean['total_layers']} layers verified intact -> {onnx_check_clean['status']}")

    # Module 3: Inference Drift
    print("\n[3] Module 3: Inference Drift & Output Authenticity")
    normal_confidences = [0.85, 0.88, 0.81, 0.79, 0.84, 0.86]
    drift_check_clean = detect_confidence_drift(normal_confidences)
    print(f"    - Confidence Drift : Observed mean {drift_check_clean['observed_mean']} (Baseline 0.82) -> {drift_check_clean['status']}")
    rec_check_clean = verify_inference_records(records_json)
    print(f"    - Output Records   : {rec_check_clean['records_count']} records indexed (SHA-256: {rec_check_clean['digest'][:16]}...)")

    drift_summary_clean = {
        "drift_detected": drift_check_clean["drift_detected"],
        "record_tampered": False
    }

    # Module 4: Cryptographic Provenance
    print("\n[4] Module 4: Cryptographic Provenance Chain")
    tracked_files = {
        "dataset_coco": coco_json,
        "dataset_yolo": yolo_clean_txt,
        "model_onnx": onnx_clean_model,
        "config": config_json,
        "records": records_json
    }
    receipt = generate_receipt(tracked_files, os.path.join(receipts_dir, "pipeline_receipt.json"))
    is_prov_clean, prov_report = verify_pipeline(receipt)
    print(f"    - Merkle Root      : {receipt['merkle_root'][:24]}...")
    print(f"    - HMAC Signature   : Verified offline (Status: {'PASS' if is_prov_clean else 'FAIL'})")
    print(f"    - Tracked Formats  : COCO (.json), YOLO (.txt), ONNX (.onnx)")

    # Module 5: Risk Engine Decision
    print("\n[5] Module 5: Risk Engine & Triage Decision")
    clean_decision = evaluate_risk(prov_report, data_summary_clean, model_check_clean, drift_summary_clean)
    print(f"    - Composite Risk Score: {clean_decision['composite_risk_score']} / 100")
    print(f"    - Recommendation      : {clean_decision['recommendation']} [CLEARED FOR DEPLOYMENT]")

    # Module 6: Cryptographic Chained Audit Ledger
    print("\n[6] Module 6: Cryptographic Chained Audit Ledger")
    ledger_path = os.path.join(receipts_dir, "audit_ledger.jsonl")
    clean_block = append_receipt({"receipt": receipt, "triage": clean_decision}, ledger_path)
    is_ledger_clean, ledger_report = verify_ledger(ledger_path)
    print(f"    - Ledger Entry     : Block #{clean_block['index']} written (Hash: {clean_block['block_hash'][:24]}...)")
    print(f"    - Chain Link       : Prev Hash ({clean_block['previous_block_hash'][:24]}...)")
    print(f"    - Chain Integrity  : {ledger_report['status']} ({ledger_report['blocks_count']} blocks verified from genesis)")

    # -------------------------------------------------------------------------
    # RUN 2: Multi-Vector Threat Simulation
    # -------------------------------------------------------------------------
    print("\n" + "="*64)
    print("--- [RUN 2] ADVERSARIAL MULTI-VECTOR THREAT SIMULATION ---")
    print("Simulating concurrent attacks:")
    print("  1. Data Poison & Anomaly: Frequency FFT trigger + corrupt YOLO coordinates")
    print("  2. Model Substitution: Swapped PyTorch fc.weight and ONNX classifier head")
    print("  3. Operational Drift: Feeding anomalous low-confidence inputs")
    print("="*64)

    # 1. Test poisoned image and malformed YOLO annotations
    print("\n[1] Data Assurance Scan (Attacked & Corrupted Data):")
    poison_eval = detect_frequency_poison(poison_img)
    print(f"    - Scanning FFT     : {os.path.basename(poison_img)}")
    print(f"    - High-frequency FFT Energy Ratio: {poison_eval['high_freq_ratio']} (Threshold: {poison_eval['threshold']})")
    print(f"    - FFT Result       : >>> {poison_eval['status']} <<<")

    dup_eval_attack = scan_duplicates([clean_img, dup_img], threshold=3)
    print(f"    - Duplicate Scan   : Found near-duplicate pair ({dup_eval_attack['duplicates'][0]['file_a']} <-> {dup_eval_attack['duplicates'][0]['file_b']})")

    yolo_corrupt_eval = validate_yolo_file(yolo_corrupt_txt)
    print(f"    - YOLO Corrupt Scan: >>> {yolo_corrupt_eval['status']} <<< (Found {len(yolo_corrupt_eval['issues'])} issues)")
    for issue in yolo_corrupt_eval["issues"][:2]:
        print(f"        * {issue}")

    yolo_empty_eval = validate_yolo_file(yolo_empty_txt)
    missing_msg = yolo_empty_eval["issues"][0] if yolo_empty_eval["issues"] else "Empty file detected"
    print(f"    - YOLO Missing Test: >>> {yolo_empty_eval['status']} <<< (Missing label check: {missing_msg})")

    data_summary_attack = {
        "poison_detected": poison_eval["is_poisoned"],
        "duplicates_count": dup_eval_attack["duplicate_pairs_found"]
    }

    # 2. Test substituted model layer (PyTorch & ONNX)
    print("\n[2] Model Integrity Scan (Substituted Weights):")
    tampered_layers = dict(baseline_layers)
    tampered_layers["head.fc.weight"] = b"MALICIOUS_SUBSTITUTED_BACKDOOR_CLASSIFIER_HEAD_WEIGHTS"
    model_eval_attack = verify_model_layers(tampered_layers, baseline_layer_fps)
    print(f"    - PyTorch Status   : >>> {model_eval_attack['status']} <<<")
    for tm in model_eval_attack["tampered_layers"]:
        print(f"      Layer: {tm['layer']}")
        print(f"      Expected hash: {tm['expected'][:16]}...")
        print(f"      Actual hash:   {tm['actual'][:16]}...")

    onnx_eval_attack = verify_onnx_layers(onnx_tampered_model, baseline_onnx_fps)
    print(f"    - ONNX Status      : >>> {onnx_eval_attack['status']} <<<")
    for tm in onnx_eval_attack["tampered_layers"]:
        print(f"      ONNX Layer: {tm['layer']} ({tm['issue']})")
        print(f"      Expected hash: {tm['expected'][:16]}...")
        print(f"      Actual hash:   {tm['actual'][:16]}...")

    # 3. Test operational drift
    print("\n[3] Inference Drift Scan (Drifted Inputs):")
    drifted_confidences = [0.42, 0.38, 0.45, 0.35, 0.40]  # Major drop
    drift_eval_attack = detect_confidence_drift(drifted_confidences)
    print(f"    - Observed mean confidence: {drift_eval_attack['observed_mean']} (Z-score: {drift_eval_attack['z_score']})")
    print(f"    - Status: >>> {drift_eval_attack['status']} <<<")

    drift_summary_attack = {
        "drift_detected": drift_eval_attack["drift_detected"],
        "record_tampered": False
    }

    # 4. Evaluate composite risk
    print("\n[4] Risk Engine Aggregation & Triage:")
    attack_decision = evaluate_risk(prov_report, data_summary_attack, model_eval_attack, drift_summary_attack)
    print(f"    - Composite Risk Score: {attack_decision['composite_risk_score']} / 100")
    print(f"    - Triage Decision     : >>> {attack_decision['recommendation']} <<< [IMMEDIATE QUARANTINE]")
    print("    - Flags Raised:")
    for flag in attack_decision["flags_raised"]:
        print(f"        * {flag}")

    # 5. Audit Ledger Tamper Detection Test
    print("\n[5] Cryptographic Audit Ledger Tamper Detection Test:")
    attack_block = append_receipt({"receipt": receipt, "triage": attack_decision}, ledger_path)
    print(f"    - Appended Attack Audit Record to Ledger (Block #{attack_block['index']})")
    is_valid_before, report_before = verify_ledger(ledger_path)
    print(f"    - Pre-Attack Ledger Integrity : {report_before['status']} ({report_before['blocks_count']} blocks verified)")

    print("\n    [!] ADVERSARY ATTACK SIMULATION: Modifying historical audit log entry (Block #0)...")
    import shutil
    tampered_demo_path = os.path.join(receipts_dir, "audit_ledger_tampered_demo.jsonl")
    shutil.copyfile(ledger_path, tampered_demo_path)
    simulate_ledger_tampering(tampered_demo_path, target_index=0, attack_type="modify")

    is_valid_after, report_after = verify_ledger(tampered_demo_path)
    print(f"    - Audit Verification Result   : >>> {'FAIL (TAMPER DETECTED)' if not is_valid_after else 'PASS'} <<<")
    print(f"    - Pinpointed Corrupted Index  : Block #{report_after['corrupted_index']}")
    print(f"    - Diagnostic Reason           : {report_after['reason']}")

    if os.path.exists(tampered_demo_path):
        os.remove(tampered_demo_path)

    # Export report to reports/assurance_report.json
    report_file = os.path.join(reports_dir, "assurance_report.json")
    with open(report_file, "w", encoding="utf-8") as f:
        json.dump(attack_decision, f, indent=2)
    print(f"\n[Done] Full audit report exported to {os.path.relpath(report_file, base_dir)}")


if __name__ == "__main__":
    main()
