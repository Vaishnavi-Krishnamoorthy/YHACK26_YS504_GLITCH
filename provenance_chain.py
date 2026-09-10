#!/usr/bin/env python3
"""
AEGIS-CV: Cryptographic Provenance & Tamper Verification
Team: GLITCH (YS504) - YHACK'26 Challenge 22

This script verifies the integrity of an offline CV pipeline:
1. Hashes dataset, model weights, and config files with SHA-256.
2. Combines hashes into a Merkle tree to get a single root hash.
3. Saves a signed receipt locally for offline audit.
4. Verifies files against the receipt and flags any tampering.
"""

import os
import sys
import json
import hmac
import hashlib
from datetime import datetime, timezone
from pathlib import Path

# Local key used to sign audit receipts in air-gapped environment
SECRET_KEY = b"aegis_offline_signing_key_2026"


def hash_file(filepath, chunk_size=65536):
    """Hash a file in chunks to handle large datasets or model weights."""
    sha = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(chunk_size):
            sha.update(chunk)
    return sha.hexdigest()


def hash_string(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def build_merkle_root(hashes):
    """
    Builds a Merkle tree from a list of SHA-256 hashes
    and returns the top root hash.
    """
    if not hashes:
        return None
    
    current = list(hashes)
    while len(current) > 1:
        next_level = []
        for i in range(0, len(current), 2):
            left = current[i]
            # If odd count, pair with itself
            right = current[i + 1] if i + 1 < len(current) else left
            next_level.append(hash_string(left + right))
        current = next_level
    
    return current[0]


def generate_receipt(files_dict, output_path=None):
    """
    Hashes all pipeline files, builds Merkle root, signs it with HMAC,
    and returns receipt dictionary.
    """
    components = {}
    ordered_hashes = []

    for name, path in files_dict.items():
        if not os.path.exists(path):
            raise FileNotFoundError(f"Missing file: {path}")
        
        file_hash = hash_file(path)
        file_size = os.path.getsize(path)
        components[name] = {
            "path": path,
            "sha256": file_hash,
            "size_bytes": file_size
        }
        ordered_hashes.append(file_hash)

    merkle_root = build_merkle_root(ordered_hashes)
    signature = hmac.new(SECRET_KEY, merkle_root.encode(), hashlib.sha256).hexdigest()

    receipt = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "components": components,
        "merkle_root": merkle_root,
        "signature": signature
    }

    if output_path:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(receipt, f, indent=2)

    return receipt


def verify_pipeline(receipt):
    """
    Checks if files currently on disk match the hashes in the receipt.
    Returns (is_valid, report_dict).
    """
    # 1. Verify receipt signature
    expected_sig = hmac.new(SECRET_KEY, receipt["merkle_root"].encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected_sig, receipt.get("signature", "")):
        return False, {"error": "Invalid receipt signature (receipt itself was modified)"}

    # 2. Check each file on disk
    component_results = {}
    current_hashes = []
    tampered_files = []

    for name, meta in receipt["components"].items():
        path = meta["path"]
        expected_hash = meta["sha256"]

        if not os.path.exists(path):
            component_results[name] = {"status": "MISSING"}
            tampered_files.append(name)
            continue

        actual_hash = hash_file(path)
        current_hashes.append(actual_hash)

        if actual_hash == expected_hash:
            component_results[name] = {"status": "OK", "hash": actual_hash}
        else:
            component_results[name] = {
                "status": "TAMPERED",
                "expected": expected_hash,
                "actual": actual_hash
            }
            tampered_files.append(name)

    # 3. Verify Merkle root matches
    calculated_root = build_merkle_root(current_hashes)
    root_match = (calculated_root == receipt["merkle_root"])

    is_clean = (len(tampered_files) == 0) and root_match
    return is_clean, {
        "is_clean": is_clean,
        "root_match": root_match,
        "expected_root": receipt["merkle_root"],
        "calculated_root": calculated_root,
        "components": component_results,
        "tampered": tampered_files
    }


# -----------------------------------------------------------------------------
# Demo helpers
# -----------------------------------------------------------------------------

def create_sample_files(base_dir):
    """Create sample dummy files to test the pipeline."""
    data_dir = os.path.join(base_dir, "sample_data")
    os.makedirs(data_dir, exist_ok=True)

    dataset_file = os.path.join(data_dir, "dataset_coco_sample.json")
    model_file = os.path.join(data_dir, "vision_model_weights.bin")
    config_file = os.path.join(data_dir, "pipeline_config.json")

    # Sample dataset annotations (COCO format excerpt)
    if not os.path.exists(dataset_file):
        dataset_content = {
            "info": {"year": 2026, "version": "1.0", "description": "COCO sample dataset"},
            "images": [{"id": 1, "file_name": "frame_001.jpg", "width": 640, "height": 480}],
            "annotations": [{"id": 1, "image_id": 1, "category_id": 1, "bbox": [100, 150, 50, 80]}]
        }
        with open(dataset_file, "w") as f:
            json.dump(dataset_content, f, indent=2)

    # Sample binary model weights
    if not os.path.exists(model_file):
        with open(model_file, "wb") as f:
            f.write(b"RESNET50_WEIGHT_DUMP_SAMPLE_BLOCK_" + (b"\x00\x01\x02\x03" * 256))

    # Sample pipeline config
    if not os.path.exists(config_file):
        config_content = {
            "model_name": "resnet50_detector",
            "input_size": [640, 640],
            "confidence_threshold": 0.65,
            "nms_threshold": 0.45
        }
        with open(config_file, "w") as f:
            json.dump(config_content, f, indent=2)

    return {
        "dataset": dataset_file,
        "model_weights": model_file,
        "config": config_file
    }


def main():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    receipt_file = os.path.join(base_dir, "receipts", "baseline_receipt.json")

    print("==================================================")
    print("  AEGIS-CV: Provenance Chain & Integrity Check   ")
    print("  Team: GLITCH (YS504) | Challenge 22             ")
    print("==================================================")

    # Step 1: Set up sample files
    files = create_sample_files(base_dir)
    print("\n[1] Tracking pipeline components:")
    for name, path in files.items():
        print(f"    - {name:<14}: {os.path.relpath(path, base_dir)} ({os.path.getsize(path)} bytes)")

    # Step 2: Generate baseline receipt
    print("\n[2] Computing SHA-256 hashes and building Merkle Tree...")
    receipt = generate_receipt(files, receipt_file)

    for name, data in receipt["components"].items():
        print(f"    - {name:<14}: {data['sha256']}")

    print(f"\n    Merkle Root : {receipt['merkle_root']}")
    print(f"    HMAC Sig    : {receipt['signature'][:32]}...")
    print(f"    Saved to    : {os.path.relpath(receipt_file, base_dir)}")

    # Step 3: Test clean verification
    print("\n[3] Test 1: Verifying clean baseline...")
    is_valid, report = verify_pipeline(receipt)
    if is_valid:
        print("    -> All component hashes match.")
        print("    -> Merkle root verified.")
        print("    -> Decision: ACCEPT [OK]")
    else:
        print("    -> Verification failed unexpectedly.")

    # Step 4: Simulate tampering
    config_path = files["config"]
    print("\n[4] Test 2: Simulating unauthorized file edit...")
    print(f"    Modifying {os.path.relpath(config_path, base_dir)}:")
    print("    Changing 'confidence_threshold' from 0.65 to 0.05")

    with open(config_path, "r") as f:
        cfg = json.load(f)
    old_val = cfg["confidence_threshold"]
    cfg["confidence_threshold"] = 0.05
    with open(config_path, "w") as f:
        json.dump(cfg, f, indent=2)

    # Step 5: Verify tampered state
    is_valid, report = verify_pipeline(receipt)
    print("\n[5] Re-verifying pipeline after edit...")
    if not is_valid:
        print(f"    -> Merkle root match: FAILED")
        print(f"       Expected: {report['expected_root'][:20]}...")
        print(f"       Got:      {report['calculated_root'][:20]}...")
        print(f"    -> Tampered file detected: {report['tampered']}")
        
        tampered_meta = report["components"][report["tampered"][0]]
        print(f"       Expected hash: {tampered_meta['expected']}")
        print(f"       Actual hash:   {tampered_meta['actual']}")
        print("\n    >>> ALERT: Integrity check failed! Decision: QUARANTINE")
    else:
        print("    -> Tamper was not detected!")

    # Cleanup: restore config file so it can be re-tested cleanly
    cfg["confidence_threshold"] = old_val
    with open(config_path, "w") as f:
        json.dump(cfg, f, indent=2)
    print("\n[Done] Restored original config file.")


if __name__ == "__main__":
    main()
