"""
Module 4: Cryptographic Provenance Chain & Merkle Tree Engine
Hashes pipeline components (dataset, model, config, output) and signs audit receipts.
"""

import os
import json
import hmac
import hashlib
from datetime import datetime, timezone

SECRET_KEY = b"aegis_offline_signing_key_2026"


def hash_file(filepath, chunk_size=65536):
    """Computes SHA-256 hash of a file in chunks to handle large files."""
    sha = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(chunk_size):
            sha.update(chunk)
    return sha.hexdigest()


def hash_string(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def build_merkle_root(hashes):
    """Constructs a Merkle tree from component hashes and returns the root digest."""
    if not hashes:
        return None
    current = list(hashes)
    while len(current) > 1:
        next_level = []
        for i in range(0, len(current), 2):
            left = current[i]
            right = current[i + 1] if i + 1 < len(current) else left
            next_level.append(hash_string(left + right))
        current = next_level
    return current[0]


def generate_receipt(files_dict, output_path=None):
    """Generates an HMAC-signed provenance receipt for registered files."""
    components = {}
    ordered_hashes = []

    for name, path in files_dict.items():
        if not os.path.exists(path):
            raise FileNotFoundError(f"Missing component: {path}")
        h = hash_file(path)
        components[name] = {
            "path": path,
            "sha256": h,
            "size_bytes": os.path.getsize(path)
        }
        ordered_hashes.append(h)

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
    """Re-hashes current files from disk and checks against the signed receipt."""
    expected_sig = hmac.new(SECRET_KEY, receipt["merkle_root"].encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected_sig, receipt.get("signature", "")):
        return False, {"error": "Receipt signature tampered", "tampered": ["receipt"]}

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
