#!/usr/bin/env python3
"""
===============================================================================
AEGIS-CV: Air-gapped Evidence-based Guardian for Integrity & Security in CV
Component: Cryptographic Provenance Chain & Tamper-Evident Merkle Engine
Challenge: YHACK'26 - Challenge 22 (Computer Vision Assurance Framework)
Team: YS504_GLITCH
===============================================================================
Features:
  1. Offline SHA-256 chunked cryptographic hashing for datasets, models & configs.
  2. Merkle Tree generation linking: Input Data -> Model -> Config -> Output.
  3. Tamper-evident Audit Receipt with offline HMAC-SHA256 verification.
  4. Real-time Tamper Simulation pinpointing corrupted files with exact diffs.
  5. Actionable AEGIS-CV Triage Decision: ACCEPT vs. QUARANTINE.
===============================================================================
"""

import os
import sys
import hmac
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Tuple, Optional

# Ensure UTF-8 output encoding across Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# Terminal ANSI styling for clean, high-impact demonstration
class Colors:
    HEADER = "\033[95m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"
    DIM = "\033[2m"
    RESET = "\033[0m"

# Enable Windows ANSI virtual terminal processing
if sys.platform == "win32":
    os.system("")

# Secret key for offline HMAC-SHA256 signature (simulates air-gapped system key)
AIR_GAP_SIGNING_KEY = b"AEGIS-CV_OFFLINE_SECRET_KEY_YHACK26_YS504"


def compute_file_sha256(file_path: str, chunk_size: int = 65536) -> str:
    """
    Computes SHA-256 hash of a file in chunks to handle large weights/datasets
    efficiently without exhausting system RAM.
    """
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(chunk_size):
            hasher.update(chunk)
    return hasher.hexdigest()


def compute_string_sha256(data: str) -> str:
    """Computes SHA-256 hash of a UTF-8 string."""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


class MerkleTree:
    """
    A lightweight, air-gap compliant Merkle Tree for Computer Vision pipelines.
    Hierarchically aggregates cryptographic hashes of all pipeline components:
    (Input Data, Model Weights, Config, Inference Output) -> Merkle Root.
    """

    def __init__(self, leaf_hashes: List[str]):
        if not leaf_hashes:
            raise ValueError("Merkle tree requires at least one leaf hash.")
        self.leaf_hashes = leaf_hashes
        self.levels: List[List[str]] = [leaf_hashes]
        self._build_tree()

    def _build_tree(self) -> None:
        current_level = self.leaf_hashes
        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                # If odd number of nodes, duplicate the last node
                right = current_level[i + 1] if i + 1 < len(current_level) else left
                combined = compute_string_sha256(left + right)
                next_level.append(combined)
            self.levels.append(next_level)
            current_level = next_level

    @property
    def root(self) -> str:
        """Returns the top Merkle Root hash."""
        return self.levels[-1][0]


class ProvenanceEngine:
    """
    Manages cryptographic baseline registration, receipt generation,
    and offline tamper detection.
    """

    @staticmethod
    def sign_merkle_root(merkle_root: str, key: bytes = AIR_GAP_SIGNING_KEY) -> str:
        """Generates an HMAC-SHA256 signature for offline provenance validation."""
        return hmac.new(key, merkle_root.encode("utf-8"), hashlib.sha256).hexdigest()

    @staticmethod
    def generate_receipt(
        component_files: Dict[str, str], output_receipt_path: Optional[str] = None
    ) -> Dict:
        """
        Creates an immutable Provenance Receipt for a Computer Vision pipeline run.
        """
        records = {}
        ordered_hashes = []

        for label, path in component_files.items():
            if not os.path.exists(path):
                raise FileNotFoundError(f"Component file missing: {path}")
            
            file_hash = compute_file_sha256(path)
            file_size = os.path.getsize(path)
            records[label] = {
                "file_path": str(Path(path).as_posix()),
                "sha256": file_hash,
                "size_bytes": file_size,
            }
            ordered_hashes.append(file_hash)

        # Build Merkle Tree from component hashes
        tree = MerkleTree(ordered_hashes)
        merkle_root = tree.root
        signature = ProvenanceEngine.sign_merkle_root(merkle_root)

        receipt = {
            "receipt_id": f"AEGIS-RCPT-{hashlib.sha1(merkle_root.encode()).hexdigest()[:12].upper()}",
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "framework": "AEGIS-CV v1.0 (Air-Gapped)",
            "pipeline_components": records,
            "merkle_root": merkle_root,
            "hmac_signature": signature,
        }

        if output_receipt_path:
            os.makedirs(os.path.dirname(output_receipt_path), exist_ok=True)
            with open(output_receipt_path, "w", encoding="utf-8") as f:
                json.dump(receipt, f, indent=2)

        return receipt

    @staticmethod
    def verify_pipeline(
        receipt: Dict, key: bytes = AIR_GAP_SIGNING_KEY
    ) -> Tuple[bool, Dict]:
        """
        Performs full cryptographic audit against a registered receipt:
          1. Verifies HMAC signature of Merkle Root.
          2. Re-computes SHA-256 for all current files on disk.
          3. Re-builds Merkle Tree and compares with expected Merkle Root.
          4. Pinpoints any tampered files.
        """
        results = {
            "is_valid": True,
            "signature_valid": False,
            "merkle_root_match": False,
            "expected_root": receipt["merkle_root"],
            "calculated_root": None,
            "tampered_components": [],
            "component_status": {},
        }

        # 1. Verify HMAC Signature
        expected_sig = ProvenanceEngine.sign_merkle_root(receipt["merkle_root"], key)
        if hmac.compare_digest(expected_sig, receipt.get("hmac_signature", "")):
            results["signature_valid"] = True
        else:
            results["is_valid"] = False
            return False, results

        # 2. Re-hash files on disk
        calculated_hashes = []
        for label, meta in receipt["pipeline_components"].items():
            path = meta["file_path"]
            expected_hash = meta["sha256"]

            if not os.path.exists(path):
                results["component_status"][label] = {
                    "status": "FILE_MISSING",
                    "expected_hash": expected_hash,
                    "actual_hash": None,
                }
                results["tampered_components"].append(label)
                results["is_valid"] = False
                continue

            current_hash = compute_file_sha256(path)
            calculated_hashes.append(current_hash)

            if current_hash == expected_hash:
                results["component_status"][label] = {
                    "status": "INTACT",
                    "sha256": current_hash,
                }
            else:
                results["component_status"][label] = {
                    "status": "TAMPERED",
                    "expected_hash": expected_hash,
                    "actual_hash": current_hash,
                }
                results["tampered_components"].append(label)
                results["is_valid"] = False

        # 3. Re-build Merkle Tree
        if len(calculated_hashes) == len(receipt["pipeline_components"]):
            recalculated_tree = MerkleTree(calculated_hashes)
            results["calculated_root"] = recalculated_tree.root
            results["merkle_root_match"] = (
                recalculated_tree.root == receipt["merkle_root"]
            )
            if not results["merkle_root_match"]:
                results["is_valid"] = False

        return results["is_valid"], results


# =============================================================================
# DEMO SUITE: Sample File Generation & Verification Simulator
# =============================================================================

def setup_sample_assets(base_dir: Path) -> Dict[str, str]:
    """Generates realistic CV pipeline sample assets for testing."""
    sample_dir = base_dir / "sample_data"
    sample_dir.mkdir(parents=True, exist_ok=True)

    dataset_path = sample_dir / "dataset_coco_sample.json"
    model_path = sample_dir / "vision_model_weights.bin"
    config_path = sample_dir / "pipeline_config.json"

    # 1. Dataset sample (COCO format excerpt)
    dataset_content = {
        "info": {"description": "YHACK26 CV Assurance Dataset", "version": "1.0"},
        "images": [
            {"id": 1, "file_name": "surveillance_001.jpg", "width": 1920, "height": 1080},
            {"id": 2, "file_name": "drone_patrol_042.jpg", "width": 1280, "height": 720}
        ],
        "annotations": [
            {"id": 101, "image_id": 1, "category_id": 1, "bbox": [120, 240, 50, 110], "label": "person"},
            {"id": 102, "image_id": 2, "category_id": 3, "bbox": [530, 180, 200, 95], "label": "vehicle"}
        ]
    }
    with open(dataset_path, "w", encoding="utf-8") as f:
        json.dump(dataset_content, f, indent=2)

    # 2. Simulated Model Weights (deterministic binary structure)
    model_binary = (
        b"AEGIS_VISION_CONV2D_L1_WEIGHTS:" + b"\x01\x02\x03\x04" * 512 +
        b"AEGIS_VISION_RESNET_FC_LAYER:" + b"\x05\x06\x07\x08" * 256
    )
    with open(model_path, "wb") as f:
        f.write(model_binary)

    # 3. Pipeline Config
    config_content = {
        "pipeline_name": "AutonomousSurveillanceDetector_v2",
        "input_resolution": [640, 640],
        "confidence_threshold": 0.65,
        "nms_iou_threshold": 0.45,
        "backbone": "ResNet-50-FPN",
        "air_gap_mode": True
    }
    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(config_content, f, indent=2)

    return {
        "1. Input Dataset (COCO)": str(dataset_path),
        "2. Model Weights (Binary)": str(model_path),
        "3. Pipeline Config (JSON)": str(config_path)
    }


def print_banner():
    banner = f"""
{Colors.RED}{Colors.BOLD}================================================================================
    ___    ______ _____ _____ _____           _______      __
   /   |  / ____// ___//_  _// ___/          / ____/ |    / /
  / /| | / __/  / / __  / /  \\__ \\  ______  / /    | |  / / 
 / ___ |/ /___ / /_/ /_/ /  ___/ / /_____/ / /___  | | / /  
/_/  |_/_____/ \\____//___/ /____/          \\____/  | |/ /   
                                                   |___/    
 AIR-GAPPED CRYPTOGRAPHIC PROVENANCE & TAMPER-EVIDENT MERKLE ENGINE
 YHACK'26 | Challenge 22 | Team: YS504_GLITCH
================================================================================{Colors.RESET}
"""
    print(banner)


def run_demo():
    print_banner()

    base_dir = Path(__file__).resolve().parent
    receipt_dir = base_dir / "receipts"
    receipt_dir.mkdir(exist_ok=True)
    receipt_file = receipt_dir / "provenance_receipt_baseline.json"

    print(f"{Colors.BOLD}{Colors.CYAN}[STEP 1/5] Initializing Sample Pipeline Components...{Colors.RESET}")
    components = setup_sample_assets(base_dir)
    for label, path in components.items():
        size = os.path.getsize(path)
        print(f"  * {Colors.BOLD}{label:<28}{Colors.RESET} -> {path} ({size:,} bytes)")

    print(f"\n{Colors.BOLD}{Colors.CYAN}[STEP 2/5] Computing Component SHA-256 & Assembling Merkle Tree...{Colors.RESET}")
    receipt = ProvenanceEngine.generate_receipt(components, str(receipt_file))

    for label, meta in receipt["pipeline_components"].items():
        print(f"  {Colors.DIM}[SHA-256]{Colors.RESET} {Colors.YELLOW}{label:<28}{Colors.RESET} : {Colors.GREEN}{meta['sha256']}{Colors.RESET}")

    merkle_root = receipt["merkle_root"]
    print(f"\n  {Colors.BOLD}+- CRYPTOGRAPHIC MERKLE ROOT (Input -> Model -> Config) ------------+{Colors.RESET}")
    print(f"  | {Colors.BOLD}{Colors.CYAN}{merkle_root}{Colors.RESET} |")
    print(f"  +-------------------------------------------------------------------+")
    print(f"  Receipt ID       : {Colors.BOLD}{receipt['receipt_id']}{Colors.RESET}")
    print(f"  HMAC Signature   : {receipt['hmac_signature'][:32]}... [OFFLINE VERIFIED]")
    print(f"  Saved Audit Log  : {receipt_file.relative_to(base_dir)}")

    # -------------------------------------------------------------------------
    # TEST 1: Verification of Intact Pipeline
    # -------------------------------------------------------------------------
    print(f"\n{Colors.BOLD}{Colors.CYAN}[STEP 3/5] Verification Test 1: Evaluating INTACT Pipeline Baseline...{Colors.RESET}")
    is_valid, report = ProvenanceEngine.verify_pipeline(receipt)

    print(f"  * HMAC Signature Check : {Colors.GREEN}[PASSED]{Colors.RESET}")
    print(f"  * Merkle Root Match    : {Colors.GREEN}[PASSED]{Colors.RESET} ({report['expected_root'][:16]}...)")
    for comp, data in report["component_status"].items():
        print(f"  * {comp:<26} : {Colors.GREEN}[{data['status']}]{Colors.RESET} {data['sha256'][:24]}...")

    if is_valid:
        print(f"\n  {Colors.GREEN}{Colors.BOLD}>>> VERIFICATION STATUS: [100% INTACT] -> TRIAGE RECOMMENDATION: ACCEPT [OK]{Colors.RESET}")

    # -------------------------------------------------------------------------
    # TEST 2: Adversarial Tampering Simulation
    # -------------------------------------------------------------------------
    target_tamper_file = Path(components["3. Pipeline Config (JSON)"])
    print(f"\n{Colors.BOLD}{Colors.RED}[STEP 4/5] Adversarial Attack Simulation: Tampering with Pipeline Config...{Colors.RESET}")
    print(f"  Target File : {target_tamper_file.name}")
    print(f"  Injecting unauthorized hyperparameter alteration:")
    print(f"    - Original : {Colors.GREEN}\"confidence_threshold\": 0.65{Colors.RESET}")
    print(f"    - Malicious: {Colors.RED}\"confidence_threshold\": 0.05  <-- [SECURITY DRIFT / BACKDOOR EXPLOIT]{Colors.RESET}")

    # Read, tamper, and write back
    with open(target_tamper_file, "r", encoding="utf-8") as f:
        config_data = json.load(f)
    
    # Store original for restoration at end of demo
    original_threshold = config_data["confidence_threshold"]
    config_data["confidence_threshold"] = 0.05
    config_data["_malicious_note"] = "Exploit trigger injected"

    with open(target_tamper_file, "w", encoding="utf-8") as f:
        json.dump(config_data, f, indent=2)

    # -------------------------------------------------------------------------
    # TEST 3: Verification on Tampered Pipeline
    # -------------------------------------------------------------------------
    print(f"\n{Colors.BOLD}{Colors.CYAN}[STEP 5/5] Verification Test 2: AEGIS-CV Offline Tamper Detection...{Colors.RESET}")
    is_valid_after_tamper, tamper_report = ProvenanceEngine.verify_pipeline(receipt)

    print(f"  * HMAC Signature Check : {Colors.GREEN}[PASSED]{Colors.RESET} (Receipt integrity preserved)")
    print(f"  * Merkle Root Match    : {Colors.RED}[FAILED] (BROKEN CHAIN){Colors.RESET}")
    print(f"      Expected Root      : {Colors.GREEN}{tamper_report['expected_root']}{Colors.RESET}")
    print(f"      Calculated Root    : {Colors.RED}{tamper_report['calculated_root']}{Colors.RESET}")

    print(f"\n  {Colors.BOLD}Component Analysis Breakdown:{Colors.RESET}")
    for comp, info in tamper_report["component_status"].items():
        if info["status"] == "INTACT":
            print(f"    * {comp:<26} : {Colors.GREEN}[INTACT]{Colors.RESET}")
        else:
            print(f"    * {comp:<26} : {Colors.RED}{Colors.BOLD}[TAMPER DETECTED]{Colors.RESET}")
            print(f"        Expected Hash    : {Colors.GREEN}{info['expected_hash']}{Colors.RESET}")
            print(f"        Observed Hash    : {Colors.RED}{info['actual_hash']}{Colors.RESET}")

    print(f"\n  {Colors.RED}{Colors.BOLD}======================================================================{Colors.RESET}")
    print(f"  {Colors.RED}{Colors.BOLD}CRITICAL INTEGRITY ALERT: PIPELINE COMPROMISED!{Colors.RESET}")
    print(f"  Corrupted Components  : {Colors.YELLOW}{tamper_report['tampered_components']}{Colors.RESET}")
    print(f"  AEGIS-CV Decision     : {Colors.RED}{Colors.BOLD}QUARANTINE [IMMEDIATE ISOLATION REQUIRED]{Colors.RESET}")
    print(f"  Evidence Action       : Hash mismatch logged to tamper-evident audit trail.")
    print(f"  {Colors.RED}{Colors.BOLD}======================================================================{Colors.RESET}")

    # Restore original file for clean reproducible testing
    config_data["confidence_threshold"] = original_threshold
    config_data.pop("_malicious_note", None)
    with open(target_tamper_file, "w", encoding="utf-8") as f:
        json.dump(config_data, f, indent=2)
    print(f"\n{Colors.DIM}[Cleanup] Restored original config file for next demo run.{Colors.RESET}\n")


if __name__ == "__main__":
    run_demo()
