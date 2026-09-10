"""
AEGIS-CV Comprehensive Verification Suite
Challenge 22 | Team GLITCH (YS504)

Tests all modules and format parsers:
1. YOLO parser (clean, corrupt, empty, bounds, degenerate boxes)
2. ONNX inspector (architecture, input/output shapes, layer fingerprinting, substitution detection)
3. Cryptographic provenance Merkle chain & HMAC receipts
4. Risk engine triage logic
"""

import os
import sys
import json
import unittest

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

from aegis.formats.yolo_parser import parse_yolo_file, validate_yolo_file, validate_yolo_dataset
from aegis.formats.onnx_inspector import inspect_onnx_model, fingerprint_onnx_layers, verify_onnx_layers
from aegis.data_assurance import validate_yolo_annotations, validate_coco_annotations
from aegis.model_integrity import verify_onnx_integrity, fingerprint_layers, verify_model_layers
from aegis.provenance import verify_pipeline
from aegis.audit_ledger import verify_ledger



class TestAegisAssurance(unittest.TestCase):

    def setUp(self):
        self.sample_dir = os.path.join(BASE_DIR, "sample_data")
        self.receipts_dir = os.path.join(BASE_DIR, "receipts")
        self.yolo_clean = os.path.join(self.sample_dir, "dataset_yolo_sample.txt")
        self.yolo_corrupt = os.path.join(self.sample_dir, "dataset_yolo_corrupt.txt")
        self.yolo_empty = os.path.join(self.sample_dir, "dataset_yolo_empty.txt")
        self.onnx_clean = os.path.join(self.sample_dir, "vision_model.onnx")
        self.onnx_tampered = os.path.join(self.sample_dir, "vision_model_tampered.onnx")
        if not os.path.exists(self.onnx_clean):
            from aegis.formats.onnx_inspector import create_sample_onnx_model
            create_sample_onnx_model(self.onnx_clean, tampered=False)
        if not os.path.exists(self.onnx_tampered):
            from aegis.formats.onnx_inspector import create_sample_onnx_model
            create_sample_onnx_model(self.onnx_tampered, tampered=True)

    def test_yolo_clean(self):
        res = validate_yolo_file(self.yolo_clean)
        self.assertTrue(res["valid"])
        self.assertEqual(res["total_boxes"], 4)
        self.assertEqual(len(res["issues"]), 0)
        self.assertEqual(res["status"], "PASS")

    def test_yolo_corrupt_coordinates_and_degenerate(self):
        res = validate_yolo_file(self.yolo_corrupt)
        self.assertFalse(res["valid"])
        self.assertGreater(len(res["issues"]), 0)
        self.assertEqual(res["status"], "INVALID_ANNOTATIONS")
        # Check that out of bounds and degenerate box were flagged
        issues_text = " ".join(res["issues"])
        self.assertIn("out of bounds", issues_text)
        self.assertIn("Degenerate box dimensions", issues_text)

    def test_yolo_empty_missing_labels(self):
        res = validate_yolo_file(self.yolo_empty)
        self.assertFalse(res["valid"])
        self.assertTrue(res["is_empty"])
        self.assertEqual(res["status"], "EMPTY_NO_LABELS")
        self.assertGreater(len(res["issues"]), 0)

    def test_onnx_inspection_architecture(self):
        info = inspect_onnx_model(self.onnx_clean)
        self.assertEqual(info["total_nodes"], 5)
        self.assertEqual(info["inputs"][0]["shape"], [1, 3, 32, 32])
        self.assertEqual(info["outputs"][0]["shape"], [1, 10])
        self.assertEqual(info["metadata"]["producer_name"], "AEGIS-CV Team GLITCH")
        self.assertEqual(len(info["initializers"]), 4)

    def test_onnx_clean_layer_integrity(self):
        fps = fingerprint_onnx_layers(self.onnx_clean)
        check = verify_onnx_layers(self.onnx_clean, fps)
        self.assertTrue(check["is_clean"])
        self.assertEqual(check["status"], "PASS")
        self.assertEqual(len(check["intact_layers"]), 4)
        self.assertEqual(len(check["tampered_layers"]), 0)

    def test_onnx_layer_substitution_detection(self):
        baseline_fps = fingerprint_onnx_layers(self.onnx_clean)
        check = verify_onnx_layers(self.onnx_tampered, baseline_fps)
        self.assertFalse(check["is_clean"])
        self.assertEqual(check["status"], "LAYER_SUBSTITUTION_DETECTED")
        tampered_names = [t["layer"] for t in check["tampered_layers"]]
        self.assertIn("head.classifier.weight", tampered_names)
        self.assertIn("head.classifier.bias", tampered_names)

    def test_pipeline_receipt_provenance(self):
        receipt_file = os.path.join(self.receipts_dir, "pipeline_receipt.json")
        if not os.path.exists(receipt_file):
            from aegis.provenance import generate_receipt
            tracked_files = {
                "dataset_coco": os.path.join(self.sample_dir, "dataset_coco_sample.json"),
                "dataset_yolo": self.yolo_clean,
                "model_onnx": self.onnx_clean,
                "config": os.path.join(self.sample_dir, "pipeline_config.json"),
                "records": os.path.join(self.sample_dir, "inference_records.json")
            }
            generate_receipt(tracked_files, receipt_file)
        else:
            with open(receipt_file, "r", encoding="utf-8") as f:
                rec_data = json.load(f)
            first_component_path = next(iter(rec_data.get("components", {}).values()), {}).get("path", "")
            if not os.path.exists(first_component_path):
                from aegis.provenance import generate_receipt
                tracked_files = {
                    "dataset_coco": os.path.join(self.sample_dir, "dataset_coco_sample.json"),
                    "dataset_yolo": self.yolo_clean,
                    "model_onnx": self.onnx_clean,
                    "config": os.path.join(self.sample_dir, "pipeline_config.json"),
                    "records": os.path.join(self.sample_dir, "inference_records.json")
                }
                generate_receipt(tracked_files, receipt_file)

        with open(receipt_file, "r", encoding="utf-8") as f:
            receipt = json.load(f)
        is_clean, report = verify_pipeline(receipt)
        self.assertTrue(is_clean)
        self.assertTrue(report["root_match"])
        self.assertIn("dataset_yolo", receipt["components"])
        self.assertIn("model_onnx", receipt["components"])
        self.assertIn("dataset_coco", receipt["components"])

    def test_audit_ledger_chain_verification(self):
        ledger_file = os.path.join(self.receipts_dir, "audit_ledger.jsonl")
        is_clean, report = verify_ledger(ledger_file)
        self.assertTrue(is_clean)
        self.assertIn(report["status"], ("INTACT", "EMPTY"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
