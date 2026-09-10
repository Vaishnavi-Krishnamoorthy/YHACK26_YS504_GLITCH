"""
AEGIS-CV Audit Ledger Test Suite
Challenge 22 | Team GLITCH (YS504)

Verifies:
1. Genesis block initialization and append-only cryptographic linking.
2. End-to-end chain verification on valid ledgers.
3. Modification attack detection pinpointing exact corrupted block index.
4. Deletion attack detection pinpointing exact corrupted block index.
"""

import os
import shutil
import tempfile
import unittest

from aegis.audit_ledger import (
    append_receipt,
    verify_ledger,
    read_ledger,
    simulate_ledger_tampering,
    GENESIS_PREVIOUS_HASH
)


class TestAuditLedger(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.ledger_path = os.path.join(self.test_dir, "audit_ledger.jsonl")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _create_sample_chain(self, count=5):
        blocks = []
        for i in range(count):
            receipt_data = {
                "run_id": f"run_{i + 1}",
                "dataset_sha256": f"hash_dataset_{i}",
                "model_sha256": f"hash_model_{i}",
                "status": "PASS",
                "risk_score": 5 * i
            }
            block = append_receipt(receipt_data, self.ledger_path)
            blocks.append(block)
        return blocks

    def test_genesis_and_chain_structure(self):
        blocks = self._create_sample_chain(count=3)
        self.assertEqual(len(blocks), 3)

        # Block 0 (Genesis) checks
        self.assertEqual(blocks[0]["index"], 0)
        self.assertEqual(blocks[0]["previous_block_hash"], GENESIS_PREVIOUS_HASH)

        # Linkage checks for Block 1 and Block 2
        self.assertEqual(blocks[1]["index"], 1)
        self.assertEqual(blocks[1]["previous_block_hash"], blocks[0]["block_hash"])

        self.assertEqual(blocks[2]["index"], 2)
        self.assertEqual(blocks[2]["previous_block_hash"], blocks[1]["block_hash"])

    def test_valid_ledger_verification(self):
        self._create_sample_chain(count=5)
        is_valid, report = verify_ledger(self.ledger_path)
        self.assertTrue(is_valid)
        self.assertEqual(report["status"], "INTACT")
        self.assertEqual(report["blocks_count"], 5)
        self.assertIsNone(report["corrupted_index"])

    def test_modification_attack_detection(self):
        """Simulates an attacker modifying an old audit log (e.g. index 2 from yesterday)."""
        self._create_sample_chain(count=5)
        target_corrupted_index = 2

        # Simulate tampering attack on block 2
        simulate_ledger_tampering(self.ledger_path, target_index=target_corrupted_index, attack_type="modify")

        is_valid, report = verify_ledger(self.ledger_path)
        self.assertFalse(is_valid)
        self.assertIn("TAMPERED", report["status"])
        self.assertEqual(report["corrupted_index"], target_corrupted_index)
        self.assertIn("Block hash integrity failure at block index 2", report["reason"])

    def test_deletion_attack_detection(self):
        """Simulates an attacker deleting an old audit log (e.g. index 2 from yesterday)."""
        self._create_sample_chain(count=5)
        target_deleted_index = 2

        # Simulate deletion attack on block 2
        simulate_ledger_tampering(self.ledger_path, target_index=target_deleted_index, attack_type="delete")

        is_valid, report = verify_ledger(self.ledger_path)
        self.assertFalse(is_valid)
        self.assertEqual(report["corrupted_index"], target_deleted_index)
        self.assertTrue(
            report["status"] in ("CORRUPTED_INDEX_SEQUENCE", "CHAIN_LINK_BROKEN")
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
