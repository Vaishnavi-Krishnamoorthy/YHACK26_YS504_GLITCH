"""
AEGIS-CV Module: Cryptographic Chained Audit Ledger
Team: GLITCH (YS504) - YHACK'26 Challenge 22

Maintains a tamper-evident audit trail in air-gapped environments by linking
each audit receipt to the previous receipt's hash:
  Block_N = Hash(Receipt_N + Previous_Block_Hash)
"""

import os
import json
import hashlib
from datetime import datetime, timezone

GENESIS_PREVIOUS_HASH = "0" * 64
DEFAULT_LEDGER_PATH = os.path.join("receipts", "audit_ledger.jsonl")


def compute_block_hash(receipt_data, previous_block_hash):
    """
    Computes SHA-256 hash for a block.
    Combines canonical JSON representation of receipt_data with previous_block_hash.
    """
    canonical_receipt = json.dumps(receipt_data, sort_keys=True, separators=(",", ":"))
    payload = f"{canonical_receipt}{previous_block_hash}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def read_ledger(ledger_path=DEFAULT_LEDGER_PATH):
    """Reads all blocks from a JSONL ledger file."""
    if not os.path.exists(ledger_path):
        return []
    
    blocks = []
    with open(ledger_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                blocks.append(json.loads(line))
    return blocks


def append_receipt(receipt_data, ledger_path=DEFAULT_LEDGER_PATH):
    """
    Appends a new receipt to the chained audit ledger.
    Links the new receipt cryptographically to the previous block's hash.
    """
    os.makedirs(os.path.dirname(os.path.abspath(ledger_path)), exist_ok=True)
    existing_blocks = read_ledger(ledger_path)

    if not existing_blocks:
        index = 0
        previous_block_hash = GENESIS_PREVIOUS_HASH
    else:
        last_block = existing_blocks[-1]
        index = last_block["index"] + 1
        previous_block_hash = last_block["block_hash"]

    block_hash = compute_block_hash(receipt_data, previous_block_hash)
    timestamp = datetime.now(timezone.utc).isoformat()

    block = {
        "index": index,
        "timestamp": timestamp,
        "receipt": receipt_data,
        "previous_block_hash": previous_block_hash,
        "block_hash": block_hash
    }

    with open(ledger_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(block) + "\n")

    return block


def verify_ledger(ledger_path=DEFAULT_LEDGER_PATH):
    """
    Verifies the cryptographic integrity of the entire audit ledger chain
    from genesis (Block 0) to the latest recorded receipt.

    Returns:
        tuple: (is_valid: bool, details: dict)
        If corrupted, details contains corrupted_index pinpointing the exact broken block.
    """
    blocks = read_ledger(ledger_path)

    if not blocks:
        return True, {
            "status": "EMPTY",
            "blocks_count": 0,
            "corrupted_index": None,
            "message": "Audit ledger is empty or non-existent."
        }

    expected_prev_hash = GENESIS_PREVIOUS_HASH

    for i, block in enumerate(blocks):
        # 1. Verify index sequence
        if block.get("index") != i:
            return False, {
                "status": "CORRUPTED_INDEX_SEQUENCE",
                "corrupted_index": i,
                "reason": f"Block index sequence broken at line {i}: expected index {i}, found {block.get('index')}"
            }

        # 2. Verify link to previous block hash
        actual_prev_hash = block.get("previous_block_hash", "")
        if actual_prev_hash != expected_prev_hash:
            return False, {
                "status": "CHAIN_LINK_BROKEN",
                "corrupted_index": i,
                "reason": (
                    f"Previous block hash mismatch at block index {i}: "
                    f"expected '{expected_prev_hash[:16]}...', found '{actual_prev_hash[:16]}...'"
                )
            }

        # 3. Verify block hash recalculation over receipt content and prev hash
        receipt_data = block.get("receipt", {})
        recalculated_hash = compute_block_hash(receipt_data, actual_prev_hash)
        recorded_block_hash = block.get("block_hash", "")

        if recorded_block_hash != recalculated_hash:
            return False, {
                "status": "TAMPERED_RECEIPT_CONTENT",
                "corrupted_index": i,
                "reason": (
                    f"Block hash integrity failure at block index {i}: "
                    f"receipt data tampered. Recalculated '{recalculated_hash[:16]}...', recorded '{recorded_block_hash[:16]}...'"
                )
            }

        # Advance expected previous hash to current block's hash
        expected_prev_hash = recorded_block_hash

    return True, {
        "status": "INTACT",
        "blocks_count": len(blocks),
        "corrupted_index": None,
        "message": f"All {len(blocks)} blocks successfully verified. Chain is cryptographically intact."
    }


def simulate_ledger_tampering(ledger_path, target_index, attack_type="modify"):
    """
    Simulates an attack on the audit ledger by modifying or deleting an old record.
    Used for adversarial assurance testing.

    attack_type:
      - "modify": Alters receipt payload of target_index block
      - "delete": Deletes the block at target_index completely
    """
    blocks = read_ledger(ledger_path)
    if not blocks or target_index < 0 or target_index >= len(blocks):
        raise ValueError(f"Invalid target_index {target_index} for ledger with {len(blocks)} blocks.")

    if attack_type == "modify":
        blocks[target_index]["receipt"]["adversary_tampered"] = True
        blocks[target_index]["receipt"]["status"] = "ALTERED_BY_ATTACKER"
    elif attack_type == "delete":
        blocks.pop(target_index)
    else:
        raise ValueError(f"Unknown attack_type: {attack_type}")

    with open(ledger_path, "w", encoding="utf-8") as f:
        for b in blocks:
            f.write(json.dumps(b) + "\n")
