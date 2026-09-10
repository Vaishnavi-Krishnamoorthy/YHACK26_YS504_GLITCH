# AEGIS-CV
**Air-gapped Evidence-based Guardian for Integrity & Security in Computer Vision**

**Event:** YHACK'26 — Challenge 22 (Computer Vision Assurance Framework)  
**Team:** GLITCH (Team ID: YS504)  
**Domain:** AI and Computer Vision  

---

## Team Members & Responsibilities

- **Vaishnavi (Team Leader)**: System architecture & overall risk decision logic
- **Vaishnavi K / S**: Cryptographic provenance chain, SHA-256 hashing & Merkle tree
- **Varshini R**: Dataset poison checks (FFT) & model weight fingerprinting
- **Tarun Pranav RS**: Inference drift monitoring & UI dashboard

---

## Project Overview

Computer vision models deployed in secure or air-gapped environments (surveillance, defense, edge devices) cannot rely on cloud servers to check model authenticity or detect tampering. If an attacker modifies training annotations, injects a backdoor, swaps model weights, or tweaks config files, the system can silently fail.

**AEGIS-CV** is an offline assurance tool that verifies pipeline integrity across three stages:
1. **Data layer**: Detects poisoned, mislabelled, or duplicate training samples.
2. **Model layer**: Verifies layer-wise weight integrity and probes for backdoor triggers.
3. **Inference & Config layer**: Detects distribution drift and catches any post-deployment file changes using cryptographic hash chains.

---

## Phase 1 Implementation (Current Working Prototype)

For Round 1, we implemented the **Cryptographic Provenance Engine** (`provenance_chain.py`):
- Uses chunked **SHA-256** to hash dataset files, binary model weights, and pipeline configs.
- Organizes the hashes into an in-memory **Merkle tree** to produce a single verifiable root hash.
- Signs the root with an offline **HMAC** signature and saves a local receipt (`receipts/baseline_receipt.json`).
- Re-verifies all files on disk before running inference:
  - If all hashes match: **ACCEPT**
  - If any file was modified: flags the exact corrupted file and triggers **QUARANTINE**.

---

## How to Run the Demo

The script uses Python's standard library (`hashlib`, `hmac`, `json`, `os`) so it has zero external dependencies and runs completely offline.

```bash
# Clone repository
git clone https://github.com/Vaishnavi-Krishnamoorthy/YHACK26_YS504_GLITCH.git
cd YHACK26_YS504_GLITCH

# Run provenance verification demo
python provenance_chain.py
```

### Sample Output:
```
==================================================
  AEGIS-CV: Provenance Chain & Integrity Check   
  Team: GLITCH (YS504) | Challenge 22             
==================================================

[1] Tracking pipeline components:
    - dataset       : sample_data/dataset_coco_sample.json (751 bytes)
    - model_weights : sample_data/vision_model_weights.bin (3132 bytes)
    - config        : sample_data/pipeline_config.json (230 bytes)

[2] Computing SHA-256 hashes and building Merkle Tree...
    - dataset       : 7d649fa02951cd0b6f8afe1be5ac42c05dbc876929bbaa5b7009582bdd314be1
    - model_weights : 9f34fc9437798b70b88f05cd457424dc38f12aec7df5259b0a4abf93d40e4114
    - config        : 9b4c1070d0f096001065fca38e8f8007d35f21bc4904f5feb31184caac344c66

    Merkle Root : 5647918c81a9ec7356a2a36320cc5405c39afff0983c51c52a4bb39c576b202e
    HMAC Sig    : 39084e3fecb626bbfdfb4e664f521a26...
    Saved to    : receipts/baseline_receipt.json

[3] Test 1: Verifying clean baseline...
    -> All component hashes match.
    -> Merkle root verified.
    -> Decision: ACCEPT [OK]

[4] Test 2: Simulating unauthorized file edit...
    Modifying sample_data/pipeline_config.json:
    Changing 'confidence_threshold' from 0.65 to 0.05

[5] Re-verifying pipeline after edit...
    -> Merkle root match: FAILED
       Expected: 5647918c81a9ec7356a2...
       Got:      36bf86baba5dcdef9a94...
    -> Tampered file detected: ['config']
       Expected hash: 9b4c1070d0f096001065fca38e8f8007d35f21bc4904f5feb31184caac344c66
       Actual hash:   b3280d18f4ca716d5f4fab103ebf30e40f448f5113dedb4c7ff8f46bb1835c06

    >>> ALERT: Integrity check failed! Decision: QUARANTINE

[Done] Restored original config file.
```

---

## Project Structure

```
YHACK26_YS504_GLITCH/
├── README.md               # Project documentation
├── provenance_chain.py     # Cryptographic hashing & Merkle tree verification
├── sample_data/            # Mock pipeline artifacts for local testing
│   ├── dataset_coco_sample.json
│   ├── vision_model_weights.bin
│   └── pipeline_config.json
└── receipts/               # Offline HMAC-signed receipts
    └── baseline_receipt.json
```

---

## Next Steps (Round 2 Roadmap)

- [ ] Add FFT-based frequency trigger scanner for training images (data poison detection).
- [ ] Add ONNX and PyTorch layer-by-layer weight hashing.
- [ ] Build a lightweight Streamlit dashboard for visual audit reporting.