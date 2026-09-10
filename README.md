# AEGIS-CV
**Air-gapped Evidence-based Guardian for Integrity & Security in Computer Vision**

**Event:** YHACK'26 — Challenge 22 (Computer Vision Assurance Framework)  
**Team:** GLITCH (Team ID: YS504)  
**Domain:** AI and Computer Vision  

---

## Team Members & Responsibilities

- **Vaishnavi (Team Leader)**: System architecture & composite risk scoring engine
- **Vaishnavi K / S**: Cryptographic provenance chain, SHA-256 hashing & Merkle tree
- **Varshini R**: FFT-based dataset poison detection & model layer fingerprinting
- **Tarun Pranav RS**: Inference drift monitoring & UI dashboard

---

## Project Overview

Computer vision models deployed in high-consequence offline or air-gapped environments (surveillance, defense, edge devices) cannot rely on cloud servers to check model authenticity or detect tampering. If an attacker modifies training annotations, injects a backdoor, swaps model weights, or tweaks config files, the system can silently fail.

**AEGIS-CV** is an offline assurance system that evaluates pipeline integrity across three stages:
1. **Data layer**: Detects poisoned, mislabelled, or duplicate training samples.
2. **Model layer**: Verifies layer-wise weight integrity and probes for backdoor triggers.
3. **Inference & Config layer**: Detects distribution drift and catches any post-deployment file changes using cryptographic hash chains.

---

## Architecture: 5 Integrated Modules

```
[INPUT DATA]             [AEGIS-CV ENGINES]                     [OUTPUT]
COCO Dataset     ──►  1. Data Assurance (FFT Poison, dHash) ──┐
Model Weights    ──►  2. Model Integrity (Layer Hashes)     ──┼─► 5. Risk Engine
Inference Logs   ──►  3. Inference Drift (OOD Z-Score)      ──┤      (0-100 Score)
Pipeline Config  ──►  4. Crypto Provenance (Merkle Tree)    ──┘      ACCEPT / QUARANTINE
                                                                     Audit Report (.json)
```

| Module | File | Implementation Technique |
|---|---|---|
| **Module 1: Data Assurance** | `aegis/data_assurance.py` | 2D Fast Fourier Transform (FFT) high-frequency trigger scanner + perceptual difference hashing (dHash) |
| **Module 2: Model Integrity** | `aegis/model_integrity.py` | Layer-by-layer SHA-256 fingerprinting + substitution detection + behavioral probing |
| **Module 3: Inference Drift** | `aegis/inference_drift.py` | Operational confidence distribution shift (Z-score OOD) + output record hashing |
| **Module 4: Crypto Provenance**| `aegis/provenance.py` | Hierarchical Merkle tree + offline HMAC-SHA256 signed audit receipts |
| **Module 5: Risk Engine** | `aegis/risk_engine.py` | Weighted composite risk scoring (0-100) + triage recommendations + JSON audit report |

---

## How to Run the System

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Launch the Interactive Web Dashboard (Streamlit)
```bash
streamlit run app.py
```
*Opens an interactive offline browser interface displaying:*
* Live Risk Score Gauge (0–100) and ACCEPT / REVIEW / QUARANTINE badges
* Visual 2D FFT Frequency Spectrum plots comparing clean vs. poisoned trigger images
* Layer-by-layer model fingerprint comparison table
* Cryptographic Merkle tree structure & HMAC receipt
* One-click audit report download

### 3. Run the CLI Review 2 Master Runner
```bash
python run_aegis.py
```

### 4. Run the Standalone Provenance Chain (Review 1)
```bash
python provenance_chain.py
```

---

## Project Structure

```
YHACK26_YS504_GLITCH/
├── README.md               # Project documentation & usage
├── requirements.txt        # Offline dependencies (numpy, Pillow, streamlit, matplotlib)
├── app.py                  # 🌟 Interactive Streamlit Web Dashboard
├── run_aegis.py            # Master CLI runner for Review 2 (all 5 modules)
├── provenance_chain.py     # Standalone provenance & Merkle demo (Review 1)
├── aegis/                  # Core package
│   ├── __init__.py
│   ├── data_assurance.py   # Module 1: FFT poison & dHash duplicate detection
│   ├── model_integrity.py  # Module 2: Layer-wise weight fingerprinting
│   ├── inference_drift.py  # Module 3: Distribution drift & output integrity
│   ├── provenance.py       # Module 4: Cryptographic Merkle tree engine
│   └── risk_engine.py      # Module 5: Composite scoring & triage logic
├── sample_data/            # Test assets
│   ├── sample_images/      # Clean, duplicate, and FFT poisoned images
│   ├── dataset_coco_sample.json
│   ├── vision_model_weights.bin
│   ├── pipeline_config.json
│   └── inference_records.json
├── receipts/               # Saved offline HMAC receipts
└── reports/                # Exported assurance audit reports (.json)
```

---

## Review Deliverables Checklist

- [x] **Problem Understanding**: Identified threats across data, model, and inference layers in air-gapped systems.
- [x] **Feasibility & Architecture**: Built 5 offline modules using standard cryptographic and vision algorithms.
- [x] **Development Planning**: Completed Phase 1 (Provenance), Phase 2 (Multi-engine integration), Phase 3 (Streamlit UI).
- [x] **Visible Prototype Progress**: Tested end-to-end with simulated attacks producing verified terminal and UI outputs.
- [x] **Originality**: Combines cryptographic hash receipts with computer-vision-specific frequency and layer analysis.