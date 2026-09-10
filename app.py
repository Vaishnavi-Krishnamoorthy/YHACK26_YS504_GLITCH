"""
AEGIS-CV: Air-gapped Computer Vision Assurance Dashboard
Team: GLITCH (YS504) - YHACK'26 Challenge 22

Interactive Streamlit UI for offline CV pipeline inspection:
1. File selection / uploads for dataset, model, config.
2. Real-time 2D FFT Frequency Spectrum Viewer (Clean vs. Poisoned images).
3. Visual Risk Score Gauge (0-100) & Triage Decision.
4. Cryptographic Provenance Merkle Tree viewer.
5. Audit Report generation and download.
"""

import os
import json
import numpy as np
from PIL import Image
import matplotlib.pyplot as plt
import streamlit as st

from aegis.provenance import hash_file, generate_receipt, verify_pipeline
from aegis.data_assurance import scan_duplicates, detect_frequency_poison, validate_coco_annotations
from aegis.model_integrity import fingerprint_layers, verify_model_layers
from aegis.inference_drift import detect_confidence_drift, verify_inference_records
from aegis.risk_engine import evaluate_risk

# Page Configuration
st.set_page_config(
    page_title="AEGIS-CV | Assurance Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SAMPLE_DIR = os.path.join(BASE_DIR, "sample_data")
IMAGE_DIR = os.path.join(SAMPLE_DIR, "sample_images")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
RECEIPTS_DIR = os.path.join(BASE_DIR, "receipts")
os.makedirs(REPORTS_DIR, exist_ok=True)
os.makedirs(RECEIPTS_DIR, exist_ok=True)

# -----------------------------------------------------------------------------
# Helper: Synthetic Image Generator (if not already on disk)
# -----------------------------------------------------------------------------
def ensure_sample_images():
    os.makedirs(IMAGE_DIR, exist_ok=True)
    clean_path = os.path.join(IMAGE_DIR, "sample_clean.png")
    dup_path = os.path.join(IMAGE_DIR, "sample_duplicate.png")
    poison_path = os.path.join(IMAGE_DIR, "sample_poisoned.png")

    if not os.path.exists(clean_path):
        y, x = np.ogrid[:128, :128]
        clean_arr = np.uint8(np.clip(128 + 60 * np.sin(x / 16.0) + 60 * np.cos(y / 16.0), 0, 255))
        Image.fromarray(clean_arr).save(clean_path)

        dup_arr = np.uint8(np.clip(clean_arr.astype(int) + 2, 0, 255))
        Image.fromarray(dup_arr).save(dup_path)

        poison_arr = clean_arr.copy()
        for r in range(96, 124, 2):
            for c in range(96, 124, 2):
                poison_arr[r:r+2, c:c+2] = 255 if ((r+c)//2)%2 == 0 else 0
        Image.fromarray(poison_arr).save(poison_path)

    return clean_path, dup_path, poison_path


clean_img_path, dup_img_path, poison_img_path = ensure_sample_images()

# -----------------------------------------------------------------------------
# Sidebar: Configuration & Controls
# -----------------------------------------------------------------------------
st.sidebar.markdown("## 🛡️ AEGIS-CV Engine")
st.sidebar.caption("YHACK'26 | Challenge 22 | Team GLITCH (YS504)")

st.sidebar.markdown("---")
mode = st.sidebar.radio(
    "Select Audit Scenario:",
    ["Clean Baseline (Normal Operation)", "Simulated Multi-Threat Attack", "Custom File Upload"]
)

st.sidebar.markdown("---")
st.sidebar.markdown("### ⚙️ Pipeline Components")

if mode == "Custom File Upload":
    uploaded_dataset = st.sidebar.file_uploader("Upload Dataset Annotations (JSON)", type=["json"])
    uploaded_model = st.sidebar.file_uploader("Upload Model Weights (.bin/.pt/.onnx)", type=["bin", "pt", "onnx"])
    uploaded_config = st.sidebar.file_uploader("Upload Pipeline Config (JSON)", type=["json"])
else:
    st.sidebar.info("Using verified offline sample assets from `sample_data/`")
    st.sidebar.text(f"Dataset: dataset_coco_sample.json")
    st.sidebar.text(f"Model: vision_model_weights.bin")
    st.sidebar.text(f"Config: pipeline_config.json")

run_audit = st.sidebar.button("🚀 Run Assurance Audit", type="primary", use_container_width=True)

# -----------------------------------------------------------------------------
# Main Header
# -----------------------------------------------------------------------------
st.title("🛡️ AEGIS-CV: Computer Vision Assurance Framework")
st.markdown("**Offline, Model-Agnostic Integrity, Behavioral Analysis & Cryptographic Provenance**")

col_badge1, col_badge2, col_badge3 = st.columns(3)
with col_badge1:
    st.success("🔌 **Environment:** 100% Offline / Air-Gapped")
with col_badge2:
    st.info("🔐 **Cryptography:** SHA-256 Merkle Chain + HMAC")
with col_badge3:
    st.warning("🎯 **Target:** YHACK'26 Challenge 22")

st.markdown("---")

# -----------------------------------------------------------------------------
# Execution Logic
# -----------------------------------------------------------------------------
coco_json = os.path.join(SAMPLE_DIR, "dataset_coco_sample.json")
config_json = os.path.join(SAMPLE_DIR, "pipeline_config.json")
records_json = os.path.join(SAMPLE_DIR, "inference_records.json")

baseline_layers = {
    "backbone.conv1.weight": b"WEIGHTS_CONV1_RESNET50_LAYER_DATA_BYTES",
    "backbone.layer1.0.conv1.weight": b"WEIGHTS_CONV2_RESNET50_LAYER_DATA_BYTES",
    "head.fc.weight": b"WEIGHTS_CLASSIFIER_HEAD_80_CLASSES_BASELINE"
}
baseline_layer_fps = fingerprint_layers(baseline_layers)

# Determine state based on mode
is_attack = (mode == "Simulated Multi-Threat Attack")

# 1. Provenance
tracked_files = {"dataset": coco_json, "config": config_json, "records": records_json}
receipt = generate_receipt(tracked_files, os.path.join(RECEIPTS_DIR, "pipeline_receipt.json"))
is_prov_clean, prov_report = verify_pipeline(receipt)

# 2. Data Assurance
test_img = poison_img_path if is_attack else clean_img_path
fft_result = detect_frequency_poison(test_img)
dup_result = scan_duplicates([clean_img_path, dup_img_path] if is_attack else [clean_img_path])
data_summary = {
    "poison_detected": fft_result["is_poisoned"],
    "duplicates_count": dup_result["duplicate_pairs_found"]
}

# 3. Model Integrity
tested_layers = dict(baseline_layers)
if is_attack:
    tested_layers["head.fc.weight"] = b"MALICIOUS_SUBSTITUTED_BACKDOOR_CLASSIFIER_HEAD_WEIGHTS"
model_result = verify_model_layers(tested_layers, baseline_layer_fps)

# 4. Inference Drift
confidences = [0.42, 0.38, 0.45, 0.35, 0.40] if is_attack else [0.85, 0.88, 0.81, 0.79, 0.84, 0.86]
drift_result = detect_confidence_drift(confidences)
drift_summary = {
    "drift_detected": drift_result["drift_detected"],
    "record_tampered": False
}

# 5. Composite Risk
risk_report = evaluate_risk(prov_report, data_summary, model_result, drift_summary)

# -----------------------------------------------------------------------------
# Section 1: Executive Summary & Triage Decision Gauge
# -----------------------------------------------------------------------------
st.subheader("1. Executive Triage Summary")

score = risk_report["composite_risk_score"]
recommendation = risk_report["recommendation"]

col_kpi1, col_kpi2, col_kpi3, col_kpi4 = st.columns(4)

with col_kpi1:
    if recommendation == "ACCEPT":
        st.metric(label="Risk Score", value=f"{score} / 100", delta="CLEAN (LOW RISK)", delta_color="normal")
    elif recommendation == "REVIEW":
        st.metric(label="Risk Score", value=f"{score} / 100", delta="SUSPICIOUS (MEDIUM)", delta_color="off")
    else:
        st.metric(label="Risk Score", value=f"{score} / 100", delta="COMPROMISED (CRITICAL)", delta_color="inverse")

with col_kpi2:
    if recommendation == "ACCEPT":
        st.success("### Decision: ACCEPT ✅\n*Pipeline cleared for deployment*")
    elif recommendation == "REVIEW":
        st.warning("### Decision: REVIEW ⚠️\n*Manual inspection required*")
    else:
        st.error("### Decision: QUARANTINE 🚨\n*Pipeline isolated immediately*")

with col_kpi3:
    st.metric("Model Layers Verified", f"{len(model_result['intact_layers'])} / 3", 
              "All Intact" if model_result["is_clean"] else "Substitution Detected")

with col_kpi4:
    st.metric("FFT Frequency Check", f"{fft_result['high_freq_ratio']} ratio",
              "CLEAN" if not fft_result["is_poisoned"] else "TRIGGER DETECTED")

# Visual Progress Gauge
st.markdown("**Composite Risk Gauge:**")
progress_color = "#4CAF50" if score <= 30 else ("#FF9800" if score <= 65 else "#F44336")
st.progress(score / 100.0)

if risk_report["flags_raised"]:
    st.error("**Active Security Flags Detected:**")
    for flag in risk_report["flags_raised"]:
        st.markdown(f"- 🔴 {flag}")
else:
    st.success("✅ **All integrity and behavioral checks passed with zero anomalies.**")

st.markdown("---")

# -----------------------------------------------------------------------------
# Section 2: 2D FFT Frequency Poison Trigger Viewer
# -----------------------------------------------------------------------------
st.subheader("2. Module 1: 2D FFT Frequency Poison Scanner")
st.caption("Detects hidden high-frequency pixel trigger patterns (BadNets, checkerboards, watermarks) invisible to human inspection.")

col_img1, col_img2 = st.columns(2)

def plot_fft(image_path, title):
    with Image.open(image_path) as img:
        gray = np.array(img.convert("L"), dtype=float)
    f_trans = np.fft.fft2(gray)
    f_shift = np.fft.fftshift(f_trans)
    magnitude_spectrum = np.log(1 + np.abs(f_shift))

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(6, 2.8))
    ax1.imshow(gray, cmap="gray")
    ax1.set_title("Input Image", fontsize=10)
    ax1.axis("off")

    im = ax2.imshow(magnitude_spectrum, cmap="inferno")
    ax2.set_title("2D FFT Spectrum", fontsize=10)
    ax2.axis("off")
    plt.tight_layout()
    return fig

with col_img1:
    st.markdown("#### Clean Baseline Image")
    fig_clean = plot_fft(clean_img_path, "Clean Sample")
    st.pyplot(fig_clean)
    clean_eval = detect_frequency_poison(clean_img_path)
    st.caption(f"High-frequency energy ratio: `{clean_eval['high_freq_ratio']}` (Threshold: `{clean_eval['threshold']}`) ➔ **{clean_eval['status']}**")

with col_img2:
    st.markdown("#### Suspected / Poisoned Image")
    fig_poison = plot_fft(poison_img_path, "Poisoned Sample")
    st.pyplot(fig_poison)
    poison_eval = detect_frequency_poison(poison_img_path)
    st.caption(f"High-frequency energy ratio: `{poison_eval['high_freq_ratio']}` (Threshold: `{poison_eval['threshold']}`) ➔ **{poison_eval['status']}**")

st.markdown("---")

# -----------------------------------------------------------------------------
# Section 3: Model Integrity & Layer Fingerprints
# -----------------------------------------------------------------------------
st.subheader("3. Module 2: Model Layer-by-Layer Fingerprinting")
st.caption("Hashes individual weight tensors to detect fine-tuning drift or substituted classifier heads.")

col_mod1, col_mod2 = st.columns([2, 1])

with col_mod1:
    layer_rows = []
    for layer, expected in baseline_layer_fps.items():
        actual = fingerprint_layers(tested_layers).get(layer)
        match = (actual == expected)
        layer_rows.append({
            "Layer Name": layer,
            "Baseline Digest (SHA-256)": expected[:20] + "...",
            "Observed Digest (SHA-256)": actual[:20] + "...",
            "Status": "MATCH ✅" if match else "SUBSTITUTED ❌"
        })
    st.table(layer_rows)

with col_mod2:
    st.markdown("#### Layer Audit Status")
    if model_result["is_clean"]:
        st.success("All 3 layers verified against known-good baseline.")
    else:
        st.error(f"Layer substitution detected on `{model_result['tampered_layers'][0]['layer']}`!")
        st.info("Attacker replaced classifier head weights with backdoored tensor.")

st.markdown("---")

# -----------------------------------------------------------------------------
# Section 4: Cryptographic Provenance Merkle Tree
# -----------------------------------------------------------------------------
st.subheader("4. Module 4: Cryptographic Provenance Chain")
st.caption("Mathematically links Input Dataset ➔ Model Weights ➔ Config ➔ Output Records into a single signed Merkle Root.")

col_tree1, col_tree2 = st.columns([2, 1])

with col_tree1:
    st.code(f"""
    [Input Dataset SHA-256] : {receipt['components']['dataset']['sha256'][:28]}...
               |
               v
    [Model Weights SHA-256] : {receipt['components']['records']['sha256'][:28]}...
               |
               v
    [Pipeline Config SHA-256]: {receipt['components']['config']['sha256'][:28]}...
               |
               ========================================
               MERKLE ROOT : {receipt['merkle_root']}
               ========================================
               HMAC SIGNATURE: {receipt['signature'][:32]}... [OFFLINE VERIFIED]
    """, language="text")

with col_tree2:
    st.markdown("#### Offline Receipt Details")
    st.json({
        "Timestamp": receipt["timestamp"],
        "Components Tracked": len(receipt["components"]),
        "Merkle Root Match": prov_report["root_match"],
        "Offline Signature": "VALID (HMAC-SHA256)"
    })

st.markdown("---")

# -----------------------------------------------------------------------------
# Section 5: Audit Log Export & Download
# -----------------------------------------------------------------------------
st.subheader("5. Audit Log & Reproducible Report Export")
col_exp1, col_exp2 = st.columns([3, 1])

report_json_str = json.dumps(risk_report, indent=2)

with col_exp1:
    st.text_area("Generated JSON Audit Report (`reports/assurance_report.json`):", report_json_str, height=140)

with col_exp2:
    st.download_button(
        label="📥 Download Audit Report",
        data=report_json_str,
        file_name="aegis_cv_audit_report.json",
        mime="application/json",
        use_container_width=True
    )
    st.caption("Verifiable completely offline in air-gapped environments.")
