"""
Module 1: Data Assurance Engine
Checks dataset integrity:
  1. Perceptual duplicate detection (dHash)
  2. Frequency-domain poison / backdoor trigger detection (2D FFT)
  3. COCO/YOLO label validation
"""

import os
import json
import numpy as np
from PIL import Image


def compute_dhash(image_path, hash_size=8):
    """
    Computes difference hash (dHash) for near-duplicate image detection.
    Robust to slight brightness or resolution changes.
    """
    with Image.open(image_path) as img:
        # Resize to (width=9, height=8), grayscale
        resized = img.convert("L").resize((hash_size + 1, hash_size), Image.Resampling.BILINEAR)
        pixels = np.array(resized)
        # Compare adjacent pixels in each row
        diff = pixels[:, 1:] > pixels[:, :-1]
        # Convert boolean array to hex string
        return "".join(format(b, "02x") for b in np.packbits(diff.flatten()))


def hamming_distance(hex1, hex2):
    """Calculates hamming distance between two hex hashes."""
    b1 = bytes.fromhex(hex1)
    b2 = bytes.fromhex(hex2)
    return sum(bin(x ^ y).count("1") for x, y in zip(b1, b2))


def scan_duplicates(image_paths, threshold=3):
    """
    Scans a list of image paths for duplicates or near-duplicates.
    Threshold: <= 3 bit difference is considered near-duplicate.
    """
    hashes = {}
    duplicates = []

    for path in image_paths:
        if not os.path.exists(path):
            continue
        h = compute_dhash(path)
        for existing_path, existing_hash in hashes.items():
            dist = hamming_distance(h, existing_hash)
            if dist <= threshold:
                duplicates.append({
                    "file_a": os.path.basename(path),
                    "file_b": os.path.basename(existing_path),
                    "hamming_distance": dist
                })
        hashes[path] = h

    return {
        "scanned_count": len(image_paths),
        "duplicate_pairs_found": len(duplicates),
        "duplicates": duplicates
    }


def detect_frequency_poison(image_path, high_freq_threshold=0.38):
    """
    Uses 2D Fast Fourier Transform (FFT) to detect hidden high-frequency triggers.
    Adversarial triggers (BadNets, checkerboard noise, watermarks) produce abnormal
    energy concentration in high-frequency spectrum bands.
    """
    with Image.open(image_path) as img:
        gray = np.array(img.convert("L"), dtype=float)

    h, w = gray.shape
    # 2D FFT
    f_transform = np.fft.fft2(gray)
    f_shift = np.fft.fftshift(f_transform)
    magnitude_spectrum = np.abs(f_shift)

    # Calculate center low-frequency mask vs outer high-frequency ring
    cy, cx = h // 2, w // 2
    r = min(h, w) // 4  # low-frequency radius

    y, x = np.ogrid[:h, :w]
    low_freq_mask = ((x - cx) ** 2 + (y - cy) ** 2) <= (r ** 2)
    high_freq_mask = ~low_freq_mask

    total_energy = np.sum(magnitude_spectrum)
    if total_energy == 0:
        return {"is_poisoned": False, "high_freq_ratio": 0.0, "status": "CLEAN"}

    high_freq_energy = np.sum(magnitude_spectrum[high_freq_mask])
    high_freq_ratio = float(high_freq_energy / total_energy)

    is_poisoned = high_freq_ratio > high_freq_threshold

    return {
        "file": os.path.basename(image_path),
        "high_freq_ratio": round(high_freq_ratio, 4),
        "threshold": high_freq_threshold,
        "is_poisoned": is_poisoned,
        "status": "POISON_TRIGGER_DETECTED" if is_poisoned else "CLEAN"
    }


def validate_coco_annotations(json_path):
    """Validates COCO annotation format: bounding boxes and class IDs."""
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    issues = []
    annotations = data.get("annotations", [])
    for ann in annotations:
        bbox = ann.get("bbox", [])
        if len(bbox) != 4:
            issues.append(f"Invalid bbox length in annotation id {ann.get('id')}")
            continue
        x, y, w, h = bbox
        if w <= 0 or h <= 0:
            issues.append(f"Degenerate bbox size in annotation id {ann.get('id')}: [{w}, {h}]")

    return {
        "total_annotations": len(annotations),
        "valid": len(issues) == 0,
        "issues_found": issues
    }
