"""
Module: YOLO Annotation Parser & Validator
Part of AEGIS-CV Data Assurance Engine (Module 1)
Supports Challenge 22 format compliance: COCO, YOLO, ONNX, and PyTorch.

Parses and verifies YOLO-format bounding box annotations:
  - Standard format: <class_id> <x_center> <y_center> <width> <height>
  - Coordinate bounds verification in normalized range [0.0, 1.0]
  - Degenerate box detection (zero/negative dimensions or collapsed areas)
  - Missing labels, empty files, and malformed token detection
"""

import os
from typing import List, Dict, Any, Optional, Tuple


def parse_yolo_line(line: str, line_number: int = 1) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """
    Parses a single line from a YOLO annotation file.
    Expected line format: class_id x_center y_center width height
    Returns (box_dict, error_message).
    """
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None, None

    tokens = stripped.split()
    if len(tokens) < 5:
        return None, f"Line {line_number}: Expected at least 5 values (class_id x_center y_center width height), found {len(tokens)}"

    # Parse class_id
    try:
        class_id = int(tokens[0])
    except ValueError:
        return None, f"Line {line_number}: Invalid class_id '{tokens[0]}', must be an integer"

    if class_id < 0:
        return None, f"Line {line_number}: Class ID cannot be negative ({class_id})"

    # Parse coordinates
    try:
        x_center = float(tokens[1])
        y_center = float(tokens[2])
        width = float(tokens[3])
        height = float(tokens[4])
    except ValueError:
        return None, f"Line {line_number}: Non-numeric bounding box coordinates found: {tokens[1:5]}"

    # Optional confidence score (e.g. from prediction dumps)
    confidence = None
    if len(tokens) >= 6:
        try:
            confidence = float(tokens[5])
        except ValueError:
            confidence = None

    box = {
        "class_id": class_id,
        "x_center": x_center,
        "y_center": y_center,
        "width": width,
        "height": height,
        "confidence": confidence,
        "line": line_number,
    }

    return box, None


def validate_box_geometry(box: Dict[str, Any]) -> List[str]:
    """
    Validates bounding box geometry:
      - Coordinate values in range [0.0, 1.0]
      - Degenerate box dimensions (width <= 0, height <= 0)
      - Box boundaries extending outside image [0.0, 1.0]
    """
    issues = []
    line_num = box.get("line", 1)
    xc, yc = box["x_center"], box["y_center"]
    w, h = box["width"], box["height"]

    # Check center coordinate bounds
    if not (0.0 <= xc <= 1.0):
        issues.append(f"Line {line_num}: x_center ({xc}) out of bounds [0.0, 1.0]")
    if not (0.0 <= yc <= 1.0):
        issues.append(f"Line {line_num}: y_center ({yc}) out of bounds [0.0, 1.0]")

    # Check degenerate dimensions
    if w <= 0.0 or h <= 0.0:
        issues.append(f"Line {line_num}: Degenerate box dimensions (width={w}, height={h} <= 0)")
    elif w > 1.0 or h > 1.0:
        issues.append(f"Line {line_num}: Dimension exceeds image scale [0.0, 1.0] (width={w}, height={h})")
    else:
        # Check box boundaries
        x_min = xc - (w / 2.0)
        x_max = xc + (w / 2.0)
        y_min = yc - (h / 2.0)
        y_max = yc + (h / 2.0)

        # Allow small epsilon tolerance for floating point rounding
        eps = 1e-4
        if x_min < -eps or x_max > 1.0 + eps or y_min < -eps or y_max > 1.0 + eps:
            issues.append(
                f"Line {line_num}: Bounding box edges exceed image frame "
                f"([x_min={x_min:.4f}, x_max={x_max:.4f}, y_min={y_min:.4f}, y_max={y_max:.4f}])"
            )

    return issues


def parse_yolo_file(file_path: str) -> Dict[str, Any]:
    """
    Parses a single YOLO annotation .txt file.
    Returns parsed bounding boxes, raw lines count, and parsing errors.
    """
    if not os.path.exists(file_path):
        return {
            "file": os.path.basename(file_path),
            "exists": False,
            "boxes": [],
            "issues": [f"File not found: {file_path}"]
        }

    boxes = []
    issues = []

    with open(file_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    non_comment_lines = [l for l in lines if l.strip() and not l.strip().startswith("#")]
    if not non_comment_lines:
        issues.append("File contains no bounding box annotations (missing labels)")

    for idx, line in enumerate(lines, start=1):
        box, err = parse_yolo_line(line, line_number=idx)
        if err:
            issues.append(err)
        elif box is not None:
            geom_issues = validate_box_geometry(box)
            issues.extend(geom_issues)
            boxes.append(box)

    return {
        "file": os.path.basename(file_path),
        "path": file_path,
        "exists": True,
        "total_lines": len(lines),
        "total_boxes": len(boxes),
        "boxes": boxes,
        "issues": issues,
        "valid": len(issues) == 0
    }


def validate_yolo_file(file_path: str, num_classes: Optional[int] = None) -> Dict[str, Any]:
    """
    Validates a single YOLO annotation file for data integrity,
    checking coordinates, degenerate boxes, and optional class boundaries.
    """
    parsed = parse_yolo_file(file_path)
    issues = list(parsed["issues"])

    if parsed["total_boxes"] == 0 and not issues:
        issues.append("Missing labels: zero bounding boxes found in file")

    if num_classes is not None:
        for box in parsed["boxes"]:
            cid = box["class_id"]
            if cid >= num_classes:
                issues.append(f"Line {box['line']}: class_id {cid} >= num_classes ({num_classes})")

    valid = len(issues) == 0 and parsed["total_boxes"] > 0
    return {
        "file": parsed["file"],
        "total_boxes": parsed["total_boxes"],
        "valid": valid,
        "is_empty": parsed["total_boxes"] == 0,
        "issues": issues,
        "status": "PASS" if valid else ("EMPTY_NO_LABELS" if parsed["total_boxes"] == 0 else "INVALID_ANNOTATIONS")
    }



def validate_yolo_dataset(
    annotation_paths_or_dir: Any,
    image_dir: Optional[str] = None,
    num_classes: Optional[int] = None
) -> Dict[str, Any]:
    """
    Audits an entire YOLO dataset (either a directory or list of file paths).
    Detects:
      - Coordinate bounds violations [0.0, 1.0]
      - Degenerate / negative bounding boxes
      - Missing labels (empty annotation files)
      - Missing annotation files for existing images (if image_dir provided)
    """
    files_to_check = []
    if isinstance(annotation_paths_or_dir, str):
        if os.path.isdir(annotation_paths_or_dir):
            for root, _, files in os.walk(annotation_paths_or_dir):
                for f in files:
                    if f.endswith(".txt"):
                        files_to_check.append(os.path.join(root, f))
        elif os.path.isfile(annotation_paths_or_dir):
            files_to_check.append(annotation_paths_or_dir)
    elif isinstance(annotation_paths_or_dir, (list, tuple)):
        files_to_check = list(annotation_paths_or_dir)

    total_boxes = 0
    clean_files = []
    corrupt_files = []
    empty_files = []
    all_issues = []

    for path in files_to_check:
        res = validate_yolo_file(path, num_classes=num_classes)
        total_boxes += res["total_boxes"]
        if res["is_empty"]:
            empty_files.append(res["file"])
            all_issues.append(f"{res['file']}: Missing labels (empty annotation file)")
        elif not res["valid"]:
            corrupt_files.append({"file": res["file"], "issues": res["issues"]})
            all_issues.extend([f"{res['file']}: {iss}" for iss in res["issues"]])
        else:
            clean_files.append(res["file"])

    missing_labels_for_images = []
    if image_dir and os.path.isdir(image_dir):
        image_extensions = (".png", ".jpg", ".jpeg", ".bmp", ".webp")
        for img in os.listdir(image_dir):
            if img.lower().endswith(image_extensions):
                base_name = os.path.splitext(img)[0]
                expected_txt = f"{base_name}.txt"
                found = any(os.path.basename(f) == expected_txt for f in files_to_check)
                if not found:
                    missing_labels_for_images.append(img)
                    all_issues.append(f"Missing YOLO annotation file for image '{img}'")

    is_clean = len(all_issues) == 0

    return {
        "scanned_files_count": len(files_to_check),
        "total_boxes": total_boxes,
        "clean_files_count": len(clean_files),
        "corrupt_files_count": len(corrupt_files),
        "empty_files_count": len(empty_files),
        "missing_labels_for_images": missing_labels_for_images,
        "is_clean": is_clean,
        "issues_found": all_issues,
        "status": "PASS" if is_clean else "ANOMALY_DETECTED"
    }


if __name__ == "__main__":
    import sys
    print("--- AEGIS-CV YOLO Parser Self-Test ---")
    demo_lines = [
        "0 0.5 0.5 0.2 0.3",       # Valid
        "1 1.2 0.4 0.1 0.2",       # Out of bounds x
        "2 0.3 0.3 -0.1 0.2",      # Degenerate width
        "malformed token text",     # Malformed
    ]
    for i, l in enumerate(demo_lines, 1):
        box, err = parse_yolo_line(l, i)
        print(f"Line {i}: Box={box}, Err={err}")
