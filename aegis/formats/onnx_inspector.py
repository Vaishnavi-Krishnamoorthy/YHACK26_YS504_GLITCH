"""
Module: ONNX Model Inspector & Substitution Detector
Part of AEGIS-CV Model Integrity Engine (Module 2)
Supports Challenge 22 format compliance: COCO, YOLO, ONNX, and PyTorch.

Inspects .onnx models offline:
  - Extracts model metadata, inputs/outputs dimensions, and node graph topology.
  - Computes individual SHA-256 fingerprints for each layer's weights/biases.
  - Detects layer substitution attacks (fine-tuned drift or swapped classifier heads).
"""

import os
import hashlib
from typing import Dict, Any, List, Optional, Tuple
import numpy as np

try:
    import onnx
    from onnx import helper, TensorProto, numpy_helper
    ONNX_AVAILABLE = True
except ImportError:
    ONNX_AVAILABLE = False


# Map ONNX TensorProto data types to human-readable names
TENSOR_TYPE_MAP = {
    1: "FLOAT",
    2: "UINT8",
    3: "INT8",
    4: "UINT16",
    5: "INT16",
    6: "INT32",
    7: "INT64",
    8: "STRING",
    9: "BOOL",
    10: "FLOAT16",
    11: "DOUBLE",
    12: "UINT32",
    13: "UINT64",
    14: "COMPLEX64",
    15: "COMPLEX128",
    16: "BFLOAT16",
}


def _get_type_name(elem_type: int) -> str:
    return TENSOR_TYPE_MAP.get(elem_type, f"TYPE_{elem_type}")


def _extract_shape(type_proto) -> List[Any]:
    """Extracts dimension list from an ONNX TypeProto."""
    shape = []
    if type_proto.HasField("tensor_type") and type_proto.tensor_type.HasField("shape"):
        for d in type_proto.tensor_type.shape.dim:
            if d.HasField("dim_value"):
                shape.append(d.dim_value)
            elif d.HasField("dim_param"):
                shape.append(d.dim_param)
            else:
                shape.append("?")
    return shape


def inspect_onnx_model(model_path: str) -> Dict[str, Any]:
    """
    Parses an ONNX model file and inspects its internal architecture:
      - Model version & opset
      - Input and output tensor names, types, and dimensions
      - Computational nodes (Conv, Relu, Gemm, etc.)
      - Weight/bias initializers with per-tensor SHA-256 fingerprints
    """
    if not os.path.exists(model_path):
        raise FileNotFoundError(f"ONNX model file not found: {model_path}")

    if not ONNX_AVAILABLE:
        raise RuntimeError("The 'onnx' Python package is required to inspect ONNX models.")

    model = onnx.load(model_path)
    graph = model.graph

    # Model metadata
    opset_versions = {}
    for entry in model.opset_import:
        domain = entry.domain or "ai.onnx"
        opset_versions[domain] = entry.version

    metadata = {
        "ir_version": model.ir_version,
        "producer_name": model.producer_name,
        "producer_version": model.producer_version,
        "opset_versions": opset_versions,
        "doc_string": model.doc_string,
        "model_file": os.path.basename(model_path),
        "file_size_bytes": os.path.getsize(model_path),
    }

    # Extract inputs (excluding initializers)
    initializer_names = set(init.name for init in graph.initializer)
    inputs = []
    for inp in graph.input:
        if inp.name in initializer_names:
            continue
        elem_type = inp.type.tensor_type.elem_type if inp.type.HasField("tensor_type") else 0
        inputs.append({
            "name": inp.name,
            "shape": _extract_shape(inp.type),
            "data_type": _get_type_name(elem_type)
        })

    # Extract outputs
    outputs = []
    for out in graph.output:
        elem_type = out.type.tensor_type.elem_type if out.type.HasField("tensor_type") else 0
        outputs.append({
            "name": out.name,
            "shape": _extract_shape(out.type),
            "data_type": _get_type_name(elem_type)
        })

    # Extract initializers (weights / biases) & compute per-layer SHA-256
    layer_fingerprints = {}
    initializers = []
    for init in graph.initializer:
        dims = list(init.dims)
        # Raw bytes for cryptographic hashing
        if init.raw_data:
            raw_bytes = init.raw_data
        else:
            # Fallback using numpy helper if stored in typed fields
            arr = numpy_helper.to_array(init)
            raw_bytes = arr.tobytes()

        tensor_hash = hashlib.sha256(raw_bytes).hexdigest()
        layer_fingerprints[init.name] = tensor_hash

        initializers.append({
            "name": init.name,
            "shape": dims,
            "data_type": _get_type_name(init.data_type),
            "byte_size": len(raw_bytes),
            "sha256": tensor_hash
        })

    # Extract computational nodes & individual node fingerprints
    nodes = []
    for i, node in enumerate(graph.node):
        node_name = node.name or f"node_{i}_{node.op_type}"
        # Compute structural fingerprint of node (operator + inputs + outputs)
        node_sig = f"{node.op_type}:{','.join(node.input)}->{','.join(node.output)}".encode("utf-8")
        node_hash = hashlib.sha256(node_sig).hexdigest()

        nodes.append({
            "index": i,
            "name": node_name,
            "op_type": node.op_type,
            "inputs": list(node.input),
            "outputs": list(node.output),
            "structural_fingerprint": node_hash
        })

    return {
        "metadata": metadata,
        "graph_name": graph.name,
        "inputs": inputs,
        "outputs": outputs,
        "nodes": nodes,
        "initializers": initializers,
        "layer_fingerprints": layer_fingerprints,
        "total_nodes": len(nodes),
        "total_weight_layers": len(initializers)
    }


def fingerprint_onnx_layers(model_path: str) -> Dict[str, str]:
    """
    Returns a dictionary mapping layer/initializer names to their SHA-256 digests.
    Enables layer-by-layer substitution detection.
    """
    inspection = inspect_onnx_model(model_path)
    return inspection["layer_fingerprints"]


def verify_onnx_layers(
    current_model_path: str,
    baseline_fingerprints: Dict[str, str]
) -> Dict[str, Any]:
    """
    Verifies an ONNX model against a known-good baseline layer fingerprint set.
    Pinpoints substituted, fine-tuned, or missing layers.
    """
    current_fps = fingerprint_onnx_layers(current_model_path)
    intact = []
    tampered = []
    missing = []

    for layer_name, expected_hash in baseline_fingerprints.items():
        if layer_name not in current_fps:
            missing.append(layer_name)
            tampered.append({
                "layer": layer_name,
                "expected": expected_hash,
                "actual": None,
                "issue": "LAYER_MISSING"
            })
        elif current_fps[layer_name] != expected_hash:
            tampered.append({
                "layer": layer_name,
                "expected": expected_hash,
                "actual": current_fps[layer_name],
                "issue": "WEIGHT_HASH_MISMATCH"
            })
        else:
            intact.append(layer_name)

    # Check for unauthorized newly added layers
    unexpected = [name for name in current_fps if name not in baseline_fingerprints]
    for layer_name in unexpected:
        tampered.append({
            "layer": layer_name,
            "expected": None,
            "actual": current_fps[layer_name],
            "issue": "UNEXPECTED_LAYER_INJECTED"
        })

    is_clean = len(tampered) == 0
    return {
        "model_file": os.path.basename(current_model_path),
        "is_clean": is_clean,
        "total_layers": len(current_fps),
        "intact_layers": intact,
        "tampered_layers": tampered,
        "status": "PASS" if is_clean else "LAYER_SUBSTITUTION_DETECTED"
    }


def create_sample_onnx_model(
    output_path: str,
    tampered: bool = False,
    seed: int = 42
) -> str:
    """
    Synthesizes a valid, offline ONNX vision classification network (SimpleCNN)
    containing Conv2D, Relu, GlobalAveragePool, and Gemm (classifier head) layers.
    
    If tampered=True, modifies the classifier head weights to simulate a layer
    substitution or fine-tuned backdoor attack.
    """
    if not ONNX_AVAILABLE:
        raise RuntimeError("The 'onnx' Python package is required to create ONNX models.")

    rng = np.random.RandomState(seed)

    # 1. Inputs & Outputs
    # Input image: [1, 3, 32, 32] (Batch x Channels x Height x Width)
    input_tensor = helper.make_tensor_value_info("input_image", TensorProto.FLOAT, [1, 3, 32, 32])
    output_tensor = helper.make_tensor_value_info("logits", TensorProto.FLOAT, [1, 10])

    # 2. Layer 1: Conv2D (16 filters of size 3x3)
    conv_w_data = rng.normal(0, 0.05, size=(16, 3, 3, 3)).astype(np.float32)
    conv_b_data = np.zeros((16,), dtype=np.float32)
    conv_w = helper.make_tensor("backbone.conv1.weight", TensorProto.FLOAT, [16, 3, 3, 3], conv_w_data.tobytes(), raw=True)
    conv_b = helper.make_tensor("backbone.conv1.bias", TensorProto.FLOAT, [16], conv_b_data.tobytes(), raw=True)

    node_conv = helper.make_node(
        "Conv",
        inputs=["input_image", "backbone.conv1.weight", "backbone.conv1.bias"],
        outputs=["conv1_out"],
        kernel_shape=[3, 3],
        pads=[1, 1, 1, 1],
        name="conv1"
    )

    # 3. Layer 2: ReLU Activation
    node_relu = helper.make_node("Relu", inputs=["conv1_out"], outputs=["relu1_out"], name="relu1")

    # 4. Layer 3: Global Average Pooling (reduces 16 x 32 x 32 to 16 x 1 x 1)
    node_pool = helper.make_node("GlobalAveragePool", inputs=["relu1_out"], outputs=["pool_out"], name="pool1")

    # 5. Flatten to [1, 16]
    node_flatten = helper.make_node("Flatten", inputs=["pool_out"], outputs=["flat_out"], name="flatten1")

    # 6. Classifier Head (Gemm: 16 features -> 10 classes)
    if tampered:
        # Malicious substituted weights
        fc_w_data = np.full((10, 16), 0.777, dtype=np.float32)
        fc_b_data = np.full((10,), 0.01, dtype=np.float32)
    else:
        # Standard clean baseline weights
        fc_w_data = rng.normal(0, 0.1, size=(10, 16)).astype(np.float32)
        fc_b_data = np.zeros((10,), dtype=np.float32)

    fc_w = helper.make_tensor("head.classifier.weight", TensorProto.FLOAT, [10, 16], fc_w_data.tobytes(), raw=True)
    fc_b = helper.make_tensor("head.classifier.bias", TensorProto.FLOAT, [10], fc_b_data.tobytes(), raw=True)

    node_gemm = helper.make_node(
        "Gemm",
        inputs=["flat_out", "head.classifier.weight", "head.classifier.bias"],
        outputs=["logits"],
        transB=1,
        name="classifier_head"
    )

    # Construct Graph
    nodes = [node_conv, node_relu, node_pool, node_flatten, node_gemm]
    initializers = [conv_w, conv_b, fc_w, fc_b]

    graph = helper.make_graph(
        nodes=nodes,
        name="aegis_simple_vision_net",
        inputs=[input_tensor],
        outputs=[output_tensor],
        initializer=initializers
    )

    model = helper.make_model(
        graph,
        producer_name="AEGIS-CV Team GLITCH",
        producer_version="2.0",
        doc_string="AEGIS-CV Assurance Test Model (Challenge 22)"
    )

    onnx.checker.check_model(model)
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    onnx.save(model, output_path)

    return output_path


if __name__ == "__main__":
    import sys
    print("--- AEGIS-CV ONNX Inspector Self-Test ---")
    tmp_onnx = "test_model.onnx"
    create_sample_onnx_model(tmp_onnx, tampered=False)
    info = inspect_onnx_model(tmp_onnx)
    print(f"Model: {info['metadata']['model_file']}")
    print(f"Inputs: {info['inputs']}")
    print(f"Outputs: {info['outputs']}")
    print(f"Nodes: {info['total_nodes']}")
    print(f"Weight Layers: {info['total_weight_layers']}")
    for k, v in info["layer_fingerprints"].items():
        print(f"  {k}: {v[:16]}...")
    if os.path.exists(tmp_onnx):
        os.remove(tmp_onnx)
