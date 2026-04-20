#!/bin/bash
# Build the five analysis environments.

set -e
# Override by exporting ENVS_ROOT before running. Must match env_selector.py.
ENVS_ROOT="${ENVS_ROOT:-/path/to/env_matrix}"
mkdir -p "$ENVS_ROOT"

make_venv() {
    local name=$1
    local env_path="$ENVS_ROOT/$name"
    if [ -d "$env_path" ] && [ -f "$env_path/.done" ]; then
        echo "[skip] $name already built"
        return 1
    fi
    echo "[build] $name"
    rm -rf "$env_path"
    python3.9 -m venv "$env_path"
    "$env_path/bin/pip" install --upgrade pip setuptools wheel
    return 0
}

# Env 1: Modern PyTorch + Transformers
if make_venv "torch_current"; then
    "$ENVS_ROOT/torch_current/bin/pip" install \
        torch==2.4.0+cpu --index-url https://download.pytorch.org/whl/cpu
    "$ENVS_ROOT/torch_current/bin/pip" install \
        transformers==4.44.0 tokenizers sentencepiece \
        huggingface_hub numpy safetensors
    touch "$ENVS_ROOT/torch_current/.done"
fi

# Env 2: Legacy PyTorch
if make_venv "torch_legacy"; then
    "$ENVS_ROOT/torch_legacy/bin/pip" install \
        torch==1.13.1+cpu --index-url https://download.pytorch.org/whl/cpu
    "$ENVS_ROOT/torch_legacy/bin/pip" install \
        transformers==4.30.0 huggingface_hub numpy safetensors
    touch "$ENVS_ROOT/torch_legacy/.done"
fi

# Env 3: TensorFlow 2 + Keras 3
if make_venv "tf2"; then
    "$ENVS_ROOT/tf2/bin/pip" install \
        tensorflow==2.17.0 keras==3.5.0 \
        huggingface_hub numpy safetensors
    touch "$ENVS_ROOT/tf2/.done"
fi

# Env 4: Classical ML
if make_venv "sklearn"; then
    "$ENVS_ROOT/sklearn/bin/pip" install \
        scikit-learn==1.5.1 joblib==1.4.2 \
        xgboost==2.1.1 lightgbm==4.5.0 catboost==1.2.7 \
        huggingface_hub numpy safetensors
    touch "$ENVS_ROOT/sklearn/.done"
fi

# Env 5: ONNX
if make_venv "onnx"; then
    "$ENVS_ROOT/onnx/bin/pip" install \
        onnxruntime==1.18.1 onnx==1.16.2 \
        huggingface_hub numpy safetensors
    touch "$ENVS_ROOT/onnx/.done"
fi

echo "All environments built at $ENVS_ROOT"
