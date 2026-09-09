"""
env_selector.py:  select the runtime environment for a given model.

Given a model entry from the discovery pipeline, pick one of the five
pre-built venvs in the environment pool and return the path to its
python3.9 interpreter.

The pipeline then spawns the model loader as a subprocess under that
interpreter.

Selection considers four factors in priority order: hub metadata tags,
the explicit library_name field, file magic bytes, and the model file
extension.
"""

import os
import struct

# Root of the pre-built venv pool. Must match ENVS_ROOT in build_env_pool.sh.
ENVS_ROOT = os.environ.get('ENVS_ROOT', '/path/to/env_pool')

# Map env name -> absolute path to its python3.9 interpreter.
POOL = {
    'torch_current': os.path.join(ENVS_ROOT, 'torch_current', 'bin', 'python3.9'),
    'torch_legacy':  os.path.join(ENVS_ROOT, 'torch_legacy',  'bin', 'python3.9'),
    'tf2':           os.path.join(ENVS_ROOT, 'tf2',           'bin', 'python3.9'),
    'sklearn':       os.path.join(ENVS_ROOT, 'sklearn',       'bin', 'python3.9'),
    'onnx':          os.path.join(ENVS_ROOT, 'onnx',          'bin', 'python3.9'),
}

# Extension -> env name
EXT_TO_ENV = {
    '.pt': 'torch_current', '.pth': 'torch_current',
    '.bin': 'torch_current', '.th': 'torch_current',
    '.safetensors': 'torch_current',
    '.h5': 'tf2', '.keras': 'tf2', '.pb': 'tf2', '.tflite': 'tf2',
    '.onnx': 'onnx', '.npy': 'sklearn', '.npz': 'sklearn',
    '.joblib': 'sklearn', '.pkl': 'sklearn', '.pickle': 'sklearn',
    '.dill': 'sklearn', '.pmml': 'sklearn',
    '.xgb': 'sklearn', '.bst': 'sklearn', '.ubj': 'sklearn',
    '.lgb': 'sklearn', '.cbm': 'sklearn',
}

# Tag -> env name (for HF hub metadata)
TAG_TO_ENV = {
    'pytorch': 'torch_current',
    'transformers': 'torch_current',
    'tensorflow': 'tf2',
    'keras': 'tf2',
    'tf-keras': 'tf2',
    'onnx': 'onnx',
    'sklearn': 'sklearn',
    'scikit-learn': 'sklearn',
    'joblib': 'sklearn',
    'xgboost': 'sklearn',
    'lightgbm': 'sklearn',
    'pmml': 'sklearn',
    'pypmml': 'sklearn',
}

# ── Magic-byte signatures ─────────────────────────────────────────────────
#
# Files can have misleading extensions (e.g. a torch ZIP archive saved as
# .pkl). Checking the first few bytes catches these before the extension
# fallback sends them to the wrong env.
#
#   PK\x03\x04           →  ZIP archive (torch >=1.6 save format)
#   \x89HDF\r\n\x1a\n    →  HDF5 (Keras / TF SavedModel weights)
#   \x7fELF               →  should not happen, skip
#   ONNX proto            →  starts with 0x08 (protobuf varint), unreliable
#                            alone, so we only use it when ext is .onnx
#
# For raw pickle (\x80\x02 … \x80\x05), the extension-based routing is
# usually correct, but a pickle that internally imports torch (e.g. a
# legacy torch save) should go to torch_current. We peek at the first
# few KB and check for torch-specific GLOBAL opcodes.

_TORCH_ZIP_MAGIC = b"PK\x03\x04"
_HDF5_MAGIC      = b"\x89HDF\r\n\x1a\n"
_PICKLE_PROTO    = b"\x80"

# Torch-specific strings that appear as GLOBAL arguments in a raw pickle
# produced by torch.save().  If any of these appear in the first 64 KB,
# the file needs torch to load.
_TORCH_PICKLE_MARKERS = (
    b"torch.",
    b"torch_utils",
    b"_rebuild_tensor",
    b"torch.serialization",
)


def _detect_format(filepath):
    """
    Read the first bytes of a file and return an env name override,
    or None if magic bytes are inconclusive.

    This catches the case where a .pkl file is actually a torch ZIP
    archive — routing it to sklearn would mean pickle.load() sees ZIP
    headers, never reaches the inner data.pkl, and the payload is
    never deserialized.
    """
    try:
        with open(filepath, "rb") as f:
            head = f.read(8)
            if not head:
                return None

            # ── ZIP archive → torch_current ────────────────────────
            # torch >=1.6 saves as a ZIP with archive/data.pkl inside.
            # This is the fix for rager_legacy (.pkl that is really a
            # torch ZIP) and similar misrouted files.
            if head[:4] == _TORCH_ZIP_MAGIC:
                return 'torch_current'

            # ── HDF5 → tf2 ────────────────────────────────────────
            if head[:8] == _HDF5_MAGIC:
                return 'tf2'

            # ── Raw pickle that needs torch ────────────────────────
            # A .pkl/.pickle file might be a legacy torch save (raw
            # pickle containing torch._utils._rebuild_tensor_v2 etc).
            # Peek at the first 64 KB for torch-specific markers.
            if head[:1] == _PICKLE_PROTO:
                f.seek(0)
                sample = f.read(65536)
                for marker in _TORCH_PICKLE_MARKERS:
                    if marker in sample:
                        return 'torch_current'

    except (OSError, IOError):
        # Can't read the file — fall through to extension-based routing.
        pass

    return None


def select(model_entry):
    """
    Return (env_name, python_path) for this model.

    model_entry is the dict produced by pipeline._build_model_entry().

    Priority order:
      1. Hub metadata tags
      2. library_name field
      3. File magic bytes   ← NEW: catches extension/format mismatches
      4. File extension
      5. Default (torch_current)
    """
    # Factor 1: hub metadata tags
    tags = [t.lower() for t in model_entry.get('tags', [])]
    for tag in tags:
        if tag in TAG_TO_ENV:
            env_name = TAG_TO_ENV[tag]
            return env_name, POOL[env_name]

    # Factor 2: library_name (HF exposes this explicitly)
    lib = (model_entry.get('library_name') or '').lower()
    if lib in TAG_TO_ENV:
        return TAG_TO_ENV[lib], POOL[TAG_TO_ENV[lib]]

    # Factor 3: file magic bytes
    # Overrides the extension when the actual file format disagrees.
    for mf in model_entry.get('model_files', []):
        path = mf.get('path') or mf.get('local_path', '')
        if path and os.path.isfile(path):
            magic_env = _detect_format(path)
            if magic_env:
                return magic_env, POOL[magic_env]

    # Factor 4: file extensions (original fallback)
    for mf in model_entry.get('model_files', []):
        ext = mf.get('extension', '').lower()
        if ext in EXT_TO_ENV:
            env_name = EXT_TO_ENV[ext]
            return env_name, POOL[env_name]

    # Default: torch_current (covers the majority of HF)
    return 'torch_current', POOL['torch_current']


def validate_pool():
    """Check that all env pythons exist. Call at pipeline startup."""
    missing = [name for name, path in POOL.items() if not os.path.exists(path)]
    if missing:
        raise RuntimeError(
            f"Environment pool incomplete. Missing: {missing}. "
            f"Run build_env_pool.sh first."
        )
