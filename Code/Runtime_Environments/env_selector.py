"""
env_selector.py:  select the runtime environment for a given model.
Given a model entry from the discovery pipeline, pick one of the five
pre-built venvs in the environment pool and return the path to its python3.9 interpreter.
The pipeline then spawns the model loader as a subprocess under that interpreter.
Selection considers three factors in priority order: hub metadata tags,
the explicit library_name field, and the model file extension.
"""
import os


# Root of the pre-built venv pool. Must match ENVS_ROOT in build_env_pool.sh.
ENVS_ROOT = os.environ.get('ENVS_ROOT', '/home/halaali_cs/modelshield/env_pool')

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


def select(model_entry):
    """
    Return (env_name, python_path) for this model.
    model_entry is the dict produced by pipeline._build_model_entry().
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

    # Factor 3: file extensions
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
