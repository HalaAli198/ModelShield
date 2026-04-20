
# Sandbox Design

This directory contains the sandbox configuration used by **ModelShield**  to load and execute each scanned model.
The pool contains **5 Python 3.9 virtual environments**, each pinned to a `(framework, major-version)` combination that dominates current uploads. 

## Environments and Supported Formats

| Environment         | Packages                                                                                                        | Target Formats                                          |
|---------------------|-----------------------------------------------------------------------------------------------------------------|---------------------------------------------------------|
| PyTorch (current)   | `torch` 2.4.0, `transformers` 4.44.0, `tokenizers`, `sentencepiece`, `dill`, `cloudpickle`, `safetensors`       | `.pt`, `.pth`, `.bin`, `.th`, `.safetensors`            |
| PyTorch (legacy)    | `torch` 1.13.1, `transformers` 4.30.0, `dill`, `cloudpickle`, `safetensors`                                     | `.pt`, `.bin` (pre-2.0)                                 |
| TensorFlow / Keras  | `tensorflow` 2.17.0, `keras` 3.5.0, `safetensors`                                                               | `.h5`, `.keras`, `.pb`, `.tflite`                       |
| Classical ML        | `scikit-learn` 1.5.1, `joblib` 1.4.2, `xgboost` 2.1.1, `lightgbm` 4.5.0, `catboost` 1.2.7, `pandas`, `sympy`    | `.joblib`, `.pkl`, `.xgb`, `.bst`, `.lgb`, `.cbm`       |
| ONNX Runtime        | `onnxruntime` 1.18.1, `onnx` 1.16.2, `safetensors`                                                              | `.onnx`                                                 |

## Files

| File                    | Purpose                                                  |
|-------------------------|----------------------------------------------------------|
| `build_env_pool.sh`     | Builds the five virtual environments.                    |
| `env_selector.py`       | Selects an environment for each model from its metadata. |


The `ENVS_ROOT` variable at the top of both files specifies the directory in which the pool is created. Either edit its default in both files, or export it in the shell before running the builder:

```bash
export ENVS_ROOT=$HOME/modelshield/env_pool
./build_env_pool.sh
```

## Environment Selection

`env_selector.select(model_entry)` returns `(env_name, python_path)` considering three factors, in priority order:

1. Platform metadata tags (e.g. `pytorch`, `keras`, `onnx`, `sklearn`).
2. The `library_name` field in the platform metadata.
3. Model file extensions. Ambiguous extensions such as `.bin` are resolved by magic-byte inspection.

If none of the factors resolves to a specific environment, PyTorch (current) is used as the default.

`env_selector.validate_matrix()` verifies that the Python interpreter exists for every environment in the pool and is called  once before processing any models.
