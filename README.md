# ModelShield

ModelShield is a runtime behavioral detection system for malicious machine learning models. Instead of relying only on static inspection of serialized model contents, it analyzes what a model does during loading and inference. ModelShield combines application-level interception of framework loading and inference APIs with kernel-level eBPF syscall tracing, then classifies the attributed syscall stream into attack behaviors such as command execution, credential access, exfiltration, persistence, reverse shells, and system manipulation.

This repository contains the reference implementation, supporting artifacts, and evaluation materials for the ModelShield paper, *I Don’t Care How You Hide It, I Care What You Do: Behavioral Detection of Malicious ML Models*.

## Key Features

- Runtime behavioral detection for malicious ML models
- Dual-layer monitoring:
  - application-level AOP interception of model loading and inference APIs
  - kernel-level eBPF syscall tracing
- Phase-aware attribution of syscalls to **LOADING** and **EXECUTION**
- Cross-thread and cross-process correlation
- Pattern-based attack classification over attributed syscall streams
- Offline LLM-assisted discovery of additional candidate attack patterns
- Large-scale scanning support for Hugging Face, ModelScope, and Kaggle
- Evaluation results for MalHug comparison, TensorFlow API abuse, pickle loading-path evasion, and pickle gadget-substitution attacks

## Repository Layout

```text
ModelShield/
├── LLM-based_Attack_Detection/
├── ModelShield Core Scripts/
│   ├── attack_behavior_classifier.py
│   ├── ebpf_program.c
│   ├── model_inspector.py
│   └── syscall_category_mapper.py
├── Platform Scanning/
│   ├── hf_scan.py
│   ├── modelscope_scan.py
│   └── kaggle_scan.py
├── Results_Comparision_MalHug_Dataset/
├── Results_Detection_Pickle_Gadget_Substitution/
├── Results_Detection_Pickle_Paths/
├── Results_Detection_TF_Abuse/
├── Sandbox_Design/
│   ├── build_env_pool.sh
│   └── env_selector.py
├── all_attacks_patterns.xlsx
├── detected_malicious_models.xlsx
├── LICENSE
└── README.md
```

### Directory Summary

| Path | Description |
|---|---|
| `ModelShield Core Scripts/` | Core runtime analysis pipeline: model inspection, eBPF syscall capture, semantic syscall decoding, and attack behavior classification. |
| `Platform Scanning/` | End-to-end scanning pipelines for Hugging Face, ModelScope, and Kaggle. These scripts automate discovery, download, environment selection, inspection, classification, and trace archiving. |
| `Sandbox_Design/` | Sandbox setup used to load and execute models across supported frameworks and formats. Includes the environment builder and environment-selection logic. |
| `LLM-based_Attack_Detection/` | Offline prompt and workflow used to analyze captured syscall traces and propose candidate attack patterns beyond the initial predefined taxonomy. |
| `Results_Comparision_MalHug_Dataset/` | Detection results for malicious models from the MalHug dataset. |
| `Results_Detection_Pickle_Gadget_Substitution/` | Detection results for pickle gadget-substitution attacks. |
| `Results_Detection_Pickle_Paths/` | Detection results for loading-path and container-based pickle evasion techniques. |
| `Results_Detection_TF_Abuse/` | Detection results for TensorFlow API abuse attacks. |
| `all_attacks_patterns.xlsx` | Full attack behavior taxonomy and pattern definitions used by the classifier. |
| `detected_malicious_models.xlsx` | Summary of malicious models detected during scanning the Hugging Face platform. |

---
## Core Pipeline

ModelShield’s runtime workflow consists of four main stages:

1. **Inspection**  
   `model_inspector.py` detects model format, infers input requirements, runs the model under AOP + eBPF monitoring, and emits phase-separated syscall traces:
   - `*_loading_events.json`
   - `*_execution_events.json`

2. **Semantic Decoding**  
   `syscall_category_mapper.py` maps raw syscall names to normalized categories and sub-operations used by the classifier.

3. **Behavior Classification**  
   `attack_behavior_classifier.py` matches ordered syscall subsequences against the attack taxonomy and returns verdicts and matched patterns.

4. **Offline LLM-Assisted Pattern Discovery**  
   Captured traces can be further analyzed with the prompt in `LLM-based_Attack_Detection/prompt.md` to capture new candidate malicious behaviors for manual review.

## Main Components

### `model_inspector.py`
The main execution component of ModelShield. It:
- identifies model format
- prepares synthetic inputs
- instruments framework APIs
- loads and executes models under monitoring
- captures attributed syscall streams across loading and execution phases
- emits JSON events for downstream classification

### `ebpf_program.c`
Kernel-side eBPF probe program attached to syscall tracepoints. It captures compact syscall events, copies correlation context from BPF maps, maintains fd-to-path mappings, and streams events to userspace through perf buffers.

### `syscall_category_mapper.py`
Semantic decoding stage that normalizes raw syscall names into analysis-friendly categories and sub-operations for classification.

### `attack_behavior_classifier.py`
Pattern-based classifier that analyzes the attributed syscall stream and labels malicious behavior classes such as credential access, code execution, reverse shells, persistence, and system manipulation.

## Supported Platforms

The scanning pipeline currently supports:

- **Hugging Face**
- **ModelScope**
- **Kaggle**

## Supported Execution Environments

The sandbox pool currently includes five Python 3.9 virtual environments targeting the framework/version combinations that dominate recent public uploads:

- PyTorch (current)
- PyTorch (legacy)
- TensorFlow / Keras
- Classical ML
- ONNX Runtime

Environment routing is based on platform metadata, declared library name, and file-extension or magic-byte analysis.

## Usage

ModelShield supports two main workflows:

1. **Single-model inspection** using the core scripts
2. **Large-scale platform scanning** using the platform scanners

### A. Build the sandbox environment pool

The scanning and inspection workflows depend on a pool of prebuilt Python environments for supported frameworks and formats.

```bash
cd Sandbox_Design
export ENVS_ROOT=$HOME/modelshield/env_pool
chmod +x build_env_pool.sh
./build_env_pool.sh
```

### B. Create the scanner environment

The platform scanners require a separate Python environment with the platform API clients installed.

```bash
export SCANNER_ENV=$HOME/modelshield/scanner_env
python3.9 -m venv "$SCANNER_ENV"
"$SCANNER_ENV/bin/pip" install huggingface_hub modelscope kaggle requests
```

### C. Configure platform scanning

Before running the scanners, update the inline configuration block in each script with your platform token and local paths, including:

- `WORK_DIR`
- `INSPECTOR_PATH`
- `CLASSIFIER_PATH`
- `TRACES_DIR`

### D. Run large-scale platform scanning

#### Hugging Face

```bash
sudo bash -c "ulimit -u unlimited && ulimit -l unlimited && $SCANNER_ENV/bin/python3.9 hf_scan.py --num-models 30000"
```

#### ModelScope

```bash
sudo bash -c "ulimit -u unlimited && ulimit -l unlimited && $SCANNER_ENV/bin/python3.9 modelscope_scan.py --num-models 30000"
```

#### Kaggle

```bash
sudo bash -c "ulimit -u unlimited && ulimit -l unlimited && $SCANNER_ENV/bin/python3.9 kaggle_scan.py --num-models 10000"
```

### E. Run single-model inspection

You can also run the inspector directly on a local model directory:

```bash
cd "ModelShield Core Scripts"
sudo python model_inspector.py <single_model_dir>
```

or

```bash
sudo python model_inspector.py <batch_models_dir>
```

This produces phase-separated syscall traces, which can then be passed to:

```bash
python attack_behavior_classifier.py <events_dir>
```
**Note:** `model_inspector.py` is the inspection engine. For platform-scale scanning, the scan scripts select the appropriate framework environment from `Sandbox_Design/` via `env_selector.py` and invoke the inspector under that interpreter. For standalone single-model analysis, run the inspector in an environment that has the dependencies required for the target model format, or use the corresponding sandbox environment directly.

### Output

Large-scale scans write:

- per-run state and summaries under `WORK_DIR`
- archived traces under `TRACES_DIR`
- evidence for malicious models under `malicious/`

For full configuration details, output layout, and scanner flags, see `Platform Scanning/README.md` and `Sandbox_Design/README.md`.

## Evaluation Results

This repository includes evaluation results for:

- **MalHug** comparison
- **TensorFlow API abuse**
- **Pickle loading-path evasion**
- **Pickle gadget-substitution**

It also includes:
- the full attack pattern spreadsheet
- the table of detected malicious models observed during platform scanning

## Research Basis

This repository contains the  implementation and supporting artifacts for the following paper:

**Hala Ali and Andrew Case**  
*I Don’t Care How You Hide It, I Care What You Do: Behavioral Detection of Malicious ML Models.*



## License

This repository is released under the AGPL-3.0 license.
