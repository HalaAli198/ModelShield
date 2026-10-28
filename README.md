# ModelShield: Runtime Detection of Malicious ML Models

## Overview

ModelShield is the first runtime behavioral detection system for malicious machine learning models that attributes observed system-level behavior to specific model operations. It combines application-level instrumentation of ML framework APIs with eBPF-based syscall tracing, tracking model behavior across spawned threads and child processes to separate model-triggered activity from environment noise. Attributed syscall sequences are classified using 195 detection patterns mapped to MITRE ATT&CK techniques.

This repository contains the reference implementation, detection results, and evaluation materials for:

> ***I Don't Care How You Hide It, I Care What You Do: Runtime Detection of Malicious ML Models***<br>
> Hala Ali and Andrew Case

> [!NOTE]
> Accepted at IEEE ACSAC.

The paper reports 41 malicious models detected on Hugging Face during the evaluation window (March 25 – May 5, 2026). Scanning has continued since submission and has surfaced 105 additional malicious models through August 18, 2026. All 146 are documented in `Found_Malicious_Models_HF.xlsx`, and technical write-ups for the real-world malware samples are in `Security_Advisories(Real_Malware_Cases)/`.

---

## Key Features

- Runtime behavioral detection for malicious ML models.
- Dual-layer monitoring: application-level AOP instrumentation and kernel-level eBPF syscall tracing.
- Phase-aware syscall attribution (loading and inference).
- Cross-thread and cross-process correlation propagation.
- 195 detection patterns mapped to MITRE ATT&CK techniques.
- Offline LLM-assisted discovery of new attack patterns.
- Support for 17 ML frameworks and 36 serialization formats.

---

## Repository Structure

```
ModelShield/
├── Code/
│   ├── ModelShield_Core_Scripts/               # Core detection pipeline
│   │   ├── model_inspector.py                  # Model format detection, input synthesis, AOP instrumentation,
│   │   │                                       #   eBPF-monitored loading + execution, phase-separated trace emission
│   │   ├── ebpf_program.c                      # Kernel-side eBPF probe: tracepoint attachment, perf-buffer streaming
│   │   ├── syscall_category_mapper.py          # Raw syscall name → normalized semantic category + sub-operation
│   │   └── attack_behavior_classifier.py       # Ordered-subsequence pattern matching against AB1-AB8 taxonomy;
│   │                                           #   emits verdict JSON with matched patterns and MITRE ATT&CK mappings
│   ├── Platform_Scanning/                      # End-to-end scanning pipelines
│   │   ├── local_scan_quick_test.py            # Smoke test: 1 benign + 1 malicious model (~1 min)
│   │   ├── local_scan_41_malicious_models.py
│   │   ├── local_scan_gadget_substitution.py
│   │   ├── local_scan_pickle_paths.py
│   │   ├── local_scan_pickleball_benign.py
│   │   ├── local_scan_pickleball_malicious.py
│   │   ├── local_scan_tf_abuse_attacks.py
│   │   ├── Hugging_Face_scan.py                # Live HF scanning: discovers recent uploads
│   │   ├── Kaggle_scan.py                      # Live Kaggle scanning: discovers recent uploads
│   │   └── ModelScope_scan.py                  # Live ModelScope scanning: discovers recent uploads
│   │
│   └── Runtime_Environments/                   # Framework environment setup
│       ├── build_env_pool.sh                   # Builds all five Python 3.9 venvs
│       └── env_selector.py                     # Routes models to the correct environment
│
├── Test_Suites/
│   ├── 41_Malicious_Models/                    # 5 representative samples from the 41 detected models
│   ├── Pickle_Gadget_Substitution/             # All 15 gadget substitution variants
│   ├── Pickle_Paths/                           # All 10 loading-path obfuscation variants
│   └── TF_Abuse/                               # All 4 TF SavedModel attack variants
│
├── Quick_Test_Samples/                         # 1 benign + 1 malicious model for smoke testing
│
├── All_Results/
│   ├── Detection_Results_41_Malicious_Models/  # Traces and verdicts for the 41 malicious models
│   ├── Detection_Results_Pickle_Gadget_Substitution/  # Traces and verdicts for 15 gadget substitution variants
│   ├── Detection_Results_Pickle_Paths/         # Traces and verdicts for 10 loading-path obfuscation variants
│   ├── Detection_Results_TF_Abuse/             # Traces and verdicts for 4 TF SavedModel API abuse attacks
│   └── Detection_Results_PickleBall_Dataset/   # Traces and verdicts for the full PickleBall dataset
│
├── Found_Malicious_Models_HF.xlsx              # 41 paper-reported + 105 newly detected malicious models
├── Patterns_Taxonomy.xlsx                      # All 195 detection patterns across AB1-AB8
├── PickleBall_Malicious_TP_FN.xlsx             # 52 TP + 32 FN across the 84 malicious models
│
├── Security_Advisories(Real_Malware_Cases)/    # Technical write-ups for real-world malware samples
│   ├── reverse-shell-huggingface-lqc.md
│   ├── cgruzicka-test-lora-weights-advisory.md
│   ├── shell-execution-minilm-antarge.md
│   └── reverse-shell-llama-afdafdfsd.md
│
├── Claims/
│   ├── claim1_41_malicious_models/             # C1: 41 confirmed malicious HF models
│   ├── claim2_substitution_gadgets/            # C2: 15 pickle gadget substitution variants
│   ├── claim3_confusion_loading_paths/         # C3: 10 loading-path obfuscation variants
│   ├── claim4_TF_Abuse/                        # C4: 4 TensorFlow SavedModel attacks
│   ├── claim5_pickleball_benign/               # C5: 252 benign PickleBall models (0 FP)
│   └── claim6_pickleball_malicious/            # C6: 84 malicious PickleBall models
│
├── install.sh                                  # Full setup from scratch on Ubuntu 22.04 VM
├── run_quick_test.sh                           # Quick test on a fresh VM (downloads samples + runs)
├── cleanup.sh                                  # Removes all installed dependencies and environments
├── data_provenance.txt                         # Data collection methodology and sources
├── ethical_considerations.txt                  # Responsible disclosure and safety measures
└── LICENSE                                     # Apache 2.0
```

Each `Claims/` subfolder contains `claim.txt` (the claim and how to verify it), `run.sh` (the exact reproduction command), and `expected/expected.txt` (the expected result of that command).

---

## ModelShield's pipeline

### Core Detection (`Code/ModelShield_Core_Scripts/`)

1. `model_inspector.py`: detects the model format, infers input requirements, instruments framework APIs via AOP, attaches eBPF probes to kernel syscall tracepoints, and loads + executes the model. It emits phase-separated syscall traces (`loading_events.json` and `execution_events.json`) for each model file.

2. `ebpf_program.c`: Kernel-side eBPF probe program attached to syscall tracepoints. It captures compact syscall events, copies correlation context from BPF maps, and streams events to userspace through perf buffers.

3. `syscall_category_mapper.py`: maps raw syscall names to normalized categories and sub-operations consumed by the classifier.

4. `attack_behavior_classifier.py`: matches ordered syscall subsequences against the attack taxonomy (195 patterns across eight behavior classes, AB1–AB8, mapped to MITRE ATT&CK) and returns verdicts with matched patterns.

### Scanning Pipelines (`Code/Platform_Scanning/`)

| Script | Purpose |
|---|---|
| `local_scan_quick_test.py` | Smoke test: 1 benign + 1 malicious model  |
| `local_scan_41_malicious_models.py` | Reproduce detection of the 41 malicious models |
| `local_scan_gadget_substitution.py` | 15 pickle gadget substitution variants |
| `local_scan_pickle_paths.py` | 10 loading-path obfuscation variants |
| `local_scan_tf_abuse_attacks.py` | 4 TensorFlow SavedModel API abuse attacks |
| `local_scan_pickleball_benign.py` | 252 benign PickleBall models (false positive check) |
| `local_scan_pickleball_malicious.py` | 84 malicious PickleBall models |
| `Hugging_Face_scan.py` | Live Hugging Face scanning: discovers recent uploads|
| `Kaggle_scan.py` |  Live Kaggle scanning: discovers recent uploads |
| `ModelScope_scan.py` |  Live ModelScope scanning: discovers recent uploads | 


### Runtime Environments (`Code/Runtime_Environments/`)

ModelShield routes each model to the appropriate framework environment based on platform metadata, declared library name, and file-extension or magic-byte analysis. The environment chosen for each model is printed in the scan log (`Routed to env: ...`). Five Python 3.9 virtual environments are provided:

| Environment | Frameworks |
|---|---|
| `torch_current` | PyTorch 2.4.0, Transformers 4.44.0 |
| `torch_legacy` | PyTorch 1.13.1, Transformers 4.30.0 |
| `tf2` | TensorFlow 2.17.0, Keras 3.5.0 |
| `sklearn` | scikit-learn 1.5.1, XGBoost, LightGBM, CatBoost, PyPMML |
| `onnx` | ONNX Runtime 1.18.1, ONNX 1.16.2 |

> **Note:** Every environment includes a CPU-only build of PyTorch and safetensors because the inspector imports them unconditionally at startup for format detection and synthetic input construction, even when the model targets a different framework.

### Supported File Extensions

The pipeline recognizes 36 model formats: 34 by file extension and 2 by filename (`saved_model.pb` for TensorFlow SavedModel and `symbol.json` for MXNet).

`.pkl` `.pickle` `.joblib` `.bin` `.pt` `.pt2` `.pth` `.th` `.ckpt` `.safetensors` `.h5` `.keras` `.pb` `.tflite` `.onnx` `.msgpack` `.xgb` `.bst` `.ubj` `.lgb` `.txt` `.cbm` `.npy` `.npz` `.dill` `.mlmodel` `.mlpackage` `.params` `.pdmodel` `.pdiparams` `.pmml` `.engine` `.plan` `.trt`

Of these, the high-risk subset (formats that deserialize arbitrary Python objects on load) is: `.pkl` `.pickle` `.joblib` `.dill` `.bin` `.pt` `.pth` `.th` `.ckpt` `.npy` `.npz`


---

## Hardware and Software Requirements

| | Specification |
|---|---|
| **OS** | Ubuntu 22.04 LTS |
| **Kernel** | 6.8.0 (minimum 5.15+, with BPF and perf event support) |
| **Privileges** | Root (sudo), or CAP_BPF + CAP_PERFMON; required for eBPF tracepoint attachment |
| **vCPUs** | 8 (minimum) |
| **RAM** | 32 GB (recommended; 16 GB minimum) |
| **Disk** | 100 GB (500 GB on the provided VM) |
| **GPU** | Not required; all environments use CPU-only builds |
| **Languages** | Python 3.9, C |
| **System deps** | BCC, linux-headers, build-essential, OpenJDK 11, xvfb |
| **Eval deps** | pydevd, Pillow, requests, mlflow, tkinter, cloudpickle, ipython |

---

## Getting Started

### Installation

`install.sh` performs the full setup from scratch on a clean Ubuntu 22.04 VM:

1. Installs Python 3.9, OpenJDK 11, eBPF tools (BCC), and system dependencies.
2. Clones this repository into your home directory.
3. Builds the five runtime environments and validates each one.
4. Installs extra packages needed by the evaluation models.
5. Installs the platform API clients (`huggingface_hub`, `modelscope`, `kaggle`)
   in their own environment.
6. Configures the inspector, classifier, and environment paths in every scan script.

The script downloads the code itself, so there is no need to clone first:

```bash
curl -fsSL https://raw.githubusercontent.com/HalaAli198/ModelShield/main/install.sh -o install.sh
chmod +x install.sh
sudo ./install.sh
```

> [!NOTE]
> Installation takes roughly 20–30 minutes depending on network speed and hardware.

### Quick Test

`run_quick_test.sh` runs ModelShield on one benign and one malicious model from `Quick_Test_Samples/`. It requires `install.sh` to have completed successfully.

```bash
chmod +x run_quick_test.sh
sudo ./run_quick_test.sh
```

The benign model should return `BENIGN` and the malicious model should return `MALICIOUS` with matched behavior classes and pattern IDs in the output.

### Cleanup

To remove all installed dependencies, environments, and cached data:

```bash
chmod +x cleanup.sh
sudo ./cleanup.sh
```

---

## Claims and Reproduction

### Claim 1: 41 Malicious Models on Hugging Face

`Test_Suites/41_Malicious_Models/` contains 5 representative repositories (10 model files) from the 41 confirmed malicious models. Each file is inspected and classified independently.

```bash
cd Claims/claim1_41_malicious_models
sudo ./run.sh
```

**Expected:** 10 files scanned, 10 MALICIOUS, 0 BENIGN, 0 errors (~5 minutes). Compare output against `expected/expected.txt`.

Pre-computed traces and verdicts for all 41 models are in `All_Results/Detection_Results_41_Malicious_Models/`.
> [!NOTE]
> **Clarification on archived results:** The results in `All_Results/Detection_Results_41_Malicious_Models/` cover 60 model files from 41 Hugging Face repositories. ModelShield evaluates each file individually, while the paper reports detection at the repository level; a repository is counted as detected if at least one of its files is classified `MALICIOUS`. The archived run classified 59 files as `MALICIOUS` and one as `BENIGN`, covering 40 of the 41 repositories.
>
> The `BENIGN` file is Model 17 (`17.hacnho_pickle-scanner-bypass-smtplib-smtp/exploit-smtplib-smtp.pkl`, archived under `FN/`). Its payload attempts an outbound SMTP connection on port 25, which was blocked in the execution environment. The connection never completed, no malicious behavior was observed, and the classifier returned `BENIGN`. In an environment that permits outbound port-25 traffic, ModelShield flags this model as `MALICIOUS` via `AB6-OUTBOUND`, which gives the 41/41 repository-level result reported in the paper. 

### Claim 2: 15 Pickle Gadget Substitution Variants

`Test_Suites/Pickle_Gadget_Substitution/` contains all 15 gadget substitution variants, each embedding a different callable from the Python standard library or ML dependencies.

```bash
cd Claims/claim2_substitution_gadgets
sudo ./run.sh
```

**Expected:** 15 files scanned, 15 MALICIOUS, 0 BENIGN, 0 errors (~5 minutes). Compare output against `expected/expected.txt`.

Pre-computed traces and verdicts are in `All_Results/Detection_Results_Pickle_Gadget_Substitution/`.

### Claim 3: 10 Loading-Path Obfuscation Variants

`Test_Suites/Pickle_Paths/` contains all 10 loading-path obfuscation variants covering Joblib raw pickle, five Joblib compression variants (gzip, bz2, xz, lzma, zlib), PyTorch ZIP and TAR containers, NumPy pickle-backed loading, and one EOP bypass.

```bash
cd Claims/claim3_confusion_loading_paths
sudo ./run.sh
```

**Expected:** 10 files scanned, 10 MALICIOUS, 0 BENIGN, 0 errors (~3 minutes). Compare output against `expected/expected.txt`.

Pre-computed traces and verdicts are in `All_Results/Detection_Results_Pickle_Paths/`.

### Claim 4: 4 TensorFlow SavedModel API Abuse Attacks

`Test_Suites/TF_Abuse/` contains all 4 TensorFlow SavedModel API abuse variants: IP exposure, code execution, shell access, and file leak. Two of the attacks (IP exposure and file leak) require listener servers to simulate the attacker's endpoint; `run.sh` starts and stops them automatically.

```bash
cd Claims/claim4_TF_Abuse
sudo ./run.sh
```

**Expected:** 4 files scanned, 4 MALICIOUS, 0 BENIGN, 0 errors (~1.5 minutes). Compare output against `expected/expected.txt`.

Pre-computed traces and verdicts are in `All_Results/Detection_Results_TF_Abuse/`.

### Claim 5: 252 Benign PickleBall Models

The PickleBall dataset (252 benign, 84 malicious models) is publicly available at [https://doi.org/10.5281/zenodo.16974644](https://doi.org/10.5281/zenodo.16974644). Download and extract the two subsets to `~/pickleball_dataset/benign/` and `~/pickleball_dataset/malicious/`. Each `run.sh` also accepts a directory as its first argument if you extracted elsewhere.

```bash
cd Claims/claim5_pickleball_benign
sudo ./run.sh
```

**Expected:** 252 files scanned, 0 MALICIOUS, 252 BENIGN, 0 errors (~119 minutes). Compare output against `expected/expected.txt`.

No benign model triggered a detection pattern, giving zero false positives across the full benign set.

### Claim 6: 84 Malicious PickleBall Models

Requires the PickleBall dataset (see Claim 5).

```bash
cd Claims/claim6_pickleball_malicious
sudo ./run.sh
```

**Expected:** 84 files scanned, 52 MALICIOUS, 32 BENIGN, 0 errors (~38 minutes). Compare output against `expected/expected.txt`.

ModelShield flagged 52 of the 84 malicious models. Of the remaining 32, 1 is a mislabeled benign sample in the dataset, and the other 31 either generate no syscalls at runtime (e.g., targeting Windows, importing modules not present in the execution environment) or produce harmless syscall patterns (e.g., payloads limited to printing to stdout or writing to non-sensitive paths).

`PickleBall_Malicious_TP_FN.xlsx` documents each of the 84 malicious files: for the 52 true positives it lists the malicious behavior, the detection pattern matched by ModelShield, and the mapped MITRE ATT&CK techniques; for the 32 false negatives it explains the reason.

Pre-computed traces and verdicts are in `All_Results/Detection_Results_PickleBall_Dataset/`.

---

## Output Structure

Each `run.sh` produces results in a dedicated directory under `~/`. For example, Claim 1 writes to `~/41_malicious_models_results/`.

| File / Directory | Contents |
|---|---|
| `summary.json` | Aggregate counts: total, benign, malicious, errors, file-type breakdown |
| `results.json` | Per-model result array (model ID, verdict, matched patterns, timings) |
| `model_list.json` | List of models discovered for scanning |
| `*_log.txt` | Full timestamped scan log |
| `verdict_results/` | Per-file verdict JSONs, organized into subdirectories by outcome |
| `TP/` | Archived traces for true positives (models correctly flagged as malicious) |
| `FN/` | Archived traces for false negatives (malicious models not flagged) |

Each archived trace folder contains:

- `loading_events.json` - syscall events captured during model loading
- `execution_events.json` - syscall events captured during model execution
- `verdict.json` - classifier output with verdict, matched behavior classes, and pattern IDs

---

## Live Platform Scanning (Optional)

The `Code/Platform_Scanning/` directory includes scanning pipelines for Hugging Face, Kaggle, and ModelScope that can scan recently uploaded models. These demonstrate ModelShield's end-to-end capability but are not part of the evaluation claims. Results depend on what is currently on the platform.

Each script requires a platform API token and root privileges. See the docstrings in each script for setup and usage instructions.

---

## Real-World Malware Found

`Security_Advisories(Real_Malware_Cases)/` contains technical write-ups for four malicious models found on Hugging Face during live scanning. Each advisory documents the payload, the disguise, the captured syscall trace, the commit history, the disclosure timeline, and recommended actions for anyone who loaded the model.

| Advisory | Repository | Found | Payload | Status |
|---|---|---|---|---|
| `reverse-shell-huggingface-lqc.md` | `LQCTestingSpace/lqc_model` | Mar 30, 2026 | Bash reverse shell to `18.138.220.214:11014` (AWS Singapore), delivered through PyTorch's legacy TAR loading path | Removed after disclosure to Hugging Face Security and AWS Trust & Safety |
| `cgruzicka-test-lora-weights-advisory.md` | `cgruzicka/test-lora-weights` | May 5, 2026 | Shell execution, host reconnaissance, `/etc/passwd` access, and HTTPS exfiltration to four IPv4/IPv6 endpoints | Flagged unsafe by Hugging Face; repository still accessible |
| `shell-execution-minilm-antarge.md` | `antarge/minilm-finetuned` | Jul 27, 2026 | Shell interpreters spawned via `pipe2` → `clone` → `dup2` → `execve` subprocess chains | Flagged unsafe by Hugging Face; repository still accessible |
| `reverse-shell-llama-afdafdfsd.md` | `afdafdfsd/aaaadsdf` | Aug 17, 2026 | `/root/.bash_history` harvesting, `/tmp` stager drop, host reconnaissance, then a reverse shell to `78.17.93.96:9000` | Access disabled by Hugging Face after disclosure |

The July and August findings come from the continued scanning described in the Overview, not from the paper's evaluation window.

---
## Deployment Considerations

In production, detection results should be forwarded off-host (e.g., to a remote syslog collector, a SIEM ingest endpoint, or a write-once object store) to prevent a compromised model from tampering with its own detection record.

---
## Responsible Use and Safety

This repository contains malicious model samples for research and evaluation purposes. These samples execute harmful payloads (shell commands, network connections, file access) when loaded or run.

- Always run experiments inside an isolated virtual machine with no sensitive data.
- Do not load test samples on production systems or shared infrastructure.
- Do not redistribute malicious samples outside of research contexts.
- All real-world malware findings were responsibly disclosed to the Hugging Face Security Team and AWS Trust & Safety prior to publication.
- The authors do not endorse misuse of these materials and are not responsible for damage resulting from unsafe or unauthorized use.
- If you discover malicious models using ModelShield, please report them to the respective platform's security team (e.g., security@huggingface.co for Hugging Face).
- Disclosure timelines and safety measures are documented in `ethical_considerations.txt`; dataset sources and collection methodology are in `data_provenance.txt`.

---

## License

Apache 2.0. See `LICENSE`.
