
# Platform Scanning

This directory contains the end-to-end scanning pipelines that run ModelShield against the three public model platforms:

| Script                      | Platform         |
|-----------------------------|------------------|
| `hf_scan.py`          | Hugging Face     |
| `modelscope_scan.py`  | ModelScope       |
| `kaggle_scan.py`      | Kaggle           |

All three share the same pipeline and the same output layout. They differ only in the client library used to talk to each platform's API.

## Pipeline

For every discovered model, each script runs the same five stages:

1. **Discovery.** Query the platform's listing API for recently uploaded models, filter by age (10 days), extract the set of model files per repository, and record metadata observations (bare pickle, missing README, typosquat name, etc.). Discovery is resumable - progress is persisted to `discovery_progress.json` every 200 checks and on rate-limit pauses.

2. **Download.** Pull the model files and auxiliary config/tokenizer files into a per-run temp directory.

3. **Environment selection.** Assign the model to one of the sandbox environments in the pool. See [`../Sandbox_Design/`](../Sandbox_Design/) for how the selection works and the set of supported frameworks.

4. **Inspection.** Call ModelShield's inspector inside the selected environment. The inspector runs the model under ModelShield's dual-layer monitoring (application-level AOP interception of framework loading and inference APIs, plus kernel-level eBPF syscall tracing) and captures the attributed syscall stream across the loading and execution phases.

5. **Classification.** Invoke ModelShield's attack-behavior classifier on the captured event stream. It returns a verdict (`BENIGN`, `MALICIOUS`, `TIMEOUT`, or `ERROR`), the matched behavior IDs, and the matched pattern IDs.

The scan phase is resumable independently of discovery: passing `--resume` picks up from the last completed model using the results file below.

## Output layout

Two output roots are written per run.

### `WORK_DIR` — per-run state and evidence

```text
WORK_DIR/
├── model_list.json               discovered models (input to the scan phase)
├── discovery_progress.json       resumable discovery state
├── results.json                  one record per scanned model
├── summary.json                  verdict counts and timing
├── scan_log.txt                  human-readable run log
├── temp_model/                   per-model scratch (wiped between models)
└── hf_results/                   (or ms_results / kaggle_results)
    ├── {model_id}_verdict.json   raw classifier output per model
    └── malicious/                extra copy of evidence for malicious verdicts
        ├── {model_id}_verdict.json
        └── {model_id}_events/
            ├── loading_events.json
            └── execution_events.json
```

`results.json` contains one record per model with the fields the scan produced: identifiers, downloads, file types, routing decision, verdict, matched behaviors and patterns, per-stage timing, and metadata reasons.

`summary.json` is a small aggregate: totals by verdict, start/end timestamps, completion count.

The `malicious/` subdirectory is a duplicate of the trace data for malicious models, kept under `WORK_DIR` so reports don't depend on `TRACES_DIR` being mounted.

### `TRACES_DIR`: full corpus for offline analysis

Every scanned model, benign or malicious, has its events archived here:

```text
TRACES_DIR/
├── benign/
│   └── 00001_{model_id}/
│       ├── 00001_{model_id}_loading_events.json
│       ├── 00001_{model_id}_execution_events.json
│       └── 00001_{model_id}_verdict.json
└── malicious/
    └── 00042_{model_id}/
        ├── 00042_{model_id}_loading_events.json
        ├── 00042_{model_id}_execution_events.json
        └── 00042_{model_id}_verdict.json
```

Folders are prefixed with a zero-padded monotonic counter so the corpus retains scan order. The same schema is used by all three scripts, which means traces from different platforms can be pooled into a single dataset for the LLM-based pattern discovery stage (see `../LLM-based_Attack_Detection/`).

## Configuration

Each script has an inline configuration block near the top:

```python
HF_TOKEN        = "hf_your_token_here"      # or equivalent platform token
WORK_DIR        = '/path/to/work_dir'
INSPECTOR_PATH  = '/path/to/model_inspector_runner.py'
CLASSIFIER_PATH = '/path/to/attack_behavior_classifier.py'
TRACES_DIR      = '/path/to/captured_events'
```

Replace the placeholders before running. Each script expects its own platform credential:

- Hugging Face: personal access token from <https://huggingface.co/settings/tokens>
- ModelScope: SDK token from <https://modelscope.cn/my/myaccesstoken>
- Kaggle: `~/.kaggle/kaggle.json` created via account settings on <https://www.kaggle.com/>

## Scanner Environment

The scan scripts need a separate venv with the platform API clients.

Create the venv and install the platform clients:

```bash
export SCANNER_ENV=$HOME/modelshield/scanner_env
python3.9 -m venv "$SCANNER_ENV"
"$SCANNER_ENV/bin/pip" install huggingface_hub modelscope kaggle requests
```

## Running

The sandbox pool must be built first (`../Sandbox_Design/build_env_pool.sh`) or `validate_pool()` will abort the run.

```bash
# Hugging Face
sudo bash -c "ulimit -u unlimited && ulimit -l unlimited && \
\"$SCANNER_ENV/bin/python3.9\" hf_scan.py --num-models 30000"

# ModelScope
sudo bash -c "ulimit -u unlimited && ulimit -l unlimited && \
\"$SCANNER_ENV/bin/python3.9\" modelscope_scan.py --num-models 30000"

# Kaggle
sudo bash -c "ulimit -u unlimited && ulimit -l unlimited && \
\"$SCANNER_ENV/bin/python3.9\" kaggle_scan.py --num-models 10000"
```

`ulimit -u` lets the inspector spawn framework worker threads; `ulimit -l` lets eBPF lock its maps into memory. Without both raised, the inspector fails.

### CLI flags

| Flag                  | Effect                                                           |
|-----------------------|------------------------------------------------------------------|
| `--num-models N`      | Discovery target for this run.                                   |
| `--resume`            | Resume the scan phase, skipping models already in `results.json`.|
| `--reset-discovery`   | Delete `discovery_progress.json` and restart discovery.          |
| `--skip-discovery`    | Reuse `model_list.json`, skip the discovery phase entirely.      |

## Isolation

The scripts run the model loader as a subprocess under the routed sandbox interpreter, but the sandbox is a *reproducibility* layer, not a security boundary.  Payloads have full user-level access to the host. Run on a disposable VM with no credentials, SSH keys, or cloud tokens on disk.
