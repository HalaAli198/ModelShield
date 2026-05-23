#!/usr/bin/env python3
"""
ModelShield LLM-Assisted Pattern Discovery

Submits syscall traces from models classified as benign by ModelShield's
pattern matcher to an LLM for discovery of novel attack behaviors not
covered by the existing AB1-AB8 taxonomy.
"""

import json
import os
import sys
import time
from pathlib import Path
from collections import defaultdict

# ─────────────────────────────────────────────────
# Configuration — edit these
# ─────────────────────────────────────────────────
OPENAI_API_KEY = "YOUR_API_KEY_HERE"

LLM_MODEL = "gpt-5.5"

TRACES_DIR = r"E:\ML_Project_2026\expirements\hf_evalautions_all\hf_evaluation5_5000\benign"

OUTPUT_FILE = r"E:\ML_Project_2026\expirements\hf_evalautions_all\hf_evaluation5_5000\llm_discovery_results.json"

BATCH_SIZE = 2          # models per LLM call (2 = one loading + one execution per model, sent together)
MAX_MODELS = 5000
MAX_EVENTS_PER_PHASE = 2000

# ─────────────────────────────────────────────────
# Prompt
# ─────────────────────────────────────────────────

SYSTEM_PROMPT = """You are analyzing Linux syscall traces captured during ML model loading and inference. Your task is to identify syscall behavior that is inconsistent with a benign ML workload. Focus on discovering behaviors that fall OUTSIDE the known attack categories listed below — the pattern-based classifier has already checked for those.

BENIGN BASELINE
===============
During LOADING, benign ML models produce:
- Read-only opens on model files (.bin, .pt, .safetensors, .h5, .onnx, .pkl), configs, and tokenizer files
- Read-only opens on Python libraries and site-packages (dependency imports)
- Directory enumeration (getdents64) of workspace directories and site-packages during from_pretrained — Transformers searches for cached model files and resolves package paths
- Reads from /proc/cpuinfo, /sys/devices/system/cpu/ (CPU feature detection)
- Reads from /etc/nsswitch.conf, /etc/hosts, /etc/resolv.conf, /etc/host.conf, /etc/gai.conf (glibc NSS — NOT model-initiated network activity)
- Reads from /etc/passwd and /etc/group (glibc getpwuid/getgrgid — NOT credential access)
- getrandom, futex, mmap, mprotect, brk (standard runtime operations)

During EXECUTION, benign ML models produce:
- Memory operations (mmap, brk, futex, getrandom)
- Writes to stdout/stderr only (for predictions/progress)
- Read-only access to tokenizer files (tokenizer_config, tokenizer.json, vocab.txt, special_tokens_map) — frameworks commonly perform lazy tokenizer loading during the first inference call
- Read-only access to framework package directories (site-packages/torch/, site-packages/transformers/) — TorchDynamo and other backends lazily import modules during first forward pass
- Reads from /proc/self/cgroup, /sys/fs/cgroup/cpu/ — PyTorch and OpenMP read CPU quota to size thread pools
- mprotect with PROT_READ|PROT_WRITE|PROT_EXEC — PyTorch JIT and TorchInductor generate native code at runtime
- clone with CLONE_THREAD flags — framework thread pool initialization (OpenMP, ONNX Runtime, PyTorch)
- sched_getaffinity — CPU affinity detection for thread pool sizing
- Reads from profiler modules (cProfile, pstats, _lsprof) — framework instrumentation
- Temporary directory creation/removal under /tmp during torch.load — PyTorch legacy tar-based deserialization
- No network activity, no writes to system paths, no execve of external programs

KNOWN ATTACK CATEGORIES (already covered by the pattern classifier)
===================================================================
AB1: Sensitive information theft — reading credentials/keys/tokens then exfiltrating over network
AB2: Backdoor/persistence — writing to cron, systemd, authorized_keys, shell profiles, ld.so.preload
AB3: System manipulation — deleting/modifying system files, logs, permissions, firewall rules
AB4: Malicious code execution — execve of shells/interpreters, script staging, fileless execution, ptrace injection
AB5: Cryptojacking — miner execution/deployment with pool communication
AB6: Remote control — reverse shells, bind shells, remote command execution, C2 connections
AB7: Ransomware — file encryption cycles, key exfiltration, ransom notes
AB8: Privilege escalation — setuid/setgid elevation, kernel module loading, namespace escape

The pattern classifier has already checked for these. Your role is to find behaviors that do NOT match any of these categories but are still inconsistent with a benign ML workload.

EVENT SCHEMA
============
Each event has:
- operation: Linux syscall name
- filename: file path, descriptor, or network target
- extra_details: flags, socket families, ports, addresses, sizes
- pid/tid: process and thread IDs
- timestamp: kernel monotonic time (seconds)
- comm: process name (change indicates execve)
- phase: LOADING or EXECUTION
- operation_chain: ML framework call stack at syscall time (empty chain around sensitive resource access is a strong signal of injected behavior)

ANALYSIS INSTRUCTIONS
=====================
1. Compare each model's trace against the benign baseline above.
2. Identify any syscall or syscall sequence that does not fit the benign baseline AND is not already covered by AB1-AB8.
3. For flagged models, report the specific syscall evidence and explain why it is inconsistent with a benign ML workload.
4. Do NOT flag behavior that matches the benign baseline (e.g., glibc NSS reads, /proc/cpuinfo reads, Python import chains).
5. Do NOT re-flag behavior already covered by AB1-AB8 categories unless it represents a novel variant.

CONFIDENCE LEVELS
=================
HIGH: Direct syscall evidence with operation_chain tying it to model loading/inference
MEDIUM: Suspicious sequence without a single definitive syscall
LOW: Anomalous but plausible benign explanation exists

If evidence does not reach LOW, verdict is BENIGN.

OUTPUT FORMAT
=============
Return a JSON array, one object per model. No prose outside the JSON.

[
  {
    "model": "<model_folder_name>",
    "verdict": "MALICIOUS|SUSPICIOUS|BENIGN",
    "confidence": "HIGH|MEDIUM|LOW",
    "phase": "LOADING|EXECUTION",
    "findings": [
      {
        "evidence": "<specific syscall(s) with timestamps and arguments>",
        "why_abnormal": "<why this does not fit a benign ML workload and is not covered by AB1-AB8>"
      }
    ],
    "mitre": "<ATT&CK technique ID(s) or N/A>",
    "reasoning": "<brief explanation of the novel behavior>"
  },
  {
    "model": "<benign_model_folder_name>",
    "verdict": "BENIGN"
  }
]

For BENIGN verdicts, include only model and verdict."""


# ─────────────────────────────────────────────────
# Trace Loading
# ─────────────────────────────────────────────────

def discover_models(traces_dir: str) -> list:
    """
    Scan traces_dir for model subfolders. Each subfolder contains
    *_loading_events.json and *_execution_events.json.

    Returns list of dicts:
        [{"model_id": "00001_User_Model",
          "loading_files": [path, ...],
          "execution_files": [path, ...]}, ...]
    """
    traces_path = Path(traces_dir)
    models = []

    for subfolder in sorted(traces_path.iterdir()):
        if not subfolder.is_dir():
            continue

        loading_files = sorted(subfolder.glob("*_loading_events.json"))
        execution_files = sorted(subfolder.glob("*_execution_events.json"))

        if not loading_files and not execution_files:
            continue

        models.append({
            "model_id": subfolder.name,
            "loading_files": [str(f) for f in loading_files],
            "execution_files": [str(f) for f in execution_files],
        })

    return models


def load_events(file_paths: list, max_events: int = 2000) -> list:
    """Load and merge event JSON files, truncating to max_events."""
    events = []
    for fpath in file_paths:
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    events.extend(data)
                elif isinstance(data, dict):
                    events.append(data)
        except (json.JSONDecodeError, IOError) as e:
            print(f"  Warning: Could not read {fpath}: {e}", file=sys.stderr)

    events.sort(key=lambda e: e.get("timestamp", 0))

    if len(events) > max_events:
        print(f"  Truncating {len(events)} -> {max_events} events",
              file=sys.stderr)
        events = events[:max_events]

    return events


# ─────────────────────────────────────────────────
# LLM Interaction
# ─────────────────────────────────────────────────

def call_llm(batch: list) -> list:
    """
    Submit a batch of models to the LLM.

    batch: list of {"model_id", "loading_events", "execution_events"}
    Returns: list of verdict dicts
    """
    import requests

    user_content = "Analyze the following model traces:\n\n"

    for item in batch:
        user_content += f"=== Model: {item['model_id']} ===\n"

        if item["loading_events"]:
            user_content += (
                f"LOADING PHASE ({len(item['loading_events'])} events):\n"
            )
            user_content += json.dumps(item["loading_events"]) + "\n\n"
        else:
            user_content += "LOADING PHASE: No events captured.\n\n"

        if item["execution_events"]:
            user_content += (
                f"EXECUTION PHASE ({len(item['execution_events'])} events):\n"
            )
            user_content += json.dumps(item["execution_events"]) + "\n\n"
        else:
            user_content += "EXECUTION PHASE: No events captured.\n\n"

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {OPENAI_API_KEY}",
    }

    payload = {
        "model": LLM_MODEL,
        "temperature": 0.1,
        "max_tokens": 4096,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_content},
        ],
    }

    try:
        resp = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers=headers,
            json=payload,
            timeout=180,
        )
        resp.raise_for_status()

        content = resp.json()["choices"][0]["message"]["content"].strip()

        # Strip markdown fences
        if content.startswith("```json"):
            content = content[7:]
        if content.startswith("```"):
            content = content[3:]
        if content.endswith("```"):
            content = content[:-3]
        content = content.strip()

        verdicts = json.loads(content)
        if not isinstance(verdicts, list):
            verdicts = [verdicts]
        return verdicts

    except Exception as e:
        print(f"  API error: {e}", file=sys.stderr)
        return []


# ─────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────

def main():
    global OPENAI_API_KEY
    if OPENAI_API_KEY == "YOUR_API_KEY_HERE":
        OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
    if not OPENAI_API_KEY:
        print("ERROR: Set OPENAI_API_KEY in the script or as env var",
              file=sys.stderr)
        sys.exit(1)

    print(f"Scanning: {TRACES_DIR}")
    models = discover_models(TRACES_DIR)
    print(f"Found {len(models)} model folders")

    models = models[:MAX_MODELS]
    print(f"Analyzing {len(models)} models, batch size {BATCH_SIZE}\n")

    all_results = []
    batch = []
    total_batches = (len(models) + BATCH_SIZE - 1) // BATCH_SIZE

    for i, m in enumerate(models):
        loading_events = load_events(m["loading_files"], MAX_EVENTS_PER_PHASE)
        execution_events = load_events(m["execution_files"], MAX_EVENTS_PER_PHASE)

        batch.append({
            "model_id": m["model_id"],
            "loading_events": loading_events,
            "execution_events": execution_events,
        })

        if len(batch) >= BATCH_SIZE or i == len(models) - 1:
            batch_num = (i // BATCH_SIZE) + 1
            print(f"Batch {batch_num}/{total_batches} "
                  f"({len(batch)} models)...")

            verdicts = call_llm(batch)

            for v in verdicts:
                all_results.append(v)
                verdict_str = v.get("verdict", "UNKNOWN")
                if verdict_str != "BENIGN":
                    print(f"  >> {v.get('model', '?')}: {verdict_str} "
                          f"({v.get('confidence', '?')})")

            batch = []
            time.sleep(1)  # rate limit

    # Write results
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(all_results, f, indent=2)

    # Summary
    summary = defaultdict(int)
    for r in all_results:
        summary[r.get("verdict", "UNKNOWN")] += 1

    print(f"\n{'='*50}")
    print(f"Results: {OUTPUT_FILE}")
    print(f"Total: {len(all_results)}")
    for v, c in sorted(summary.items()):
        print(f"  {v}: {c}")

    non_benign = [r for r in all_results if r.get("verdict") != "BENIGN"]
    if non_benign:
        print(f"\nFlagged for manual review ({len(non_benign)}):")
        for r in non_benign:
            print(f"  - {r.get('model')}: {r.get('verdict')} "
                  f"({r.get('confidence')})")
            if "reasoning" in r:
                print(f"    {r['reasoning'][:150]}")


if __name__ == "__main__":
    main()
