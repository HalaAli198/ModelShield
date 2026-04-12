
# Syscall Trace Analysis Prompt

Prompt for classifying HuggingFace models as benign, suspicious, or malicious based on Linux syscall traces captured during model loading and inference.

**Target model:** `claude-opus-4-6`
**Recommended temperature:** `0` (deterministic)
**Output format:** strict JSON

---

## Task

You are analyzing Linux syscall traces captured from HuggingFace models executed under an instrumentation harness. For each model, determine whether its behavior during loading and/or inference is consistent with a benign ML workload or indicates malicious activity.

## Input

Each model produces two JSON files sharing a prefix `NNNNN_UserName_ModelName_`:

- `..._loading_events.json` — syscalls during deserialization (loading weights from disk into memory)
- `..._execution_events.json` — syscalls captured during model inference (running a forward pass / prediction)

Files with the same prefix belong to the same model and must be analyzed jointly.

## Event schema

Each file is a JSON array of event objects. Each event has the following fields:

| Field | Description |
|---|---|
| `operation` | Linux syscall name (e.g., `openat`, `read`, `write`, `connect`, `socket`, `execve`, `fstat`, `ioctl`, `mmap`, `clone`, `sendto`, `recvfrom`, `getrandom`, `unlink`, `rename`, `chmod`, `chown`). |
| `filename` | File path, file descriptor, network target, or resource involved. |
| `extra_details` | Syscall-specific info: flags (`O_RDONLY`, `O_WRONLY`, `O_CREAT`, `O_TRUNC`), file descriptors, socket families (`AF_INET`, `AF_INET6`, `AF_UNIX`, `AF_NETLINK`), ports, addresses, protocol, sizes. |
| `pid` / `tid` | Process and thread IDs. |
| `timestamp` | Kernel monotonic timestamp (seconds). |
| `comm` | Process name (e.g., `python3.9`). A change in `comm` for events sharing the same `pid`/`tid` indicates `execve` replaced the process image. |
| `phase` | `LOADING` or `EXECUTION`. |
| `operation_chain` | ML framework call stack at syscall time (shows which ML operation triggered the syscall). An empty `operation_chain`, or a chain unrelated to model loading, around a syscall touching sensitive resources is a strong signal of injected behavior. |
| `suspicious_indicators` | Harness pre-flagged suspicious markers. |
| `attack_indicators` | Harness pre-flagged attack markers. |

## Benign baseline

During **LOADING**, legitimate ML models produce syscalls like:

- `openat` (read-only) on model weight files (`.bin`, `.pt`, `.safetensors`, `.h5`, `.onnx`, `.pkl`), `config.json`, tokenizer files, and vocabulary files
- `fstat`, `mmap`, `read`, `pread64`, `readv` on those same model files
- `openat` (read-only) on standard Python libraries and site-packages (importing dependencies)
- Reads from `/proc/cpuinfo`, `/sys/devices/system/cpu/` (CPU feature detection by NumPy, PyTorch, OpenMP)
- Reads from `/etc/nsswitch.conf`, `/etc/hosts`, `/etc/resolv.conf`, `/etc/host.conf`, `/etc/gai.conf` (glibc NSS name resolution — triggered by standard library imports, **NOT** by the model doing anything network-related)
- Reads from `/etc/passwd` and `/etc/group` (glibc `getpwuid`/`getgrgid` calls triggered by file operations — these are **NOT** credential access)
- `getrandom` (ASLR, library initialization, random seed)
- `futex` (thread synchronization)
- `mmap` / `mprotect` (memory allocation for model weights)
- `brk` (heap management)

During **EXECUTION**, legitimate ML models produce syscalls like:

- Memory operations (`mmap`, `brk`, `futex`)
- `write` / `writev` / `pwrite64` to stdout/stderr (printing predictions or progress)
- `getrandom` (random sampling, dropout)
- Reads from `/proc/self/maps`, `/proc/meminfo` (memory management)
- No file I/O to disk beyond stdout/stderr
- No network activity
- No process spawning

## Abnormal behavior

Do **NOT** limit yourself to the categories below. These are starting points. Use full reasoning to identify ANY behavior that seems wrong for an ML model, including novel patterns not enumerated here.

### Known suspicious categories

- Network connections during model loading (`socket`, `connect`, `sendto`, `recvfrom`) — especially to external IP addresses or non-standard ports
- Raw DNS traffic: `sendto` to UDP/TCP port 53 that is NOT preceded by a standard glibc `getaddrinfo` pattern (indicates resolver bypass)
- File writes outside the model's own directory during loading
- Executing shell commands or other programs (`execve` of `/bin/sh`, `/bin/bash`, `curl`, `wget`, `nc`, `ssh`, etc.)
- Accessing credential files (`/etc/shadow`, `~/.ssh/`, `~/.aws/`, `~/.config/gcloud/`, browser cookie databases, crypto wallets, auth tokens, keyrings)
- Accessing command history files (`~/.bash_history`, `~/.zsh_history`)
- Writing to system configuration files (`/etc/crontab`, `/etc/systemd/`, `/etc/init.d/`, `/etc/sudoers`, `/etc/passwd`, `/etc/ld.so.preload`)
- File permission changes (`chmod`, `chown`) on system files
- File deletion of system or log files
- Process privilege changes (`setuid`, `setgid`, `capset`)
- `dup2` redirecting stdin/stdout/stderr to a network socket (reverse shell signature)
- DNS/SSL configuration reads during model loading that are NOT caused by glibc NSS resolution
- Reading `/dev/input/` devices (keylogging)
- Kernel module loading (`init_module`, `finit_module`)
- Namespace manipulation (`unshare`, `setns`) outside of browser sandboxing
- `ptrace` operations on other processes
- `memfd_create` followed by `write` and `execve` (fileless execution)

### But also look for

- Unusual combinations of individually benign syscalls that together form a suspicious sequence
- Timing anomalies (long pauses between syscalls suggesting waiting for C2 responses)
- Low-and-slow data staging (small writes to unusual locations across many events)
- Obfuscated network activity — `AF_UNIX` sockets used for data movement rather than local IPC (flag unexpected `AF_UNIX` connections in a headless inference context), or `AF_NETLINK` used for reconnaissance followed by data transmission
- Any `operation_chain` entries showing `pickle.load`, `torch.load`, or `from_pretrained` triggering syscalls that have nothing to do with loading model weights
- Any syscall that simply doesn't make sense for an ML model to make during loading or inference, even if it's not in any known attack category
- Patterns where the model appears to be fingerprinting the environment (reading multiple system info files in sequence) even without immediate exfiltration — this could indicate a staged attack

Again: these are starting points, not an exhaustive taxonomy. Apply the same reasoning to any pattern that does not fit the benign baseline, whether or not it appears in this list.

## Confidence calibration

- **HIGH** — direct syscall-level evidence of a flagged behavior with a clear `operation_chain` tying it to model loading/inference (e.g., `pickle.load` → `connect` to an external IP).
- **MEDIUM** — strong inference from a sequence of syscalls that together constitute an attack pattern, but no single smoking-gun syscall.
- **LOW** — behavior is anomalous relative to the baseline but has a plausible benign explanation, or the trace is partial.

If evidence does not reach LOW, the verdict is `BENIGN`. Prefer false positives over false negatives — when uncertain, return `SUSPICIOUS` with `LOW` confidence and explain in `reasoning`.

If a trace appears truncated (abrupt end, missing `EXECUTION` phase, corrupted JSON, or missing fields), state this explicitly in `findings` and lower confidence by one band; do not guess at missing behavior.

## MITRE ATT&CK field

Use a valid Enterprise ATT&CK technique ID (e.g., `T1059.004`, `T1071.001`, `T1552.004`). If multiple apply, list up to three separated by commas. If none apply, use the literal string `N/A`. Do not invent IDs and do not include free-text technique names alongside the ID.

## Output

Return a JSON array, one object per model, in this exact schema. No prose outside the JSON.

​```json
[
  {
    "model": "00001_manja316_modelscan-bypass-ftplib",
    "verdict": "MALICIOUS",
    "confidence": "HIGH",
    "phase": "LOADING",
    "findings": [
      {
        "evidence": "openat(\"/home/user/.ssh/id_rsa\", O_RDONLY) at t=1.234, operation_chain=[_pickle.load, torch.load]",
        "why_abnormal": "Credential file access during pickle deserialization; no ML artifact justification."
      }
    ],
    "mitre": "T1552.004",
    "reasoning": "pickle.load triggers read of an SSH private key, which is outside any legitimate weight-loading path."
  },
  {
    "model": "00002_acme_sentiment-base",
    "verdict": "BENIGN"
  }
]
​```

For `BENIGN` verdicts, include only `model` and `verdict`. For `SUSPICIOUS` and `MALICIOUS` verdicts, include all fields.
