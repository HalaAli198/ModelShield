# Malicious Model Disguised as Fine-Tuned MiniLM on Hugging Face

**Date:** July 27, 2026
**Classification:** MALICIOUS(Shell Execution via Pipe-Based Subprocess Chains)
**Status:** Active, flagged as unsafe by Hugging Face but still publicly accessible

---

## Summary

On July 27, 2026, [ModelShield](https://github.com/HalaAli198/ModelShield) identified a malicious model in the Hugging Face repository `antarge/minilm-finetuned`, disguised as a fine-tuned MiniLM sentence embedding model. The repository used the name of the widely adopted MiniLM model family and included supporting files (`config.json`, `README.md`, `example.py`) to appear legitimate.

Both model files, `model.pt` and `pytorch_model.bin`, contained pickle payloads that spawn shell interpreters via pipe-based subprocess chains during deserialization. The model was detected approximately one hour after it was uploaded to the platform.

The repository accumulated 26 downloads before Hugging Face flagged both files as unsafe, and had reached 30 downloads by the time of writing this report.

---

## Indicators of Compromise

| Indicator | Value |
|---|---|
| Model URL | `https://huggingface.co/antarge/minilm-finetuned` |
| Malicious files | `model.pt`, `pytorch_model.bin` |
| File format | PyTorch checkpoint (pickle payload) |
| Uploader | antarge |
| Downloads | 30 (at time of writing) |
| Upload date | July 27, 2026 |
| Detection date | July 27, 2026 (~1 hour after upload) |
| Shells spawned | `/usr/bin/sh`, `/usr/bin/bash` |

---

## The Payload

During deserialization, both model files execute the following syscall chain:

| Syscall | Target | Details |
|---|---|---|
| `pipe2()` | create_pipe | Pipe created with `O_CLOEXEC` |
| `clone()` | flags=0x1200011 | Child process forked (`CLONE_SYSVSEM\|CLONE_CHILD_CLEARTID`) |
| `execve()` | `/usr/bin/sh` | Shell interpreter spawned |
| `clone()` | flags=0x1200011 | Second child process forked |
| `dup2()` | dup_4->1 | Stdout redirected to pipe |
| `dup2()` | dup_3->0 | Stdin redirected from pipe |
| `execve()` | `/usr/bin/bash` | Interactive bash shell spawned |

The pipe-fork-redirect-exec pattern is characteristic of programmatic subprocess spawning rather than simple `os.system()` calls, indicating a more sophisticated payload. Extensive data output to stdout (~8 KB per write, dozens of writes) was also observed, suggesting data collection or enumeration output.

---

## The Disguise

Unlike most malicious models found on Hugging Face, which are explicitly named as proof-of-concept or bypass demonstrations, this repository was carefully constructed to appear as a legitimate fine-tuned model:

| File | Purpose |
|---|---|
| `config.json` | Model configuration to enable loading via `transformers` |
| `README.md` | Model card describing the model |
| `example.py` | Usage example script |
| `pytorch_model.bin` | **Malicious**: pickle payload with shell execution |
| `model.pt` | **Malicious**: pickle payload with shell execution |

The use of the MiniLM name, a widely recognized model family for sentence embeddings, adds credibility and makes the repository more likely to attract downloads from users seeking a fine-tuned embedding model.

---

## Commit History

The repository contained 6 commits from a single author, all dated July 27, 2026:

| # | Date / Time (UTC) | Message |
|---|---|---|
| 1 | Jul 27, 03:23:37 | initial commit |
| 2 | Jul 27, 03:23:41 | Upload pytorch_model.bin with huggingface_hub |
| 3 | Jul 27, 03:23:44 | Upload model.pt with huggingface_hub |
| 4 | Jul 27, 03:23:45 | Upload config.json with huggingface_hub |
| 5 | Jul 27, 03:23:46 | Upload README.md with huggingface_hub |
| 6 | Jul 27, 03:23:47 | Upload example.py with huggingface_hub |

All commits occurred within a 10-second window, indicating automated upload via the `huggingface_hub` library.

---

## Attack Scenario

```
Step 1: Attacker creates antarge account on Hugging Face
        Uploads model.pt and pytorch_model.bin containing pickle payloads
        Includes config.json, README.md, and example.py for legitimacy

Step 2: Repository uses the MiniLM name and appears as a fine-tuned model
        Model is loadable via standard transformers workflows

Step 3: Victim loads the model:
        >>> from transformers import AutoModel
        >>> model = AutoModel.from_pretrained("antarge/minilm-finetuned")

Step 4: torch.load() deserializes the pickle payload

Step 5: Payload spawns /usr/bin/sh and /usr/bin/bash via pipe+fork+redirect

Step 6: Attacker gains shell execution with victim's privileges
```

---

## Disclosure  Timeline

| Date | Event |
|---|---|
| July 27, 2026, 03:23 UTC | Model uploaded to Hugging Face |
| July 27, 2026, 04:34 UTC | ModelShield detects model as malicious (~1 hour after upload) |

The detection was fully automated. No prior reports or platform flags existed for this model at the time of detection.

---

## Key Takeaways

- **Disguised malicious models are harder to catch.** This model used a well-known model family name, included a model card and example code, and carried two malicious files. It looked like a real model.
- **Downloads accumulate quickly.** The repository reached 26 downloads before Hugging Face flagged it, demonstrating that even brief exposure on the platform can lead to real-world impact.
- **Sophisticated payloads go beyond os.system().** The pipe-based subprocess chain used here is harder to detect through static analysis than a simple `os.system()` call.
- **Runtime detection caught it in one hour.** ModelShield's automated scanning flagged this model approximately one hour after upload, before any manual report was filed.

---

## Recommended Actions

If you downloaded and loaded `antarge/minilm-finetuned`:

1. Treat the system as potentially compromised. The payload spawns interactive shell processes with your user privileges.
2. Inspect the host for suspicious shell processes or unexpected subprocess activity.
3. Review shell history and process execution logs for unauthorized commands.
4. Rotate any secrets or credentials that may have been accessible to the loading process.
5. Remove the model artifacts from local systems.

---

## About

This analysis was conducted as part of research on runtime behavioral detection of malicious ML models. The detection was made using [ModelShield](https://github.com/HalaAli198/ModelShield), a runtime behavioral detection system that monitors system-call activity during model loading and inference.

**Author:** Hala Ali
