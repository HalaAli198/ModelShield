# Reverse Shell with Credential Harvesting Disguised as Llama Model on Hugging Face

**Date:** August 17, 2026
**Classification:** MALICIOUS (Reverse Shell + Credential Theft)
**Status:** Reported to Hugging Face Security. Model access disabled by Hugging Face.

---

## Summary

On August 17, 2026, [ModelShield](https://github.com/HalaAli198/ModelShield), identified a malicious model in the Hugging Face repository `afdafdfsd/aaaadsdf`, disguised as a Llama language model. The repository contained no real model weights, only a 10.2 KB pickle payload (`model.pt`) that executes a multi-stage attack during deserialization: it harvests the user's bash command history from `/root/.bash_history`, performs host reconnaissance via the `id` command, and opens a reverse shell to an attacker-controlled endpoint at `78.17.93.96:9000`.

The model had been on the platform for approximately three hours at the time of discovery. The repository contained 4 commits from a single contributor, and the most recent commit was titled "Delete evil-repo," confirming the author's awareness of the payload's nature. All malicious activity fires during the model loading phase, before any inference call is made.

We reported the model to Hugging Face Security.

---

## Indicators of Compromise

| Indicator | Value |
|---|---|
| Model URL | `https://huggingface.co/afdafdfsd/aaaadsdf` |
| Malicious file | `model.pt` |
| File size | 10,240 bytes (10.2 KB) |
| File format | Pickle payload via PyTorch serialization |
| C2 IP | `78.17.93.96` |
| C2 port | `9000/tcp` |
| Uploader | afdafdfsd |
| Claimed architecture | Llama (tag: `llama`) |
| config.json size | 228 bytes |
| Upload date | August 17, 2026 |
| Reported | August 17, 2026 |

---

## The Payload

Unlike the single-command reverse shells commonly seen in malicious Hugging Face models, this payload chains three distinct attack phases during pickle deserialization.

### Phase 1: Credential Harvesting

The payload opens and reads `/root/.bash_history` in read-only mode (`O_RDONLY`), extracting 35 bytes of command history. Bash history files frequently contain credentials, API keys, database connection strings, and internal hostnames leaked through prior shell commands. This gives the attacker immediate context about the victim's environment before the reverse shell even connects.

### Phase 2: Host Reconnaissance and Staging

The payload performs four code execution sub-behaviors, chained together to prepare the host:

- Drops a temporary file at `/tmp/379uefk5` (`O_RDWR|O_CREAT|O_EXCL`, mode `0o600`, 4 bytes written),  likely a command stager
- Spawns `/usr/bin/sh` and `/usr/bin/bash` via `execve` across multiple threads
- Uses the `pipe2` → `clone` → `dup2` → `execve` pattern to fork a child process with redirected file descriptors
- Executes `/usr/bin/id` to determine the current user, group, and privilege level

### Phase 3: Reverse Shell

This is the primary payload. The attack constructs a textbook Unix reverse shell:

1. Opens a socket (`AF_UNIX`/`SOCK_STREAM`)
2. Connects outbound to `78.17.93.96:9000` (`AF_INET`)
3. Redirects stdin (`dup2 fd3→0`), stdout (`dup2 fd3→1`), and stderr (`dup2 fd3→2`) to the network socket
4. Executes `/usr/bin/bash`, giving the attacker a fully interactive shell session

If the C2 server at `78.17.93.96` is listening on port 9000, the attacker gains an interactive bash session running with the victim's user privileges. Combined with the bash history exfiltration in Phase 1, the attacker arrives with harvested credentials and host context already in hand.

---

## The Disguise

The repository included the Hugging Face tag "llama" and a `config.json` of only 228 bytes. A legitimate Llama model with even a minimal configuration would require hundreds of megabytes to gigabytes of weights. The actual malicious file was **10.2 KB**, roughly **5 to 6 orders of magnitude** smaller than any real model matching the claimed architecture. The `config.json` exists solely to make the model appear loadable via `transformers.AutoModel.from_pretrained()`. The 12 KB total repository size is the most immediate red flag.

### Key Observations

- The file is named `model.pt` (PyTorch format), not `pytorch_model.bin` or `model.safetensors`
- At 10.2 KB, the file cannot contain any real tensor data, it is pure payload
- The exclusive-create flags (`O_EXCL`) on the temp file drop suggest deliberate anti-detection: the file is created fresh, avoiding overwrites that might trip file integrity monitors
- The `dup2` fd redirection pattern (`fd3→0`, `fd3→1`, `fd3→2`) is the canonical reverse shell signature in Unix malware

---

## Commit History

The repository contained 4 commits from a single author (afdafdfsd), all dated August 17, 2026:

| # | Message | Details |
|---|---|---|
| 1 | initial commit | `.gitattributes` (1.52 KB) |
| 2 | Upload 2 files | `config.json` (228 B) + `model.pt` (10.2 KB) |
| 3 | Delete evil-repo | `e9ed55f`, VERIFIED |
| 4 | — | Possible additional cleanup commit |

The commit titled "Delete evil-repo" (hash `e9ed55f`, verified signature) confirms the uploader's awareness that the repository contained a malicious payload. Despite this commit message, the malicious files (`model.pt` and `config.json`) remained in the repository at the time of discovery.

---

## Attack Scenario

```
Step 1: Attacker creates the afdafdfsd account on Hugging Face
        Uploads model.pt containing multi-stage pickle payload
        Includes minimal config.json claiming Llama architecture

Step 2: config.json and the "llama" tag make the repository appear legitimate
        Model loads via transformers without errors

Step 3: Victim loads the model:
        >>> from transformers import AutoModel
        >>> model = AutoModel.from_pretrained("afdafdfsd/aaaadsdf")

Step 4: torch.load() deserializes the pickle → triggers the embedded __reduce__ payload

Step 5: Payload reads /root/.bash_history (credential harvesting)
        Runs /usr/bin/id (reconnaissance)
        Drops a stager script to /tmp

Step 6: TCP connection opens to 78.17.93.96:9000
        File descriptors 0, 1, and 2 are redirected to the socket via dup2

Step 7: /usr/bin/bash is executed
        Attacker receives a fully interactive reverse shell
        with the victim's privileges and the exfiltrated command history
```

---

## Disclosure Timeline

| Date | Event |
|---|---|
| August 17, 2026 | Model uploaded to Hugging Face |
| August 17, 2026 (~3 hours later) | Discovered and reported to Hugging Face Security |
| August 19, 2026 (~2 days after upload) | Hugging Face flagged model.pt as unsafe |
| Post-report | Model access disabled by Hugging Face ("This content infringes our Content Policy") |

---

## Key Takeaways

- **Multi-stage payloads are escalating.** This model chained credential harvesting, host reconnaissance, and a reverse shell into a single deserialization event.
- **Bash history is a high-value target.** Exfiltrating command history before the reverse shell connects gives the attacker credentials and context on arrival.
- **Runtime detection outpaced static scanners.** ModelShield detected the model approximately three hours after upload. Hugging Face flagged the file as unsafe two days later and subsequently disabled access only after our report.
- **Commit messages can be evidence.** The "Delete evil-repo" commit confirms the uploader's awareness of the payload's nature.

---

## Recommended Actions

If you downloaded and loaded `afdafdfsd/aaaadsdf` before its removal:

- **Treat the system as compromised.** The reverse shell grants full interactive access with your user privileges.
- **Check for active connections** to `78.17.93.96` on port `9000`.
- **Review `/root/.bash_history`**: the attacker may have exfiltrated credentials or hostnames from it.
- **Review process history** for unexpected `bash` processes spawned by Python, and check `/tmp` for the stager file (`379uefk5`).
- **Rotate credentials** accessible from the affected machine.
- **Block the C2 IP** at your network egress.

---


## About

This analysis was conducted as part of research on runtime behavioral detection of malicious ML models. The detection was made using [ModelShield](https://github.com/HalaAli198/ModelShield), a runtime behavioral detection system that monitors system-call activity during model loading and inference.

**Author:** Hala Ali
