# Malicious ML Model Report: `cgruzicka/test-lora-weights`

**Date reported:** May 5, 2026  
**Reported by:** Hala Ali  
**Platform:** Hugging Face  
**Model:** [`cgruzicka/test-lora-weights`](https://huggingface.co/cgruzicka/test-lora-weights)  
**Status at time of report:** Flagged as unsafe but still publicly accessible  

## Summary

During automated scanning of recently uploaded Hugging Face models, I identified a model repository that appeared to contain malicious pickle payloads with active outbound network behavior.

The repository, `cgruzicka/test-lora-weights`, included files named `lora_weights.bin` and `pytorch_lora_weights.bin`. In controlled analysis, deserializing these files with `torch.load()` triggered shell execution, host reconnaissance, sensitive file access, environment variable collection, and outbound HTTPS connections to external infrastructure.

Although the repository name suggested a test or proof-of-concept model, the observed runtime behavior was consistent with malicious activity.

## Affected Artifacts

The following files were observed to contain embedded pickle payloads:

- `lora_weights.bin`
- `pytorch_lora_weights.bin`

## Observed Runtime Behavior

During the model loading phase, the payload triggered the following behaviors:

- Shell execution during deserialization
- Host reconnaissance commands, including:
  - `id`
  - `whoami`
  - `hostname`
  - `cat /proc/version`
- Environment variable collection
- Access to system files, including:
  - `/etc/passwd`
  - `/proc/version`
- Outbound HTTPS connections to external infrastructure on port `443`

## Observed External Endpoints

The following external endpoints were observed during controlled analysis:

```text
178.63.67.153:443
178.63.67.106:443
[2a01:4f8:121:114d::2]:443
[2a01:4f8:121:11a5::2]:443
```

The repeated outbound connections across multiple IPv4 and IPv6 addresses suggest possible failover or exfiltration infrastructure.

## Security Impact

The observed behavior indicates that loading the model could execute attacker-controlled code in the user's environment. Potential impact includes:

- Execution of shell commands
- Host and user reconnaissance
- Collection of environment variables
- Access to sensitive local files
- Outbound communication with external infrastructure
- Possible data exfiltration

Because the behavior is triggered during deserialization, users may be exposed simply by loading the model artifact with unsafe loading mechanisms.

## Detection Context

The activity was observed during controlled runtime analysis of the model loading phase. The behavior was identified through runtime monitoring rather than static metadata alone, highlighting the risk of relying exclusively on static scanners for malicious ML model detection.

## Responsible Disclosure

I reported this finding to the Hugging Face Security Team on May 5, 2026, recommending repository removal and review of the associated account for related uploads.

I also offered to provide full syscall-level event traces, behavioral verdicts, and supporting logs to assist the investigation.

## Recommended User Action

Users who downloaded or loaded this model should:

1. Avoid loading the affected artifacts.
2. Inspect the host for suspicious outbound connections to the listed endpoints.
3. Review shell history, process execution logs, and environment exposure.
4. Rotate any secrets that may have been present in environment variables.
5. Remove the model artifacts from local systems.

## Indicators of Compromise

### Model Repository

```text
https://huggingface.co/cgruzicka/test-lora-weights
```

### Files

```text
lora_weights.bin
pytorch_lora_weights.bin
```

### Network Endpoints

```text
178.63.67.153:443
178.63.67.106:443
[2a01:4f8:121:114d::2]:443
[2a01:4f8:121:11a5::2]:443
```

### Commands Observed

```text
id
whoami
hostname
cat /proc/version
```

### Files Accessed

```text
/etc/passwd
/proc/version
```
