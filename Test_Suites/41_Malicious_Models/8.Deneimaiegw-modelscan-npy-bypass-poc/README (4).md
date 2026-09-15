# ModelScan NumPy Scanner Bypass PoC

## WARNING
These files contain proof-of-concept pickle payloads. Do NOT load in production environments.

## Vulnerability
ModelScan's `scan_numpy` function (in `tools/picklescanner.py`) uses internal NumPy APIs (`_check_version`, `_read_array_header`) that were removed in NumPy >=2.3.5. The scanner crashes with `AttributeError` and reports "No issues found" while the malicious file remains fully executable.

## Files
- **malicious_model.npy** - Malicious .npy file with pickle RCE payload
- **create_malicious_npy.py** - Creates the malicious file
- **simple_poc.py** - Demonstrates the bypass

## Reproduction
```bash
pip install modelscan numpy>=2.3.5
python3 simple_poc.py
modelscan -p malicious_model.npy        # Reports "No issues found"
python3 -c "import numpy as np; np.load('malicious_model.npy', allow_pickle=True)"  # Executes payload
cat /tmp/numpy_bypass_pwned.txt         # Proof of execution
```

## Affected
- ModelScan 0.8.8 with NumPy >=2.3.5