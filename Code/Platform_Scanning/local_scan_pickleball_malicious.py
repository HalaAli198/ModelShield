"""
local_scan_pickleball_malicious.py

Scans the PickleBall malicious model dataset from a local directory.
Each model file is traced via eBPF during loading and execution,
then classified against 195 behavioral patterns (AB1-AB8).

All models in this dataset are malicious. Verdicts of MALICIOUS are
true positives (TP); verdicts of BENIGN are false negatives (FN).

Usage (run from the repository root):
    cd ~/ModelShield
    export ENVS_ROOT=~/ms_envs/env_pool
    SCANNER_ENV=~/ms_envs/scanner_env

    sudo bash -c "export ENVS_ROOT=$ENVS_ROOT && \
        ulimit -u unlimited && ulimit -l unlimited && \
        xvfb-run $SCANNER_ENV/bin/python3.9 \
        Code/Platform_Scanning/local_scan_pickleball_malicious.py \
        --local-dir <path-to-downloaded-malicious-pickleball>"

    # Resume after interruption:
    sudo bash -c "export ENVS_ROOT=$ENVS_ROOT && \
        ulimit -u unlimited && ulimit -l unlimited && \
        xvfb-run $SCANNER_ENV/bin/python3.9 \
        Code/Platform_Scanning/local_scan_pickleball_malicious.py \
        --local-dir <path-to-downloaded-malicious-pickleball> --resume"

Results are saved under ~/malicious_pickleball/ in the home
directory of the user who invoked sudo.
"""

import os
import sys
import json
import time
import shutil
import argparse
import subprocess
import re

from datetime import datetime

_HOME = os.path.expanduser("~" + os.environ.get("SUDO_USER", ""))

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(_SCRIPT_DIR)

sys.path.insert(0, os.path.join(_REPO_ROOT, 'Runtime_Environments'))
from env_selector import select, validate_pool, POOL

# =============================================================================
# Configuration
# =============================================================================
SCAN_DIR = os.path.join(_HOME, 'malicious_pickleball')
RESULTS_DIR = os.path.join(SCAN_DIR, 'malicious_pickleball_results')
LOG_FILE = os.path.join(SCAN_DIR, 'malicious_pickleball_log.txt')
MODEL_TEMP_DIR = os.path.join(SCAN_DIR, 'temp_model')

INSPECTOR_PATH = os.path.join(_REPO_ROOT, 'ModelShield_Core_Scripts', 'model_inspector.py')
CLASSIFIER_PATH = os.path.join(_REPO_ROOT, 'ModelShield_Core_Scripts', 'attack_behavior_classifier.py')
TRACES_DIR = os.path.join(_HOME, 'malicious_pickleball')

# File extensions the pipeline inspects.
MODEL_EXTENSIONS = [
    '.pkl', '.pickle', '.joblib',
    '.bin', '.pt', '.pt2', '.pth', '.th', '.ckpt',
    '.safetensors',
    '.h5', '.keras', '.pb', '.tflite',
    '.onnx',
    '.msgpack',
    '.xgb', '.bst', '.ubj', '.lgb', '.txt', '.cbm',
    '.npy', '.npz', '.dill',
    '.mlmodel', '.mlpackage',
    '.params',
    '.pdmodel', '.pdiparams', '.pmml',
    '.engine', '.plan', '.trt',
]

# Extensions that deserialize arbitrary Python objects on load.
HIGH_RISK_EXTENSIONS = ['.pkl', '.pickle', '.joblib', '.dill', '.bin', '.pt', '.pth',
                        '.th', '.ckpt', '.npy', '.npz']

# Per-file size limits.
MAX_MODEL_SIZE = 3 * 1024 * 1024 * 1024
MIN_MODEL_SIZE = 100

# Subprocess timeouts, in seconds.
INSPECTOR_TIMEOUT = 300
CLASSIFIER_TIMEOUT = 300

# Monotonic counter used to prefix archived trace folders.
_trace_counter = 0

def _make_safe_name(model_id):
    parts = model_id.split('/')
    if len(parts) >= 3:
        owner = parts[0]
        repo = parts[1]
        rest = '_'.join(parts[2:])            
        rest = rest.replace('.', '_')          
        return f"{owner}_{repo}_{rest}"
    else:
        return model_id.replace('/', '_')


def _strip_inspector_prefix(event_file):
    """Strip temp directory prefix from inspector event filenames."""
    if '__' in event_file:
        return event_file.split('__', 1)[1]
    return event_file

def log(msg):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    line = f"[{timestamp}] {msg}"
    print(line)
    with open(LOG_FILE, 'a') as f:
        f.write(line + '\n')


def _init_trace_counter():
    """
    Set _trace_counter to the highest existing prefix in TRACES_DIR.
    Called once at startup so a resumed scan doesn't overwrite folders.
    """
    global _trace_counter
    max_n = 0
    prefix_re = re.compile(r'^(\d{5})_')

    for subdir in ('FN', 'TP'):
        path = os.path.join(TRACES_DIR, subdir)
        if not os.path.isdir(path):
            continue
        for name in os.listdir(path):
            m = prefix_re.match(name)
            if m:
                n = int(m.group(1))
                if n > max_n:
                    max_n = n

    _trace_counter = max_n
    log(f"[trace_counter] Initialized to {_trace_counter} "
        f"(next folder will be {_trace_counter + 1:05d})")


# =============================================================================
# Local directory discovery
# =============================================================================
def discover_local(local_dir):
    """
    Build model entries from a local directory tree.
    Creates one entry per model file. The model_id is the relative path
    from the root dir using '/' separators.
    """
    models = []
    for root, dirs, files in os.walk(local_dir):
        for f in files:
            ext = os.path.splitext(f)[1].lower()
            if ext not in MODEL_EXTENSIONS:
                continue
            full_path = os.path.join(root, f)
            file_size = os.path.getsize(full_path)
           

            rel_path = os.path.relpath(full_path, local_dir)
            model_id = rel_path.replace(os.sep, '/')

            models.append({
                'model_id': model_id,
                'local_path': full_path,
                'model_files': [{
                    'filename': f,
                    'size': file_size,
                    'extension': ext,
                    'path': full_path,
                }],
                'total_size': file_size,
                'downloads': 0,
                'likes': 0,
                'has_safetensors': False,
                'has_pickle': ext in HIGH_RISK_EXTENSIONS,
                'tags': [],
                'metadata_reasons': [],
                'is_official': False,
            })

    log(f"[discover_local] Found {len(models)} model files in {local_dir}")
    return models


def download_local(model_info):
    """Copy a local model file into MODEL_TEMP_DIR for inspection."""
    if os.path.exists(MODEL_TEMP_DIR):
        shutil.rmtree(MODEL_TEMP_DIR)
    os.makedirs(MODEL_TEMP_DIR, exist_ok=True)

    src = model_info['local_path']
    fname = os.path.basename(src)
    dst = os.path.join(MODEL_TEMP_DIR, fname)
    shutil.copy2(src, dst)

    return [{
        'filename': fname,
        'path': dst,
        'size': os.path.getsize(dst),
    }]


# =============================================================================
# Inspect and classify
# =============================================================================
def run_inspector(model_dir, model_entry=None):
    """Run the inspector under the environment selected for this model."""
    if model_entry is None:
        env_name, py_bin = 'torch_current', POOL['torch_current']
    else:
        env_name, py_bin = select(model_entry)

    log(f"    Routed to env: {env_name}")

    display = os.environ.get('DISPLAY', '')
    cmd = (
        f"ulimit -u unlimited && ulimit -l unlimited && "
        f"{py_bin} {INSPECTOR_PATH} {model_dir}"
    )
    stdout_tmp = os.path.join(SCAN_DIR, '.inspector_stdout.tmp')
    stderr_tmp = os.path.join(SCAN_DIR, '.inspector_stderr.tmp')
    file_cmd = f"{cmd} >{stdout_tmp} 2>{stderr_tmp}"
    try:
        result = subprocess.run(
            ['bash', '-c', file_cmd],
            timeout=INSPECTOR_TIMEOUT, start_new_session=True )
        stderr = open(stderr_tmp).read() if os.path.exists(stderr_tmp) else ''
        return result.returncode == 0, env_name, stderr
    except subprocess.TimeoutExpired:
        stderr = open(stderr_tmp).read() if os.path.exists(stderr_tmp) else ''
        return False, env_name, f"Inspector timed out. stderr: {stderr[-500:]}"
    except Exception as e:
        return False, env_name, str(e)


def run_classifier(events_dir, output_json_path):
    """Run the classifier and return a normalized verdict dict."""
    try:
        result = subprocess.run(
            ['python3.9', CLASSIFIER_PATH, events_dir,
             '--output', output_json_path],
            capture_output=True, text=True,
        )

        if os.path.exists(output_json_path):
            with open(output_json_path) as f:
                verdict_data = json.load(f)

            is_malicious = verdict_data.get('is_malicious', False)
            behaviors = verdict_data.get('behaviors', [])

            pattern_ids = []
            for b in behaviors:
                for pm in b.get('pattern_matches', []):
                    pid = pm.get('pattern_id', '')
                    if pid and pid not in pattern_ids:
                        pattern_ids.append(pid)

            return {
                'verdict': 'MALICIOUS' if is_malicious else 'BENIGN',
                'behavior_ids': [b.get('behavior_id', '') for b in behaviors],
                'pattern_ids': pattern_ids,
                'behavior_count': len(behaviors),
                'loading_events': verdict_data.get('total_loading_events', 0),
                'execution_events': verdict_data.get('total_execution_events', 0),
                'raw_verdict': verdict_data,
            }

        return {
            'verdict': 'ERROR', 'behavior_ids': [], 'pattern_ids': [],
            'behavior_count': 0, 'loading_events': 0, 'execution_events': 0,
            'raw_verdict': None,
            'stderr': result.stderr[:500] if result.stderr else '',
        }

    except subprocess.TimeoutExpired:
        return {'verdict': 'TIMEOUT', 'behavior_ids': [], 'pattern_ids': [],
                'behavior_count': 0, 'loading_events': 0,
                'execution_events': 0, 'raw_verdict': None}
    except Exception as e:
        return {'verdict': 'ERROR', 'behavior_ids': [], 'pattern_ids': [],
                'behavior_count': 0, 'loading_events': 0,
                'execution_events': 0, 'raw_verdict': None, 'error': str(e)}


def cleanup_model():
    """Remove the per-model temp directory between runs."""
    if os.path.exists(MODEL_TEMP_DIR):
        shutil.rmtree(MODEL_TEMP_DIR, ignore_errors=True)


def evaluate_model(model_info, index, total):
    """Full pipeline for one model: copy -> inspect -> classify."""
    model_id = model_info['model_id']
    model_files = model_info['model_files']
    total_size_mb = model_info['total_size'] / (1024 * 1024)
    file_types = [os.path.splitext(f['filename'])[1] for f in model_files]

    log(f"\n[{index}/{total}] {model_id}")
    log(f"  Files: {len(model_files)} ({total_size_mb:.1f} MB) — types: {file_types}")
    log(f"  Source: LOCAL ({model_info['local_path']})")

    result = {
        'model_id': model_id,
        'model_files': [f['filename'] for f in model_files],
        'file_types': file_types,
        'total_size': model_info['total_size'],
        'has_pickle': model_info.get('has_pickle'),
        'timestamp': datetime.now().isoformat(),
        'status': 'pending',
        'source': 'local',
    }

    try:
        env_name_pre, _ = select(model_info)
        result['routed_env'] = env_name_pre
    except Exception as e:
        result['routed_env'] = 'routing_failed'
        log(f"  Routing failed: {e}")

    start_time = time.time()

    # Step 1: copy local file
    log(f"  Copying local file...")
    downloaded = download_local(model_info)

    if not downloaded:
        result['status'] = 'copy_failed'
        cleanup_model()
        return result

    copy_time = time.time() - start_time
    result['downloaded_files'] = [d['filename'] for d in downloaded]
    log(f"  Copied {len(downloaded)} file(s) in {copy_time:.1f}s")

    # Step 2: inspect (loading + execution phases)
    log(f"  Running eBPF inspector (loading + execution)...")
    inspector_start = time.time()
    inspector_ok, env_name, inspector_stderr = run_inspector(MODEL_TEMP_DIR, model_info)
    result['routed_env'] = env_name
    inspector_time = time.time() - inspector_start
    log(f"  Inspector finished in {inspector_time:.1f}s")

    if not inspector_ok:
        reason = (inspector_stderr or 'unknown')[:500]
        log(f"  Inspector FAILED ({env_name}): {reason[:300]}")
        # Check if events were written before the timeout killed the process
        events_dir_check = None
        for root, dirs, _ in os.walk(MODEL_TEMP_DIR):
            if 'events' in dirs:
                events_dir_check = os.path.join(root, 'events')
                break
        if events_dir_check and any(f.endswith('.json') for f in os.listdir(events_dir_check)):
            log(f"  Events found despite inspector failure — continuing to classify")
        else:
            result['status'] = 'inspector_failed'
            result['inspector_error'] = reason
            result['inspector_time'] = inspector_time
            result['copy_time'] = copy_time
            cleanup_model()
            return result

    # Step 3: locate the events directory the inspector wrote.
    events_dir = None
    for root, dirs, _ in os.walk(MODEL_TEMP_DIR):
        if 'events' in dirs:
            events_dir = os.path.join(root, 'events')
            break

    if not events_dir or not os.path.isdir(events_dir):
        log(f"  No events directory found after inspector run")
        result['status'] = 'no_events'
        result['inspector_time'] = inspector_time
        result['copy_time'] = copy_time
        cleanup_model()
        return result

    # Step 4: classify
    log(f"  Running classifier...")
    safe_name = _make_safe_name(model_id)
    classifier_json = os.path.join(RESULTS_DIR, f'{safe_name}_verdict.json')
    classifier_start = time.time()
    classifier_result = run_classifier(events_dir, classifier_json)
    classifier_time = time.time() - classifier_start
    log(f"  Classifier finished in {classifier_time:.2f}s")

    result['status'] = 'completed'
    result['verdict'] = classifier_result['verdict']
    result['behavior_ids'] = classifier_result['behavior_ids']
    result['pattern_ids'] = classifier_result['pattern_ids']
    result['behavior_count'] = classifier_result['behavior_count']
    result['loading_events'] = classifier_result['loading_events']
    result['execution_events'] = classifier_result['execution_events']
    result['inspector_time'] = inspector_time
    result['classifier_time'] = classifier_time
    result['copy_time'] = copy_time
    result['total_time'] = time.time() - start_time

    # Archive traces
    try:
        global _trace_counter
        _trace_counter += 1
        padded = f"{_trace_counter:05d}"
        folder_name = safe_name

        subdir = 'TP' if classifier_result['verdict'] == 'MALICIOUS' else 'FN'
        trace_subdir = os.path.join(TRACES_DIR, subdir, folder_name)
        os.makedirs(trace_subdir, exist_ok=True)

        if os.path.exists(events_dir):
            for event_file in os.listdir(events_dir):
                if not event_file.endswith('.json'):
                    continue
                src = os.path.join(events_dir, event_file)
                dst_name = _strip_inspector_prefix(event_file)
                if dst_name.endswith('_loading_events.json'):
                    dst_name = 'loading_events.json'
                elif dst_name.endswith('_execution_events.json'):
                    dst_name = 'execution_events.json'
                shutil.copy2(src, os.path.join(trace_subdir, dst_name))

        if classifier_result.get('raw_verdict'):
            verdict_path = os.path.join(trace_subdir,
                                        "verdict.json")
            with open(verdict_path, 'w') as f:
                json.dump(classifier_result['raw_verdict'], f,
                          indent=2, default=str)

        log(f"  Saved traces to {trace_subdir}")
    except Exception as e:
        log(f"  WARNING: Failed to save traces: {e}")

    # Extra copy for malicious verdicts
    if classifier_result['verdict'] == 'MALICIOUS':
        malicious_dir = os.path.join(RESULTS_DIR, 'TP')
        os.makedirs(malicious_dir, exist_ok=True)

        malicious_verdict = os.path.join(malicious_dir,
                                         f'{safe_name}_verdict.json')
        if classifier_result.get('raw_verdict'):
            with open(malicious_verdict, 'w') as f:
                json.dump(classifier_result['raw_verdict'], f,
                          indent=2, default=str)

        events_save_dir = os.path.join(malicious_dir, f'{safe_name}_events')
        if os.path.exists(events_dir):
            os.makedirs(events_save_dir, exist_ok=True)
            for event_file in os.listdir(events_dir):
                if not event_file.endswith('.json'):
                    continue
                src = os.path.join(events_dir, event_file)
                dst_name = _strip_inspector_prefix(event_file)
                if dst_name.endswith('_loading_events.json'):
                    dst_name = 'loading_events.json'
                elif dst_name.endswith('_execution_events.json'):
                    dst_name = 'execution_events.json'
                shutil.copy2(src, os.path.join(events_save_dir, dst_name))
        log(f"  MALICIOUS — saved evidence to {malicious_dir}")

    log(f"  Verdict: {classifier_result['verdict']}")
    if classifier_result['behavior_ids']:
        log(f"  Behaviors: {', '.join(classifier_result['behavior_ids'])}")
    if classifier_result['pattern_ids']:
        log(f"  Patterns: {', '.join(classifier_result['pattern_ids'][:10])}")

    cleanup_model()
    return result


# =============================================================================
# Scan runner
# =============================================================================
def save_progress(all_results):
    path = os.path.join(SCAN_DIR, 'results.json')
    tmp = path + '.tmp'
    with open(tmp, 'w') as f:
        json.dump(all_results, f, indent=2, default=str)
    os.replace(tmp, path)


def save_summary(all_results):
    benign = sum(1 for r in all_results if r.get('verdict') == 'BENIGN')
    malicious = sum(1 for r in all_results if r.get('verdict') == 'MALICIOUS')
    errors = len(all_results) - benign - malicious

    status_counts = {}
    for r in all_results:
        s = r.get('status', 'unknown')
        status_counts[s] = status_counts.get(s, 0) + 1

    type_counts = {}
    for r in all_results:
        for ft in r.get('file_types', []):
            type_counts[ft] = type_counts.get(ft, 0) + 1

    summary = {
        'platform': 'pickleball',
        'total_models': len(all_results),
        'benign': benign,
        'malicious': malicious,
        'errors': errors,
        'status_breakdown': status_counts,
        'file_types_tested': type_counts,
        'last_updated': datetime.now().isoformat(),
    }

    path = os.path.join(SCAN_DIR, 'summary.json')
    tmp = path + '.tmp'
    with open(tmp, 'w') as f:
        json.dump(summary, f, indent=2, default=str)
    os.replace(tmp, path)


def run_scan(models, resume=False):
    total = len(models)
    if total == 0:
        log("No models to evaluate")
        return []

    log(f"\n{'='*70}\nEvaluating {total} models\n{'='*70}")

    with open(os.path.join(SCAN_DIR, 'model_list.json'), 'w') as f:
        json.dump(models, f, indent=2, default=str)

    all_results = []
    completed_ids = set()

    if resume:
        results_path = os.path.join(SCAN_DIR, 'results.json')
        if os.path.exists(results_path):
            with open(results_path) as f:
                all_results = json.load(f)
            completed_ids = {r['model_id'] for r in all_results}
            log(f"  Resuming: {len(completed_ids)} already completed")

    for i, model_info in enumerate(models, 1):
        if model_info['model_id'] in completed_ids:
            continue

        try:
            result = evaluate_model(model_info, i, total)
            all_results.append(result)

            if len(all_results) % 5 == 0:
                save_progress(all_results)
                save_summary(all_results)
                benign = sum(1 for r in all_results if r.get('verdict') == 'BENIGN')
                malicious = sum(1 for r in all_results if r.get('verdict') == 'MALICIOUS')
                errors = len(all_results) - benign - malicious
                log(f"\n  --- Progress: {len(all_results)}/{total} | "
                    f"Benign: {benign} | Malicious: {malicious} | "
                    f"Errors: {errors} ---\n")

        except KeyboardInterrupt:
            log(f"\n\nInterrupted. Saving progress...")
            save_progress(all_results)
            save_summary(all_results)
            cleanup_model()
            break
        except Exception as e:
            log(f"  ERROR: {e}")
            all_results.append({
                'model_id': model_info['model_id'],
                'status': 'error', 'error': str(e),
            })
            cleanup_model()

    save_progress(all_results)
    save_summary(all_results)
    return all_results


def print_summary(results):
    benign = sum(1 for r in results if r.get('verdict') == 'BENIGN')
    malicious = sum(1 for r in results if r.get('verdict') == 'MALICIOUS')
    errors = len(results) - benign - malicious

    log(f"\n{'='*70}\nSCAN COMPLETE\n{'='*70}")
    log(f"  Total:     {len(results)} models")
    log(f"  Benign:    {benign} ({benign / max(len(results), 1) * 100:.1f}%)")
    log(f"  Malicious: {malicious} "
        f"({malicious / max(len(results), 1) * 100:.1f}%)")
    log(f"  Errors:    {errors}")

    type_counts = {}
    for r in results:
        for ft in r.get('file_types', []):
            type_counts[ft] = type_counts.get(ft, 0) + 1
    if type_counts:
        sorted_types = dict(sorted(type_counts.items(), key=lambda x: -x[1]))
        log(f"  File types tested: {sorted_types}")

    if malicious > 0:
        log(f"\n  MALICIOUS MODELS FOUND:")
        for r in results:
            if r.get('verdict') == 'MALICIOUS':
                patterns = ', '.join(r.get('pattern_ids', [])[:5])
                log(f"  {r['model_id']} — "
                    f"types={r.get('file_types', [])}, patterns: {patterns}")

    log(f"\nResults saved to: {SCAN_DIR}")
    log(f"True positives: {RESULTS_DIR}/TP/")


# =============================================================================
# Main
# =============================================================================
def main():
    try:
        validate_pool()
    except RuntimeError as e:
        log(f"FATAL: {e}")
        log("Run the sandbox builder (build_env_pool.sh) first.")
        sys.exit(1)

    parser = argparse.ArgumentParser(
        description='PickleBall dataset local scan pipeline')
    parser.add_argument('--local-dir', type=str, required=True,
                        help='Path to local directory of model files')
    parser.add_argument('--resume', action='store_true',
                        help='Resume an interrupted scan')
    args = parser.parse_args()

    if not os.path.isdir(args.local_dir):
        print(f"ERROR: --local-dir path does not exist: {args.local_dir}")
        sys.exit(1)

    os.makedirs(SCAN_DIR, exist_ok=True)
    os.makedirs(RESULTS_DIR, exist_ok=True)
    os.makedirs(TRACES_DIR, exist_ok=True)
    _init_trace_counter()

    log(f"{'='*70}")
    log(f"PickleBall Local Scan Pipeline")
    log(f"Source:     {args.local_dir}")
    log(f"File types: {len(MODEL_EXTENSIONS) + 2} formats supported")
    log(f"Work dir:   {SCAN_DIR}")
    log(f"Inspector:  {INSPECTOR_PATH}")
    log(f"Classifier: {CLASSIFIER_PATH}")
    log(f"Traces:     {TRACES_DIR}")
    log(f"{'='*70}")

    models = discover_local(args.local_dir)
    results = run_scan(models, resume=args.resume)
    print_summary(results)


if __name__ == '__main__':
    main()
