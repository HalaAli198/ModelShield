"""
kaggle_scan.py

Scans recent Kaggle model uploads across all supported formats
(pickle, safetensors, ONNX, Keras, TF, etc.) during both LOADING and
EXECUTION phases.

Discovery is resumable: progress is saved to discovery_progress.json
and the scan can be interrupted and resumed at any point.

Usage:
    sudo bash -c "ulimit -u unlimited && ulimit -l unlimited && \\
    python3.9 kaggle_scan.py --num-models 10000"
"""

import os
import sys
import json
import time
import shutil
import subprocess
import argparse
from datetime import datetime
from env_selector import select, validate_pool, POOL
import re
# =============================================================================
# Configuration
# =============================================================================
SCAN_DIR       =  '/path/to/kaggle_scan'
RESULTS_DIR    = os.path.join(SCAN_DIR, 'scan_results')
LOG_FILE       = os.path.join(SCAN_DIR, 'scan_log.txt')
MODEL_TEMP_DIR = os.path.join(SCAN_DIR, 'temp_model')
DISCOVERY_FILE = os.path.join(SCAN_DIR, 'discovery_progress.json')

INSPECTOR_PATH = '/path/to/model_inspector.py'
CLASSIFIER_PATH = '/path/to/attack_behavior_classifier.py'
TRACES_DIR = '/path/to/captured_events'

# Every extension the pipeline will download and inspect.
MODEL_EXTENSIONS = [
    '.pkl', '.pickle', '.joblib',
    '.bin', '.pt', '.pth', '.th', '.ckpt',
    '.safetensors', '.sft',
    '.h5', '.keras', '.pb', '.tflite',
    '.onnx',
    '.msgpack',
    '.xgb', '.bst', '.ubj', '.lgb', '.cbm',
    '.npy', '.npz',
    '.mlmodel',
    '.params',
    '.pdmodel', '.pdiparams',
    '.gguf',
]

# Subset of the above that can execute arbitrary code on load.
HIGH_RISK_EXTENSIONS = [
    '.pkl', '.pickle', '.joblib',
    '.bin', '.pt', '.pth', '.th', '.ckpt',
    '.npy', '.npz',
]

# Per-file size limits. Files outside this range are skipped during discovery.
MAX_DOWNLOAD_SIZE = 3 * 1024 * 1024 * 1024
MIN_MODEL_SIZE    = 100

# Subprocess timeouts, in seconds.
INSPECTOR_TIMEOUT  = 300
CLASSIFIER_TIMEOUT = 300

# Upper bound on files inspected per repo.
MAX_FILES_PER_MODEL = 10

# Download subprocess memory cap. Kaggle archives can be large and the SDK
# occasionally holds the full archive in memory; an unbounded download
# process can OOM the host and kill the scan.
DOWNLOAD_MEMORY_LIMIT_BYTES = 4 * 1024 * 1024 * 1024
DOWNLOAD_TIMEOUT            = 600
# Monotonic counter used to prefix archived trace folders.
_trace_counter = 0
def log(msg):
    ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    line = f"[{ts}] {msg}"
    print(line, flush=True)
    try:
        with open(LOG_FILE, 'a') as f:
            f.write(line + '\n')
    except Exception:
        pass


def _init_trace_counter():
    """
    Set _trace_counter to the highest existing prefix in TRACES_DIR.
    Called once at startup so a resumed scan doesn't overwrite folders
    from the interrupted run.
    """
    global _trace_counter
    max_n = 0
    prefix_re = re.compile(r'^(\d{5})_')

    for subdir in ('benign', 'malicious'):
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
# Kaggle API
# =============================================================================
def get_kaggle_api():
    """Initialize the Kaggle API. Credentials are read from ~/.kaggle/kaggle.json."""
    try:
        from kaggle.api.kaggle_api_extended import KaggleApi
        api = KaggleApi()
        api.authenticate()
        return api
    except Exception as e:
        log(f"ERROR: Kaggle API init failed: {e}")
        sys.exit(1)


def model_list_with_token(api, sort_by='createTime', page_size=20, page_token=None):
    """
    Call api.model_list and capture the next_page_token. The Kaggle SDK
    prints this token to stdout rather than returning it, so we redirect
    stdout and parse the line that carries it.
    """
    import io
    from contextlib import redirect_stdout

    f = io.StringIO()
    with redirect_stdout(f):
        models = api.model_list(
            sort_by=sort_by,
            page_size=page_size,
            page_token=page_token,
        )

    output = f.getvalue()
    next_token = None
    for line in output.splitlines():
        if line.startswith('Next Page Token = '):
            next_token = line.split('= ', 1)[1].strip()
            break

    return models, next_token


# =============================================================================
# Discovery progress
# =============================================================================
def load_discovery():
    """Return (found_models, checked_ids, complete, page) from the progress file."""
    if os.path.exists(DISCOVERY_FILE):
        try:
            with open(DISCOVERY_FILE) as f:
                d = json.load(f)
            return (
                d.get('found', []),
                set(d.get('checked', [])),
                d.get('complete', False),
                d.get('page', 1),
            )
        except Exception:
            pass
    return [], set(), False, 1


def save_discovery(found, checked, complete=False, page=1):
    """Atomically save discovery progress via temp-file rename."""
    data = {
        'found': found,
        'checked': list(checked),
        'complete': complete,
        'page': page,
        'saved': datetime.now().isoformat(),
        'total': len(found),
    }
    tmp = DISCOVERY_FILE + '.tmp'
    with open(tmp, 'w') as f:
        json.dump(data, f, default=str)
    os.replace(tmp, DISCOVERY_FILE)


# =============================================================================
# Metadata reasons
# =============================================================================
def compute_metadata_reasons(entry, model_files):
    """
    Record metadata observations about a repo (raw pickle without safetensors,
    tiny high-risk files, etc.). Used for reporting only; does not affect
    whether the model is scanned.
    """
    reasons = []

    extensions = [mf['extension'] for mf in model_files]

    has_raw_pickle = any(ext in ['.pkl', '.pickle'] for ext in extensions)
    has_joblib = any(ext == '.joblib' for ext in extensions)
    has_numpy = any(ext in ['.npy', '.npz'] for ext in extensions)
    has_safetensors = any(ext == '.safetensors' for ext in extensions)
    has_pickle_based = any(ext in HIGH_RISK_EXTENSIONS for ext in extensions)

    framework = entry.get('framework', 'unknown')
    downloads = entry.get('downloads', 0)

    if has_raw_pickle and not has_safetensors:
        reasons.append('raw pickle without safetensors')

    if has_joblib:
        reasons.append('single joblib file' if len(model_files) == 1
                       else 'contains joblib file')

    if has_numpy and not has_safetensors:
        reasons.append('numpy files (pickle inside .npy/.npz)')

    if not has_safetensors and has_pickle_based:
        reasons.append('no safetensors alternative')

    if downloads == 0:
        reasons.append('zero downloads')
    elif downloads < 5:
        reasons.append(f'near-zero downloads ({downloads})')
    elif downloads < 50:
        reasons.append(f'very low downloads ({downloads})')

    for mf in model_files:
        if mf['size'] and mf['size'] < 10000:
            if mf['extension'] in HIGH_RISK_EXTENSIONS:
                reasons.append(
                    f'tiny high-risk file: {mf["filename"]} ({mf["size"]} bytes)')
                break

    pickle_count = sum(1 for ext in extensions if ext in ['.pkl', '.pickle'])
    if pickle_count >= 2:
        reasons.append(f'{pickle_count} pickle files')

    if framework and framework != 'unknown':
        reasons.append(f'framework: {framework}')

    return reasons


# =============================================================================
# Discovery (resumable)
# =============================================================================
def discover_models(api, num_models):
    """
    Discover up to `num_models` recently created Kaggle models. Resumable:
    state is persisted to DISCOVERY_FILE on page boundaries and on
    rate-limit sleeps.
    """
    prev_found, prev_checked, complete, prev_page = load_discovery()

    if complete and prev_found:
        log(f"[discover] Using {len(prev_found)} models from completed run")
        return prev_found

    found = list(prev_found)
    found_ids = {m.get('model_ref', '') for m in found}
    checked = set(prev_checked)

    if found:
        log(f"[discover] Resuming: {len(found)} found, {len(checked)} checked")
    else:
        log(f"[discover] Scanning recently created models (target: {num_models})")

    count = len(checked)
    errors = 0
    page_token = None
    page_num = 0

    while len(found) < num_models:
        try:
            models, next_token = model_list_with_token(
                api,
                sort_by='createTime',
                page_size=20,
                page_token=page_token,
            )

            if not models:
                log(f"  No more models returned")
                break

            page_num += 1
            log(f"  Page {page_num}: {len(models)} models")

            for model in models:
                if len(found) >= num_models:
                    break

                count += 1
                ref = model.ref

                if ref in checked or ref in found_ids:
                    continue

                checked.add(ref)

                try:
                    # model_list returns shallow records; model_get is the
                    # only way to reach the instance list with version and
                    # framework metadata we need for downloading.
                    detail = api.model_get(ref)
                    instances = getattr(detail, 'instances', [])

                    if not instances:
                        continue

                    inst = instances[0]

                    framework = str(getattr(inst, 'framework', 'unknown'))
                    inst_slug = getattr(inst, 'slug', '')
                    version_num = getattr(inst, 'versionNumber', 1)
                    total_bytes = getattr(inst, 'totalUncompressedBytes', 0)

                    # Build the instance_ref that model_instance_version_download
                    # expects. The framework segment comes from the instance URL
                    # because the 'framework' field uses a display name that
                    # doesn't always match the URL slug.
                    inst_url = getattr(inst, 'url', '')
                    url_parts = inst_url.rstrip('/').split('/')
                    if len(url_parts) >= 2:
                        fw_name = url_parts[-2]
                        instance_ref = f'{ref}/{fw_name}/{inst_slug}'
                    else:
                        instance_ref = f'{ref}/{framework}/{inst_slug}'

                    parts = ref.split('/')

                    # Prefix the ID with the platform name so Kaggle, HF, and
                    # Kaggle results can be pooled into a single corpus
                    # without collisions.
                    entry = {
                        'model_id': f'kaggle_{ref}',
                        'model_ref': ref,
                        'instance_ref': instance_ref,
                        'version_number': version_num,
                        'platform': 'kaggle',
                        'framework': framework,
                        'owner': parts[0] if parts else '',
                        'title': getattr(detail, 'title', ''),
                        'downloads': 0,
                        'likes': 0,
                        'total_size': total_bytes,
                    }
                    found.append(entry)
                    found_ids.add(ref)

                    size_mb = total_bytes / (1024 * 1024) if total_bytes else 0
                    log(f"    found: {ref} — framework: {framework}, "
                        f"size: {size_mb:.1f} MB, instance: {instance_ref}")

                except Exception as e:
                    errors += 1
                    if '429' in str(e):
                        log("  Rate limited, sleeping 60s...")
                        save_discovery(found, checked, False, page_num)
                        time.sleep(60)
                    else:
                        log(f"    Error on {ref}: {e}")
                        time.sleep(1)

                time.sleep(0.5)

            # A short page is the end of the listing.
            if len(models) < 20:
                log(f"  Last page (got {len(models)} < 20)")
                break

            if next_token:
                page_token = next_token
            else:
                log(f"  No more page tokens")
                break

            if count % 100 == 0:
                log(f"  Progress: checked {count}, found {len(found)}, errors {errors}")
                save_discovery(found, checked, False, page_num)

        except KeyboardInterrupt:
            log(f"\n  Discovery interrupted. Saving progress...")
            save_discovery(found, checked, False, page_num)
            return found

        except Exception as e:
            errors += 1
            log(f"  Discovery error: {e}")
            if '429' in str(e):
                save_discovery(found, checked, False, page_num)
                time.sleep(60)
            else:
                time.sleep(5)
            if errors > 50:
                log(f"  Too many errors ({errors}), stopping discovery")
                break

    save_discovery(found, checked, True, page_num)

    log(f"\n[discover] complete:")
    log(f"  Pages scanned: {page_num}")
    log(f"  Models checked: {count}")
    log(f"  Found with instances: {len(found)}")
    log(f"  API errors: {errors}")

    fw_counts = {}
    for m in found:
        fw = m.get('framework', 'unknown')
        fw_counts[fw] = fw_counts.get(fw, 0) + 1
    log(f"  Frameworks: {fw_counts}")

    return found


# =============================================================================
# File extraction (post-download, from disk)
# =============================================================================
def find_model_files(directory):
    """Walk the download directory and return a list of model files to inspect."""
    found = []

    for root, dirs, files in os.walk(directory):
        for fn in files:
            fp = os.path.join(root, fn)
            ext = os.path.splitext(fn)[1].lower()

            if ext in MODEL_EXTENSIONS:
                try:
                    sz = os.path.getsize(fp)
                    if sz >= MIN_MODEL_SIZE and sz <= MAX_DOWNLOAD_SIZE:
                        found.append({
                            'filename': fn,
                            'path': fp,
                            'size': sz,
                            'extension': ext,
                        })
                except Exception:
                    pass

    # Repos with many checkpoints: keep the files most likely to exercise
    # code paths we care about (pickle first, pytorch second, etc.).
    if len(found) > MAX_FILES_PER_MODEL:
        def priority(mf):
            if mf['extension'] in ['.pkl', '.pickle', '.joblib']:
                return 0
            if mf['extension'] in ['.bin', '.pt', '.pth', '.th', '.ckpt']:
                return 1
            if mf['extension'] in ['.npy', '.npz', '.h5', '.keras']:
                return 2
            if mf['extension'] in ['.onnx', '.pb', '.msgpack']:
                return 3
            return 4
        found.sort(key=priority)
        found = found[:MAX_FILES_PER_MODEL]

    return found


# =============================================================================
# Download
# =============================================================================
def download_model(entry):
    """
    Download a model instance version via the Kaggle SDK, wrapped in a
    subprocess with an address-space limit so a single huge archive
    cannot OOM the scanner.
    """
    try:
        if os.path.exists(MODEL_TEMP_DIR):
            shutil.rmtree(MODEL_TEMP_DIR)
        os.makedirs(MODEL_TEMP_DIR, exist_ok=True)

        instance_ref = entry.get('instance_ref', '')
        version_num = entry.get('version_number', 1)
        version_ref = f'{instance_ref}/{version_num}'

        download_script = f'''
import os
import resource
# Hard address-space cap; OOMs the download child instead of the scanner.
resource.setrlimit(
    resource.RLIMIT_AS,
    ({DOWNLOAD_MEMORY_LIMIT_BYTES}, {DOWNLOAD_MEMORY_LIMIT_BYTES}),
)
from kaggle.api.kaggle_api_extended import KaggleApi
api = KaggleApi()
api.authenticate()
api.model_instance_version_download(
    "{version_ref}",
    path="{MODEL_TEMP_DIR}",
    untar=True,
)
'''
        result = subprocess.run(
            [sys.executable, '-c', download_script],
            capture_output=True, text=True,
            timeout=DOWNLOAD_TIMEOUT,
            env={**os.environ},
        )

        if result.returncode != 0:
            log(f"    Download subprocess failed (rc={result.returncode})")
            if result.stderr:
                log(f"    stderr: {result.stderr[:200]}")
            return []

        return find_model_files(MODEL_TEMP_DIR)

    except subprocess.TimeoutExpired:
        log(f"    Download timed out")
        return []
    except Exception as e:
        log(f"    Download failed: {e}")
        return []


# =============================================================================
# Inspect and classify
# =============================================================================
def run_inspector(model_dir, model_entry=None):
    """Run the inspector in the environment selected for this model."""
    if model_entry is None:
        env_name, py_bin = 'torch_current', POOL['torch_current']
    else:
        env_name, py_bin = select(model_entry)

    log(f"    Selected env: {env_name}")

    try:
        cmd = (
            f"ulimit -u unlimited && ulimit -l unlimited && "
            f"{py_bin} {INSPECTOR_PATH} {model_dir}"
        )
        result = subprocess.run(
            ['bash', '-c', cmd],
            capture_output=True, text=True,
            timeout=INSPECTOR_TIMEOUT,
        )
        if result.returncode != 0:
            log(f"    Inspector returncode={result.returncode}")
            if result.stderr:
                log(f"    Inspector stderr: {result.stderr[:300]}")
        return result.returncode == 0, env_name
    except subprocess.TimeoutExpired:
        log(f"    Inspector timed out ({INSPECTOR_TIMEOUT}s)")
        return False, env_name
    except Exception as e:
        log(f"    Inspector error: {e}")
        return False, env_name


def run_classifier(events_dir, output_json):
    """Run the classifier and return a normalized verdict dict."""
    try:
        result = subprocess.run(
            ['python3.9', CLASSIFIER_PATH, events_dir,
             '--output', output_json],
            capture_output=True, text=True,
            timeout=CLASSIFIER_TIMEOUT,
        )

        if os.path.exists(output_json):
            with open(output_json) as f:
                vd = json.load(f)

            behaviors = vd.get('behaviors', [])
            # Flatten matched pattern IDs from all behaviors, de-duplicated
            # while preserving insertion order for readable log output.
            pids = []
            for b in behaviors:
                for pm in b.get('pattern_matches', []):
                    p = pm.get('pattern_id', '')
                    if p and p not in pids:
                        pids.append(p)

            return {
                'verdict': 'MALICIOUS' if vd.get('is_malicious') else 'BENIGN',
                'behavior_ids': [b.get('behavior_id', '') for b in behaviors],
                'pattern_ids': pids,
                'behavior_count': len(behaviors),
                'loading_events': vd.get('total_loading_events', 0),
                'execution_events': vd.get('total_execution_events', 0),
                'raw_verdict': vd,
            }

        return {
            'verdict': 'ERROR', 'behavior_ids': [], 'pattern_ids': [],
            'behavior_count': 0, 'loading_events': 0, 'execution_events': 0,
            'raw_verdict': None,
            'stderr': result.stderr[:500] if result.stderr else '',
        }
    except subprocess.TimeoutExpired:
        return {
            'verdict': 'TIMEOUT', 'behavior_ids': [], 'pattern_ids': [],
            'behavior_count': 0, 'loading_events': 0, 'execution_events': 0,
            'raw_verdict': None,
        }
    except Exception as e:
        return {
            'verdict': 'ERROR', 'behavior_ids': [], 'pattern_ids': [],
            'behavior_count': 0, 'loading_events': 0, 'execution_events': 0,
            'raw_verdict': None, 'error': str(e),
        }


def cleanup():
    """Remove the per-model temp directory between runs."""
    if os.path.exists(MODEL_TEMP_DIR):
        shutil.rmtree(MODEL_TEMP_DIR, ignore_errors=True)


def evaluate_model(entry, index, total):
    """Full pipeline for one model: download -> inspect -> classify."""
    model_id = entry['model_id']
    model_ref = entry.get('model_ref', model_id)
    title = entry.get('title', model_ref)

    log(f"\n[{index}/{total}] [Kaggle] {title} ({model_ref})")
    log(f"  Owner: {entry.get('owner', '?')}, "
        f"Framework: {entry.get('framework', '?')}, "
        f"Downloads: {entry.get('downloads', 0)}")

    result = {
        'model_id': model_id,
        'model_ref': model_ref,
        'platform': 'kaggle',
        'title': title,
        'owner': entry.get('owner', ''),
        'framework': entry.get('framework', 'unknown'),
        'downloads': entry.get('downloads', 0),
        'likes': entry.get('likes', 0),
        'timestamp': datetime.now().isoformat(),
        'status': 'pending',
    }

    start_time = time.time()

    # Step 1: download
    log(f"  Downloading...")
    downloaded = download_model(entry)
    if not downloaded:
        result['status'] = 'download_failed'
        cleanup()
        return result

    download_time = time.time() - start_time
    result['downloaded_files'] = [f['filename'] for f in downloaded]
    result['file_types'] = [f['extension'] for f in downloaded]
    result['total_size'] = sum(f['size'] for f in downloaded)
    total_size_mb = result['total_size'] / (1024 * 1024)

    # Metadata reasons are computed post-download here (not at discovery
    # time like HF/ModelScope) because Kaggle's listing endpoint doesn't
    # expose per-file info. We only see filenames once the archive is
    # on disk.
    metadata_reasons = compute_metadata_reasons(entry, downloaded)
    result['metadata_reasons'] = metadata_reasons

    has_safetensors = any(f['extension'] == '.safetensors' for f in downloaded)
    has_pickle = any(f['extension'] in HIGH_RISK_EXTENSIONS for f in downloaded)
    result['has_safetensors'] = has_safetensors
    result['has_pickle'] = has_pickle

    log(f"  Files: {len(downloaded)} ({total_size_mb:.1f} MB) — "
        f"types: {result['file_types']}")
    log(f"  SafeTensors: {has_safetensors}, Pickle: {has_pickle}")
    if metadata_reasons:
        log(f"  Metadata: {', '.join(metadata_reasons[:5])}")
    log(f"  Downloaded in {download_time:.1f}s")

    # Step 2: inspect (loading + execution phases)
    log(f"  Running inspector (loading + execution)...")
    inspector_start = time.time()
    inspector_ok, env_name = run_inspector(MODEL_TEMP_DIR, entry)
    result['routed_env'] = env_name
    inspector_time = time.time() - inspector_start
    log(f"  Inspector finished in {inspector_time:.1f}s")

    if not inspector_ok:
        result['status'] = 'inspector_failed'
        result['inspector_time'] = inspector_time
        cleanup()
        return result

    # Step 3: locate the events directory the inspector wrote.
    # Exact location varies by model layout; first 'events' dir wins.
    events_dir = None
    for root, dirs, files in os.walk(MODEL_TEMP_DIR):
        if 'events' in dirs:
            events_dir = os.path.join(root, 'events')
            break

    if not events_dir or not os.path.isdir(events_dir):
        result['status'] = 'no_events'
        result['inspector_time'] = inspector_time
        cleanup()
        return result

    # Step 4: classify
    log(f"  Running classifier...")
    safe_name = model_id.replace('/', '_').replace('\\', '_')
    classifier_json = os.path.join(RESULTS_DIR, f'{safe_name}_verdict.json')
    classifier_result = run_classifier(events_dir, classifier_json)

    result['status'] = 'completed'
    result['verdict'] = classifier_result['verdict']
    result['behavior_ids'] = classifier_result['behavior_ids']
    result['pattern_ids'] = classifier_result['pattern_ids']
    result['behavior_count'] = classifier_result.get('behavior_count', 0)
    result['loading_events'] = classifier_result.get('loading_events', 0)
    result['execution_events'] = classifier_result.get('execution_events', 0)
    result['inspector_time'] = inspector_time
    result['total_time'] = time.time() - start_time
    # Archive traces for every model (benign and malicious) so the full
    # corpus is available for offline pattern discovery.
    try:
        global _trace_counter
        _trace_counter += 1
        padded = f"{_trace_counter:05d}"
        folder_name = f"{padded}_{safe_name}"

        subdir = 'malicious' if classifier_result['verdict'] == 'MALICIOUS' else 'benign'
        trace_subdir = os.path.join(TRACES_DIR, subdir, folder_name)
        os.makedirs(trace_subdir, exist_ok=True)

        if os.path.exists(events_dir):
           model_prefix = f"{padded}_{safe_name}"
           for event_file in os.listdir(events_dir):
               if not event_file.endswith('.json'):
                  continue
               src = os.path.join(events_dir, event_file)
               if '__' in event_file:
                  tail = event_file.split('__', 1)[1]
                  dst_name = f"{model_prefix}__{tail}"
               else:
                  dst_name = f"{model_prefix}_{event_file}"
               shutil.copy2(src, os.path.join(trace_subdir, dst_name))

        if classifier_result.get('raw_verdict'):
            verdict_path = os.path.join(trace_subdir,
                                        f"{padded}_{safe_name}_verdict.json")
            with open(verdict_path, 'w') as f:
                json.dump(classifier_result['raw_verdict'], f,
                          indent=2, default=str)

        log(f"  Saved traces to {trace_subdir}")
    except Exception as e:
        log(f"  WARNING: Failed to save traces: {e}")
    # Copy evidence for malicious verdicts to a dedicated folder.
    if classifier_result['verdict'] == 'MALICIOUS':
        malicious_dir = os.path.join(RESULTS_DIR, 'malicious')
        os.makedirs(malicious_dir, exist_ok=True)

        if classifier_result.get('raw_verdict'):
            verdict_path = os.path.join(
                malicious_dir, f'{safe_name}_verdict.json')
            with open(verdict_path, 'w') as f:
                json.dump(classifier_result['raw_verdict'], f, indent=2, default=str)

        if os.path.exists(events_dir):
            events_save = os.path.join(
                malicious_dir, f'{safe_name}_events')
            shutil.copytree(events_dir, events_save, dirs_exist_ok=True)

        log(f"  MALICIOUS — saved evidence to {malicious_dir}")

   

    log(f"  Verdict: {classifier_result['verdict']}")
    if classifier_result['behavior_ids']:
        log(f"  Behaviors: {', '.join(classifier_result['behavior_ids'])}")
    if classifier_result['pattern_ids']:
        log(f"  Patterns: {', '.join(classifier_result['pattern_ids'][:10])}")

    cleanup()
    return result


# =============================================================================
# Scan runner
# =============================================================================
def save_progress(results):
    """Atomically write the combined results list."""
    path = os.path.join(SCAN_DIR, 'results_kaggle.json')
    tmp = path + '.tmp'
    with open(tmp, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    os.replace(tmp, path)


def save_summary(all_results):
    """Write a small aggregate summary alongside the full results file."""
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

    framework_counts = {}
    for r in all_results:
        fw = r.get('framework', 'unknown')
        framework_counts[fw] = framework_counts.get(fw, 0) + 1

    summary = {
        'platform': 'kaggle',
        'total_models': len(all_results),
        'benign': benign,
        'malicious': malicious,
        'errors': errors,
        'status_breakdown': status_counts,
        'file_types_tested': type_counts,
        'frameworks': framework_counts,
        'last_updated': datetime.now().isoformat(),
    }

    path = os.path.join(SCAN_DIR, 'summary_kaggle.json')
    tmp = path + '.tmp'
    with open(tmp, 'w') as f:
        json.dump(summary, f, indent=2, default=str)
    os.replace(tmp, path)


# =============================================================================
# Main
# =============================================================================
def main():
    parser = argparse.ArgumentParser(description='Kaggle model scan pipeline')
    parser.add_argument('--num-models', type=int, default=10000,
                        help='Number of models to scan (default: 10000)')
    parser.add_argument('--resume', action='store_true',
                        help='Resume an interrupted scan')
    parser.add_argument('--reset-discovery', action='store_true',
                        help='Force restart discovery from scratch')
    args = parser.parse_args()

    os.makedirs(SCAN_DIR, exist_ok=True)
    os.makedirs(RESULTS_DIR, exist_ok=True)
    os.makedirs(TRACES_DIR, exist_ok=True) 
    _init_trace_counter()  
    if args.reset_discovery and os.path.exists(DISCOVERY_FILE):
        os.remove(DISCOVERY_FILE)
        log("Discovery progress reset.")

    log(f"\n{'='*70}")
    log(f"  Kaggle Model Scan Pipeline")
    log(f"  Target:     {args.num_models} models")
    log(f"  Extensions: {len(MODEL_EXTENSIONS)} formats supported")
    log(f"  Work dir:   {SCAN_DIR}")
    log(f"  Inspector:  {INSPECTOR_PATH}")
    log(f"  Classifier: {CLASSIFIER_PATH}")
    log(f"{'='*70}\n")

    api = get_kaggle_api()
    log("Kaggle API authenticated")

    models = discover_models(api, args.num_models)
    if not models:
        log("No models found.")
        return

    all_results = []
    completed_ids = set()

    # Auto-resume from any existing results file. --resume is kept as an
    # explicit flag for parity with the HF pipeline.
    results_path = os.path.join(SCAN_DIR, 'results_kaggle.json')
    if os.path.exists(results_path):
        try:
            with open(results_path) as f:
                all_results = json.load(f)
            completed_ids = {r['model_id'] for r in all_results}
            log(f"Resuming: {len(completed_ids)} already completed")
        except Exception:
            pass

    total = len(models)
    for i, entry in enumerate(models, 1):
        if entry['model_id'] in completed_ids:
            continue

        try:
            result = evaluate_model(entry, i, total)
            all_results.append(result)
           
            # Checkpoint every 5 models.
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
            log("\nInterrupted. Saving progress...")
            save_progress(all_results)
            save_summary(all_results)
            cleanup()
            break

        except Exception as e:
            log(f"  ERROR: {e}")
            all_results.append({
                'model_id': entry['model_id'],
                'status': 'error',
                'error': str(e),
                'platform': 'kaggle',
            })
            cleanup()

    save_progress(all_results)
    save_summary(all_results)

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

    log(f"\n{'='*70}")
    log(f"  KAGGLE SCAN COMPLETE")
    log(f"  Scanned:   {len(all_results)}")
    log(f"  Benign:    {benign} ({benign / max(len(all_results), 1) * 100:.1f}%)")
    log(f"  Malicious: {malicious} "
        f"({malicious / max(len(all_results), 1) * 100:.1f}%)")
    log(f"  Errors:    {errors}")
    log(f"  Status breakdown: {status_counts}")
    log(f"  File types tested: "
        f"{dict(sorted(type_counts.items(), key=lambda x: -x[1]))}")
    log(f"{'='*70}")

    if malicious > 0:
        log(f"\n  MALICIOUS MODELS FOUND:")
        for r in all_results:
            if r.get('verdict') == 'MALICIOUS':
                patterns = ', '.join(r.get('pattern_ids', [])[:5])
                metadata = ', '.join(r.get('metadata_reasons', [])[:3])
                log(f"  {r['model_id']} — "
                    f"downloads={r.get('downloads', 0)}, "
                    f"types={r.get('file_types')}, "
                    f"behaviors={r.get('behavior_count', 0)}, "
                    f"patterns: {patterns}"
                    f"{f', metadata: {metadata}' if metadata else ''}")

    log(f"\nResults saved to: {SCAN_DIR}")
    log(f"Malicious evidence: {RESULTS_DIR}/malicious/")


if __name__ == '__main__':
    main()
