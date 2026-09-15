"""
Hugging_Face_scan.py

Scans recently uploaded HuggingFace models(default: last 10 days) across all supported formats
(pickle, safetensors, ONNX, Keras, TF, etc.) during both LOADING and
EXECUTION phases. Discovery is resumable and runs in continuous polling
cycles.

Prerequisites:
    1. A HuggingFace API token with read access (set HF_TOKEN below).
       Get one at: https://huggingface.co/settings/tokens
    2. The runtime environment pool must be built (build_env_pool.sh).
    3. Must run as root (eBPF requires CAP_SYS_ADMIN).

Arguments:
    --num-models N       Number of models to scan per cycle (default: 500)
    --resume             Resume an interrupted scan from the last checkpoint
    --reset-discovery    Discard cached discovery state and start fresh
    --poll-interval S    Seconds between continuous scan cycles (default: 1800).
                         The scanner runs in a loop: discover → scan → sleep →
                         repeat. Press Ctrl+C during sleep to exit cleanly.

Usage (run from the repository root):
    SCANNER_ENV=~/modelshield/scanner_env

    # Single batch: scan 500 recently uploaded models:
    sudo bash -c "ulimit -u unlimited && ulimit -l unlimited && \\
        $SCANNER_ENV/bin/python3.9 \\
        Platform_Scanning/Hugging_Face_scan.py"

    # Larger batch: scan 1000 models:
    sudo bash -c "ulimit -u unlimited && ulimit -l unlimited && \\
        $SCANNER_ENV/bin/python3.9 \\
        Platform_Scanning/Hugging_Face_scan.py \\
        --num-models 1000"

    # Resume after interruption:
    sudo bash -c "ulimit -u unlimited && ulimit -l unlimited && \\
        $SCANNER_ENV/bin/python3.9 \\
        Platform_Scanning/Hugging_Face_scan.py \\
        --resume"

    # Continuous monitoring: scan 500 models every 10 minutes:
    sudo bash -c "ulimit -u unlimited && ulimit -l unlimited && \\
        $SCANNER_ENV/bin/python3.9 \\
        Platform_Scanning/Hugging_Face_scan.py \\
        --num-models 500 --poll-interval 600"
        
Results are saved under ~/hf_scan_results/ in the home directory of
the user who invoked sudo (via SUDO_USER), so multiple reviewers can
run scans without overwriting each other's results.
"""

import os
import sys
import json
import time
import shutil
import argparse
import subprocess
import multiprocessing
import queue
import re

from datetime import datetime, timezone
from concurrent.futures import TimeoutError as FuturesTimeoutError

_HOME = os.path.expanduser("~" + os.environ.get("SUDO_USER", ""))

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(_SCRIPT_DIR)

sys.path.insert(0, os.path.join(_REPO_ROOT, 'Runtime_Environments'))
from env_selector import select, validate_pool, POOL
from huggingface_hub import HfApi, hf_hub_download, list_models, hf_hub_url, get_hf_file_metadata

# =============================================================================
# HuggingFace API Token
# =============================================================================
# Get a token at https://huggingface.co/settings/tokens
# Paste your token below (read access is sufficient).
HF_TOKEN = "paste_your_token_here"

# =============================================================================
# Configuration
# =============================================================================
SCAN_DIR = os.path.join(_HOME, 'hf_scan_results')
RESULTS_DIR = os.path.join(SCAN_DIR, 'verdict_results')
LOG_FILE = os.path.join(SCAN_DIR, 'hf_scan_log.txt')
MODEL_TEMP_DIR = os.path.join(SCAN_DIR, 'temp_model')
DISCOVERY_FILE = os.path.join(SCAN_DIR, 'discovery_progress.json')
TRACES_DIR = os.path.join(SCAN_DIR, 'traces')

INSPECTOR_PATH = os.path.join(_REPO_ROOT, 'ModelShield_Core_Scripts', 'model_inspector.py')
CLASSIFIER_PATH = os.path.join(_REPO_ROOT, 'ModelShield_Core_Scripts', 'attack_behavior_classifier.py')

# File extensions the pipeline inspects.
MODEL_EXTENSIONS = [
    '.pkl', '.pickle', '.joblib',
    '.bin', '.pt', '.pt2', '.pth', '.th',
    '.safetensors',
    '.h5', '.keras', '.pb', '.tflite',
    '.onnx',
    '.msgpack',
    '.xgb', '.bst', '.ubj', '.lgb', '.cbm',
    '.npy', '.npz', '.dill',
    '.mlmodel',
    '.params',
    '.pdmodel', '.pdiparams', '.pmml',
]

# Extensions that deserialize arbitrary Python objects on load.
HIGH_RISK_EXTENSIONS = ['.pkl', '.pickle', '.joblib', '.dill', '.bin', '.pt', '.pth',
                        '.th', '.npy', '.npz']

# Per-file size limits.
MAX_MODEL_SIZE = 3 * 1024 * 1024 * 1024
MIN_MODEL_SIZE = 100

# Subprocess timeouts, in seconds.
INSPECTOR_TIMEOUT = 300
CLASSIFIER_TIMEOUT = 300
DOWNLOAD_TIMEOUT = 300

# Upper bound on files inspected per repo.
MAX_FILES_PER_MODEL = 10

# Only scan models uploaded within this many days.
MAX_AGE_DAYS = 10

# Monotonic counter used to prefix archived trace folders.
_trace_counter = 0

# Orgs treated as known-legitimate for metadata reporting.
_OFFICIAL_ORGS = {
    'meta-llama', 'openai', 'mistralai', 'google', 'microsoft',
    'stabilityai', 'huggingface', 'bigscience', 'EleutherAI',
    'facebook', 'apple', 'nvidia', 'salesforce', 'tiiuae',
    'databricks', 'mosaicml', 'allenai', 'deepseek-ai',
    'Qwen', 'THUDM', 'baichuan-inc', 'internlm',
}

# Names that frequently appear in typosquatted repositories.
_POPULAR_KEYWORDS = [
    'llama', 'gpt', 'mistral', 'gemma', 'phi', 'qwen',
    'stable-diffusion', 'whisper', 'bert-base', 'roberta',
    'clip', 'deepseek', 'falcon', 'vicuna', 'alpaca',
    'codellama', 'starcoder', 'yi-', 'baichuan', 'chatglm',
]


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


def get_already_scanned():
    """Collect all model IDs we've already scanned from results files."""
    scanned = set()
    if not os.path.isdir(SCAN_DIR):
        return scanned

    for fname in os.listdir(SCAN_DIR):
        fpath = os.path.join(SCAN_DIR, fname)
        if fname.startswith('results') and fname.endswith('.json'):
            try:
                with open(fpath) as f:
                    results = json.load(f)
                for r in results:
                    if 'model_id' in r:
                        scanned.add(r['model_id'])
            except Exception:
                pass

    return scanned


# =============================================================================
# File extraction
# =============================================================================
def _extract_model_files(siblings):
    """Extract all model files from a HuggingFace siblings list."""
    model_files = []
    for sibling in siblings:
        fname = sibling.rfilename
        size = sibling.size
        if any(fname.endswith(ext) for ext in MODEL_EXTENSIONS):
            if size is not None:
                if size < MIN_MODEL_SIZE or size > MAX_MODEL_SIZE:
                    continue
            ext = os.path.splitext(fname)[1].lower()
            model_files.append({'filename': fname, 'size': size, 'extension': ext})

    if len(model_files) > MAX_FILES_PER_MODEL:
        def priority(f):
            name = f['filename']
            if any(name.endswith(ext) for ext in ['.pkl', '.pickle', '.joblib']):
                return 0
            if name == 'pytorch_model.bin' or name.endswith(('.pt', '.pth', '.th')):
                return 1
            if any(name.endswith(ext) for ext in ['.npy', '.npz', '.h5', '.keras']):
                return 2
            return 3
        model_files.sort(key=priority)
        model_files = model_files[:MAX_FILES_PER_MODEL]

    return model_files


def _build_model_entry(model_summary, model_files, siblings):
    """Build a standardized model entry dict."""
    has_safetensors = any(s.rfilename.endswith('.safetensors') for s in siblings)
    has_pickle = any(any(f['filename'].endswith(ext)
                         for ext in HIGH_RISK_EXTENSIONS) for f in model_files)

    return {
        'model_id': model_summary.id,
        'downloads': model_summary.downloads or 0,
        'likes': model_summary.likes or 0,
        'model_files': model_files,
        'total_size': sum(f['size'] for f in model_files if f['size'] is not None),
        'has_safetensors': has_safetensors,
        'has_pickle': has_pickle,
        'tags': list(model_summary.tags or [])[:5],
    }


def _compute_metadata_reasons(model_id, filenames, model_files, downloads):
    """
    Record metadata observations about a repo. Used for reporting only;
    does not affect whether the model is scanned.
    """
    has_raw_pickle = any(f.endswith(('.pkl', '.pickle')) for f in filenames)
    has_joblib = any(f.endswith('.joblib') for f in filenames)
    has_numpy = any(f.endswith(('.npy', '.npz')) for f in filenames)
    has_config = 'config.json' in filenames
    has_safetensors = any(f.endswith('.safetensors') for f in filenames)
    has_pt_bin = any(
        f in ('pytorch_model.bin', 'model.bin') or
        f.endswith(('.pt', '.pth', '.th'))
        for f in filenames
    )
    has_readme = any(f.lower() in ('readme.md', 'readme') for f in filenames)

    org = model_id.split('/')[0] if '/' in model_id else model_id
    is_official = org in _OFFICIAL_ORGS

    reasons = []

    if has_raw_pickle and not has_config and not has_safetensors:
        reasons.append('bare pickle, no config.json, no safetensors')
    elif has_raw_pickle and not has_safetensors:
        reasons.append('raw pickle without safetensors')

    if has_joblib:
        reasons.append('single joblib file' if len(model_files) == 1
                       else 'contains joblib file')

    if has_numpy and not has_pt_bin and not has_safetensors:
        reasons.append('numpy-only model (pickle inside .npy/.npz)')

    if has_pt_bin and not has_safetensors and downloads < 100:
        reasons.append(f'pickle-only from {org}, low downloads')

    name_lower = model_id.lower()
    for keyword in _POPULAR_KEYWORDS:
        if keyword in name_lower and downloads < 50:
            reasons.append(f'mimics popular model ({keyword}), only {downloads} downloads')
            break

    if downloads == 0:
        reasons.append('zero downloads')
    elif downloads < 5:
        reasons.append(f'near-zero downloads ({downloads})')
    elif downloads < 50:
        reasons.append(f'very low downloads ({downloads})')

    if not has_readme:
        reasons.append('no README.md')

    for mf in model_files:
        if mf['size'] is not None and mf['size'] < 10000:
            if any(mf['filename'].endswith(ext) for ext in HIGH_RISK_EXTENSIONS):
                reasons.append(
                    f'tiny high-risk file: {mf["filename"]} ({mf["size"]} bytes)')
                break

    pickle_count = sum(1 for f in filenames if f.endswith(('.pkl', '.pickle')))
    if pickle_count >= 2:
        reasons.append(f'{pickle_count} pickle files in repo')

    if is_official:
        reasons.append('official org')

    return reasons, is_official


# =============================================================================
# Discovery (resumable)
# =============================================================================
def _load_discovery_progress():
    """Return (found_models, checked_ids, complete) from the progress file."""
    if not os.path.exists(DISCOVERY_FILE):
        return [], set(), False
    try:
        with open(DISCOVERY_FILE) as f:
            data = json.load(f)
        return (data.get('found_models', []),
                set(data.get('checked_ids', [])),
                data.get('discovery_complete', False))
    except Exception:
        return [], set(), False


def _save_discovery_progress(found_models, checked_ids, complete=False):
    """Atomically save discovery progress via temp-file rename."""
    data = {
        'found_models': found_models,
        'checked_ids': list(checked_ids),
        'discovery_complete': complete,
        'last_saved': datetime.now().isoformat(),
        'total_found': len(found_models),
        'total_checked': len(checked_ids),
    }
    tmp = DISCOVERY_FILE + '.tmp'
    with open(tmp, 'w') as f:
        json.dump(data, f, default=str)
    os.replace(tmp, DISCOVERY_FILE)


def discover_models(num_models, already_scanned=None):
    """
    Discover up to `num_models` recently uploaded models. Resumable: state
    is persisted to DISCOVERY_FILE every 200 checks.
    """
    found_models, checked_ids, complete = _load_discovery_progress()

    if already_scanned:
        checked_ids |= already_scanned

    if complete and found_models:
        log(f"[discover] Using {len(found_models)} models from completed run")
        return found_models

    if found_models:
        log(f"[discover] Resuming: {len(found_models)} found, "
            f"{len(checked_ids)} checked")
    else:
        log(f"[discover] Scanning recently uploaded models (target: {num_models})")

    api = HfApi(token=HF_TOKEN)
    checked_count = 0
    api_errors = 0
    MAX_CHECKS = num_models * 10
    consecutive_old = 0
    models = list_models(sort="lastModified")

    for model_summary in models:
        if len(found_models) >= num_models:
            break
        if checked_count >= MAX_CHECKS:
            log(f"[discover] Hit safety cap ({MAX_CHECKS} checks), stopping")
            break

        model_id = model_summary.id
        if model_id in checked_ids:
            continue

        checked_count += 1

        if checked_count % 200 == 0:
            log(f"  Checked {checked_count}, found {len(found_models)}...")
            _save_discovery_progress(found_models, checked_ids, False)

        try:
            info = api.model_info(model_id)
            checked_ids.add(model_id)

            created_at = getattr(info, 'created_at', None)
            age_days = None
            if created_at:
                age_days = (datetime.now(timezone.utc) - created_at).days
                if age_days > MAX_AGE_DAYS:
                    consecutive_old += 1
                    if consecutive_old >= 500:
                        log(f"[discover] 500 consecutive models older than "
                            f"{MAX_AGE_DAYS} days, stopping")
                        break
                    continue
                else:
                    consecutive_old = 0

            siblings = info.siblings or []
            filenames = [s.rfilename for s in siblings]
            model_files = _extract_model_files(siblings)
            if not model_files:
                continue

            downloads = model_summary.downloads or 0
            reasons, is_official = _compute_metadata_reasons(
                model_id, filenames, model_files, downloads)

            entry = _build_model_entry(model_summary, model_files, siblings)
            entry['metadata_reasons'] = reasons
            entry['is_official'] = is_official
            if created_at:
                entry['created_at'] = created_at.isoformat()
                entry['age_days'] = age_days

            found_models.append(entry)
            time.sleep(0.35)

        except Exception as e:
            api_errors += 1
            checked_ids.add(model_id)
            if '429' in str(e):
                log("  Rate limited, sleeping 120s...")
                _save_discovery_progress(found_models, checked_ids, False)
                time.sleep(120)
            elif '401' in str(e) or '403' in str(e):
                time.sleep(1)
            else:
                time.sleep(0.5)
            continue

    _save_discovery_progress(found_models, checked_ids, True)
    log(f"[discover] Found {len(found_models)} models "
        f"(checked {checked_count}, {api_errors} errors)")
    return found_models


# =============================================================================
# Download, inspect, classify
# =============================================================================
def _hf_download_worker(q, kwargs):
    try:
        q.put(('ok', hf_hub_download(**kwargs)))
    except Exception as e:
        q.put(('err', str(e)))


def _hf_download_with_timeout(timeout=DOWNLOAD_TIMEOUT, **kwargs):
    q = multiprocessing.Queue()
    p = multiprocessing.Process(target=_hf_download_worker, args=(q, kwargs))
    p.start()
    p.join(timeout)

    if p.is_alive():
        p.terminate()
        p.join(5)
        if p.is_alive():
            p.kill()
            p.join()
        raise FuturesTimeoutError(f"download exceeded {timeout}s")

    try:
        status, payload = q.get(timeout=10)
    except queue.Empty:
        raise RuntimeError("download worker died without result")

    if status == 'err':
        raise RuntimeError(payload)
    return payload


def download_model(model_id, model_files):
    """Download model files and auxiliary config/tokenizer files."""
    try:
        if os.path.exists(MODEL_TEMP_DIR):
            shutil.rmtree(MODEL_TEMP_DIR)
        os.makedirs(MODEL_TEMP_DIR, exist_ok=True)

        downloaded = []
        for mf in model_files:
            filename = mf['filename']
            try:
                url = hf_hub_url(repo_id=model_id, filename=filename)
                metadata = get_hf_file_metadata(url, token=HF_TOKEN)
                remote_size = metadata.size

                if remote_size is not None and remote_size > MAX_MODEL_SIZE:
                    log(f"    Skipping {filename}: "
                        f"{remote_size / (1024*1024):.1f} MB exceeds limit")
                    continue

                path = _hf_download_with_timeout(
                    repo_id=model_id, filename=filename,
                    local_dir=MODEL_TEMP_DIR,
                    token=HF_TOKEN,
                )
                downloaded.append({
                    'filename': filename, 'path': path,
                    'size': os.path.getsize(path),
                })
            except FuturesTimeoutError:
                log(f"    Skipping {filename}: download timed out after {DOWNLOAD_TIMEOUT}s")
            except Exception as e:
                log(f"    Skipping {filename}: {e}")

        for aux in ['config.json', 'tokenizer.json', 'tokenizer_config.json',
                    'vocab.txt', 'special_tokens_map.json']:
            try:
                _hf_download_with_timeout(
                    repo_id=model_id, filename=aux,
                    local_dir=MODEL_TEMP_DIR,
                    token=HF_TOKEN,
                )
            except Exception:
                pass

        return downloaded
    except Exception as e:
        log(f"  Download failed: {e}")
        return []


def run_inspector(model_dir, model_entry=None):
    """Run the inspector under the environment selected for this model."""
    if model_entry is None:
        env_name, py_bin = 'torch_current', POOL['torch_current']
    else:
        env_name, py_bin = select(model_entry)

    log(f"    Routed to env: {env_name}")

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
            timeout=CLASSIFIER_TIMEOUT,
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
    """Full pipeline for one model: download -> inspect -> classify."""
    model_id = model_info['model_id']
    model_files = model_info['model_files']
    total_size_mb = model_info['total_size'] / (1024 * 1024)
    file_types = [os.path.splitext(f['filename'])[1] for f in model_files]

    log(f"\n[{index}/{total}] {model_id}")
    log(f"  Files: {len(model_files)} ({total_size_mb:.1f} MB) — types: {file_types}")
    log(f"  Downloads: {model_info['downloads']}, "
        f"SafeTensors: {model_info.get('has_safetensors')}, "
        f"Pickle: {model_info.get('has_pickle')}")
    if model_info.get('metadata_reasons'):
        log(f"  Metadata: {', '.join(model_info['metadata_reasons'][:5])}")

    result = {
        'model_id': model_id,
        'model_files': [f['filename'] for f in model_files],
        'file_types': file_types,
        'total_size': model_info['total_size'],
        'downloads': model_info['downloads'],
        'likes': model_info['likes'],
        'has_safetensors': model_info.get('has_safetensors'),
        'has_pickle': model_info.get('has_pickle'),
        'tags': model_info.get('tags', []),
        'metadata_reasons': model_info.get('metadata_reasons', []),
        'is_official': model_info.get('is_official'),
        'timestamp': datetime.now().isoformat(),
        'status': 'pending',
    }

    try:
        env_name_pre, _ = select(model_info)
        result['routed_env'] = env_name_pre
    except Exception as e:
        result['routed_env'] = 'routing_failed'
        log(f"  Routing failed: {e}")

    start_time = time.time()

    # Step 1: download
    log(f"  Downloading {len(model_files)} file(s)...")
    downloaded = download_model(model_id, model_files)
    if not downloaded:
        result['status'] = 'download_failed'
        cleanup_model()
        return result

    download_time = time.time() - start_time
    result['downloaded_files'] = [d['filename'] for d in downloaded]
    log(f"  Downloaded {len(downloaded)} file(s) in {download_time:.1f}s")

    # Step 2: inspect
    log(f"  Running eBPF inspector (loading + execution)...")
    inspector_start = time.time()
    inspector_ok, env_name, inspector_stderr = run_inspector(MODEL_TEMP_DIR, model_info)
    result['routed_env'] = env_name
    inspector_time = time.time() - inspector_start
    log(f"  Inspector finished in {inspector_time:.1f}s")

    if not inspector_ok:
        reason = (inspector_stderr or 'unknown')[:500]
        log(f"  Inspector FAILED ({env_name}): {reason[:300]}")
        events_dir_check = None
        for root, dirs, _ in os.walk(MODEL_TEMP_DIR):
            if 'events' in dirs:
                events_dir_check = os.path.join(root, 'events')
                break
        if events_dir_check and any(f.endswith('.json') for f in os.listdir(events_dir_check)):
            log(f"  Events found despite inspector failure -- continuing to classify")
        else:
            result['status'] = 'inspector_failed'
            result['inspector_error'] = reason
            result['inspector_time'] = inspector_time
            result['download_time'] = download_time
            cleanup_model()
            return result

    # Step 3: locate events directory
    events_dir = None
    for root, dirs, _ in os.walk(MODEL_TEMP_DIR):
        if 'events' in dirs:
            events_dir = os.path.join(root, 'events')
            break

    if not events_dir or not os.path.isdir(events_dir):
        log(f"  No events directory found after inspector run")
        result['status'] = 'no_events'
        result['inspector_time'] = inspector_time
        result['download_time'] = download_time
        cleanup_model()
        return result

    # Step 4: classify
    log(f"  Running classifier...")
    safe_name = model_id.replace('/', '_')
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
    result['download_time'] = download_time
    result['total_time'] = time.time() - start_time

    # Archive traces
    try:
        global _trace_counter
        _trace_counter += 1
        padded = f"{_trace_counter:05d}"
        folder_name = safe_name

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

    # Extra copy for malicious verdicts
    if classifier_result['verdict'] == 'MALICIOUS':
        malicious_dir = os.path.join(RESULTS_DIR, 'malicious')
        os.makedirs(malicious_dir, exist_ok=True)

        malicious_verdict = os.path.join(malicious_dir,
                                         f'{safe_name}_verdict.json')
        if classifier_result.get('raw_verdict'):
            with open(malicious_verdict, 'w') as f:
                json.dump(classifier_result['raw_verdict'], f,
                          indent=2, default=str)

        events_save_dir = os.path.join(malicious_dir, f'{safe_name}_events')
        if os.path.exists(events_dir):
            shutil.copytree(events_dir, events_save_dir, dirs_exist_ok=True)
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
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    path = os.path.join(SCAN_DIR, f'results_{timestamp}.json')
    for p in [path, os.path.join(SCAN_DIR, 'results.json')]:
        tmp = p + '.tmp'
        with open(tmp, 'w') as f:
            json.dump(all_results, f, indent=2, default=str)
        os.replace(tmp, p)


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
        'platform': 'huggingface',
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
                metadata = ', '.join(r.get('metadata_reasons', [])[:3])
                log(f"  {r['model_id']} — "
                    f"types={r.get('file_types', [])}, patterns: {patterns}"
                    f"{f', metadata: {metadata}' if metadata else ''}")

    log(f"\nResults saved to: {SCAN_DIR}")
    log(f"Malicious evidence: {RESULTS_DIR}/malicious/")


# =============================================================================
# Main
# =============================================================================
def main():
    if HF_TOKEN == "paste_your_token_here":
        print("ERROR: Set your HuggingFace API token in HF_TOKEN at the top of this script.")
        print("       Get one at https://huggingface.co/settings/tokens")
        sys.exit(1)

    try:
        validate_pool()
    except RuntimeError as e:
        log(f"FATAL: {e}")
        log("Run the sandbox builder (build_env_pool.sh) first.")
        sys.exit(1)

    parser = argparse.ArgumentParser(
        description='HuggingFace model scan pipeline')
    parser.add_argument('--num-models', type=int, default=500,
                        help='Number of models to scan per cycle (default: 500)')
    parser.add_argument('--resume', action='store_true',
                        help='Resume an interrupted scan')
    parser.add_argument('--reset-discovery', action='store_true',
                        help='Force restart discovery from scratch')
    parser.add_argument('--poll-interval', type=int, default=1800,
                        help='Seconds between scan cycles (default: 1800 = 30min)')
    args = parser.parse_args()

    os.makedirs(SCAN_DIR, exist_ok=True)
    os.makedirs(RESULTS_DIR, exist_ok=True)
    os.makedirs(TRACES_DIR, exist_ok=True)
    _init_trace_counter()

    if args.reset_discovery and os.path.exists(DISCOVERY_FILE):
        os.remove(DISCOVERY_FILE)
        log("Discovery progress reset.")

    log(f"{'='*70}")
    log(f"HuggingFace Model Scan Pipeline")
    log(f"Target:     {args.num_models} models per cycle")
    log(f"File types: {len(MODEL_EXTENSIONS)} extensions supported")
    log(f"Work dir:   {SCAN_DIR}")
    log(f"Inspector:  {INSPECTOR_PATH}")
    log(f"Classifier: {CLASSIFIER_PATH}")
    log(f"Traces:     {TRACES_DIR}")
    log(f"{'='*70}")

    batch_size = args.num_models
    poll_interval = args.poll_interval
    cycle = 0

    while True:
        cycle += 1
        log(f"\n{'='*70}")
        log(f"CYCLE {cycle} — scanning up to {batch_size} recent models")
        log(f"{'='*70}")

        already_scanned = get_already_scanned()
        log(f"Already scanned: {len(already_scanned)} models")

        if os.path.exists(DISCOVERY_FILE):
            os.remove(DISCOVERY_FILE)

        models = discover_models(num_models=batch_size,
                                 already_scanned=already_scanned)

        if models:
            results = run_scan(models, resume=False)
            print_summary(results)
        else:
            log("No new models found this cycle.")

        log(f"Sleeping {poll_interval}s until next cycle...")
        try:
            time.sleep(poll_interval)
        except KeyboardInterrupt:
            log("Interrupted during sleep. Exiting.")
            break


if __name__ == '__main__':
    main()