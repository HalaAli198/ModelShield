"""
hf_scan.py

Scans recent HuggingFace model uploads across all supported formats
(pickle, safetensors, ONNX, Keras, TF, etc.) during both LOADING and
EXECUTION phases.

Discovery is resumable: progress is saved to discovery_progress.json
and the scan can be interrupted and resumed at any point.


Usage:
    sudo bash -c "ulimit -u unlimited && ulimit -l unlimited && \\
    python3.9 hf_scan.py --num-models 30000"
"""

import os
import sys
import json
import time
import shutil
import argparse
import subprocess
from datetime import datetime, timezone

from env_selector import select, validate_matrix, MATRIX
from huggingface_hub import HfApi, hf_hub_download, list_models, hf_hub_url, get_hf_file_metadata

# Get a token at https://huggingface.co/settings/tokens
HF_TOKEN = "hf_your_token_here"

# =============================================================================
# Configuration
# =============================================================================
WORK_DIR = '/path/to/hf_scan'
RESULTS_DIR = os.path.join(WORK_DIR, 'hf_results')
LOG_FILE = os.path.join(WORK_DIR, 'scan_log.txt')
MODEL_TEMP_DIR = os.path.join(WORK_DIR, 'temp_model')
DISCOVERY_FILE = os.path.join(WORK_DIR, 'discovery_progress.json')

INSPECTOR_PATH = '/path/to/model_inspector_runner.py'
CLASSIFIER_PATH = '/path/to/attack_behavior_classifier.py'
TRACES_DIR = '/path/to/captured_events'

# File extensions the pipeline inspects. 
MODEL_EXTENSIONS = [
    '.pkl', '.pickle', '.joblib',
    '.bin', '.pt', '.pth', '.th',
    '.safetensors',
    '.h5', '.keras', '.pb', '.tflite',
    '.onnx',
    '.msgpack',
    '.xgb', '.bst', '.ubj', '.lgb', '.cbm',
    '.npy', '.npz',
    '.mlmodel',
    '.params',
    '.pdmodel', '.pdiparams',
]

# Extensions that deserialize arbitrary Python objects on load.
HIGH_RISK_EXTENSIONS = ['.pkl', '.pickle', '.joblib', '.bin', '.pt', '.pth',
                        '.th', '.npy', '.npz']

# Per-file size limits. Files outside this range are skipped during discovery.
MAX_MODEL_SIZE = 5 * 1024 * 1024 * 1024
MIN_MODEL_SIZE = 100

# Subprocess timeouts, in seconds.
INSPECTOR_TIMEOUT = 300
CLASSIFIER_TIMEOUT = 300

# Upper bound on files inspected per repo; keeps runtime predictable on
# multi-checkpoint repositories.
MAX_FILES_PER_MODEL = 10

# Only scan models uploaded within this many days. Tracks the "recently
# uploaded" scope of the scan.
MAX_AGE_DAYS = 10

# Orgs treated as known-legitimate when computing metadata reasons.
# Recorded for reporting; does not affect scan decisions.
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


# Monotonic counter used to prefix archived trace folders.
_trace_counter = 0


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
            model_files.append({'filename': fname, 'size': size})

    # Repos with many checkpoints: keep the files most likely to exercise
    # code paths we care about (pickle first, pytorch second, etc.).
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
    Record metadata observations about a repo (bare pickle, missing README,
    typosquat name, etc.). Used for reporting only; does not affect whether
    the model is scanned.
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


def discover_models(num_models):
    """
    Discover up to `num_models` recently uploaded models. Resumable: state
    is persisted to DISCOVERY_FILE every 200 checks and on rate-limit
    sleeps, so an interrupted run picks up where it left off.
    """
    found_models, checked_ids, complete = _load_discovery_progress()
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
    models = list_models(sort="lastModified", direction=-1, limit=num_models)

    for model_summary in models:
        if len(found_models) >= num_models:
            break

        model_id = model_summary.id
        if model_id in checked_ids:
            continue

        checked_count += 1
        if checked_count % 200 == 0:
            log(f"  Checked {checked_count}, found {len(found_models)}...")
            _save_discovery_progress(found_models, checked_ids, False)

        downloads = model_summary.downloads or 0

        try:
            info = api.model_info(model_id)
            # Mark as checked before any filter below so a resume never
            # re-hits this model, whether it's kept or discarded.
            checked_ids.add(model_id)

            created_at = getattr(info, 'created_at', None)
            age_days = None
            if created_at:
                age_days = (datetime.now(timezone.utc) - created_at).days
                if age_days > MAX_AGE_DAYS:
                    continue

            siblings = info.siblings or []
            filenames = [s.rfilename for s in siblings]
            model_files = _extract_model_files(siblings)
            if not model_files:
                continue

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
            checked_ids.add(model_id)  # don't retry the same failure
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
                # Check remote size before downloading; some repos list a
                # small size but actually serve a much larger file.
                url = hf_hub_url(repo_id=model_id, filename=filename)
                metadata = get_hf_file_metadata(url, token=HF_TOKEN)
                remote_size = metadata.size

                if remote_size is not None and remote_size > MAX_MODEL_SIZE:
                    log(f"    Skipping {filename}: "
                        f"{remote_size / (1024*1024):.1f} MB exceeds limit")
                    continue

                path = hf_hub_download(
                    repo_id=model_id, filename=filename,
                    local_dir=MODEL_TEMP_DIR, local_dir_use_symlinks=False,
                    token=HF_TOKEN,
                )
                downloaded.append({
                    'filename': filename, 'path': path,
                    'size': os.path.getsize(path),
                })
            except Exception as e:
                log(f"    Skipping {filename}: {e}")

        # Auxiliary files. Missing ones are normal; the inspector tolerates
        # their absence but benefits from them when present (tokenizer
        # availability affects the execution phase).
        for aux in ['config.json', 'tokenizer.json', 'tokenizer_config.json',
                    'vocab.txt', 'special_tokens_map.json']:
            try:
                hf_hub_download(
                    repo_id=model_id, filename=aux,
                    local_dir=MODEL_TEMP_DIR, local_dir_use_symlinks=False,
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
        env_name, py_bin = 'torch_current', MATRIX['torch_current']
    else:
        env_name, py_bin = select(model_entry)

    log(f"    Routed to env: {env_name}")

    # ulimit -u / -l raised so the inspector's eBPF programs can lock
    # their maps and spawn worker threads without hitting kernel limits.
    cmd = (
        f"ulimit -u unlimited && ulimit -l unlimited && "
        f"{py_bin} {INSPECTOR_PATH} {model_dir}"
    )
    try:
        result = subprocess.run(
            ['bash', '-c', cmd],
            capture_output=True, text=True,
            timeout=INSPECTOR_TIMEOUT,
        )
        return result.returncode == 0, env_name
    except subprocess.TimeoutExpired:
        return False, env_name


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

            # Flatten matched pattern IDs from all behaviors, de-duplicated
            # while preserving insertion order for readable log output.
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

    # Record the routed env name up front so it's present in the result
    # even if the inspector later fails.
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

    # Step 2: inspect (loading + execution phases)
    log(f"  Running eBPF inspector (loading + execution)...")
    inspector_start = time.time()
    inspector_ok, env_name = run_inspector(MODEL_TEMP_DIR, model_info)
    result['routed_env'] = env_name
    inspector_time = time.time() - inspector_start
    log(f"  Inspector finished in {inspector_time:.1f}s")

    if not inspector_ok:
        result['status'] = 'inspector_failed'
        result['inspector_time'] = inspector_time
        result['download_time'] = download_time
        cleanup_model()
        return result

    # Step 3: locate the events directory the inspector wrote.
    # Its exact location varies by model layout; first 'events' dir wins.
    events_dir = None
    for root, dirs, _ in os.walk(MODEL_TEMP_DIR):
        if 'events' in dirs:
            events_dir = os.path.join(root, 'events')
            break

    if not events_dir or not os.path.isdir(events_dir):
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
            for event_file in os.listdir(events_dir):
                if event_file.endswith('.json'):
                    src = os.path.join(events_dir, event_file)
                    if 'loading' in event_file.lower():
                        dst_name = f"{padded}_{safe_name}_loading_events.json"
                    elif 'execution' in event_file.lower():
                        dst_name = f"{padded}_{safe_name}_execution_events.json"
                    else:
                        dst_name = f"{padded}_{safe_name}_{event_file}"
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

    # Second copy of evidence for malicious verdicts, under WORK_DIR, so
    # reports don't depend on TRACES_DIR being mounted.
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
def save_progress(all_results, summary):
    """Write per-run results and summary to WORK_DIR."""
    with open(os.path.join(WORK_DIR, 'results.json'), 'w') as f:
        json.dump(all_results, f, indent=2, default=str)
    with open(os.path.join(WORK_DIR, 'summary.json'), 'w') as f:
        json.dump(summary, f, indent=2, default=str)


def run_scan(models, resume=False):
    """Run the scan phase over a list of discovered models."""
    total = len(models)
    if total == 0:
        log("No models to evaluate")
        return []

    log(f"\n{'='*70}\nEvaluating {total} models\n{'='*70}")

    with open(os.path.join(WORK_DIR, 'model_list.json'), 'w') as f:
        json.dump(models, f, indent=2, default=str)

    all_results = []
    completed_ids = set()

    # On --resume, reload prior results and skip models whose model_id
    # already has an entry.
    if resume:
        results_path = os.path.join(WORK_DIR, 'results.json')
        if os.path.exists(results_path):
            with open(results_path) as f:
                all_results = json.load(f)
            completed_ids = {r['model_id'] for r in all_results}
            log(f"  Resuming: {len(completed_ids)} already completed")

    summary = {
        'total_models': total,
        'completed': len(completed_ids),
        'benign': 0, 'malicious': 0, 'errors': 0,
        'start_time': datetime.now().isoformat(),
    }
    for r in all_results:
        v = r.get('verdict', '')
        if v == 'BENIGN':
            summary['benign'] += 1
        elif v == 'MALICIOUS':
            summary['malicious'] += 1
        else:
            summary['errors'] += 1

    for i, model_info in enumerate(models, 1):
        if model_info['model_id'] in completed_ids:
            continue

        try:
            result = evaluate_model(model_info, i, total)
            all_results.append(result)
            summary['completed'] = len(all_results)

            v = result.get('verdict', '')
            if v == 'BENIGN':
                summary['benign'] += 1
            elif v == 'MALICIOUS':
                summary['malicious'] += 1
            else:
                summary['errors'] += 1

            # Checkpoint every 5 models so an interrupted run loses little.
            if len(all_results) % 5 == 0:
                save_progress(all_results, summary)
                log(f"\n  --- Progress: {summary['completed']}/{total} | "
                    f"Benign: {summary['benign']} | "
                    f"Malicious: {summary['malicious']} | "
                    f"Errors: {summary['errors']} ---\n")

        except KeyboardInterrupt:
            log(f"\n\nInterrupted. Saving progress...")
            save_progress(all_results, summary)
            cleanup_model()
            break
        except Exception as e:
            log(f"  ERROR: {e}")
            all_results.append({
                'model_id': model_info['model_id'],
                'status': 'error', 'error': str(e),
            })
            summary['errors'] += 1
            cleanup_model()

    summary['end_time'] = datetime.now().isoformat()
    save_progress(all_results, summary)
    return all_results


def print_summary(results):
    """Log verdict counts, file-type breakdown, and the list of malicious IDs."""
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

    log(f"\nResults saved to: {WORK_DIR}")
    log(f"Malicious evidence: {RESULTS_DIR}/malicious/")


# =============================================================================
# Main
# =============================================================================
def main():
    # Sandbox pool must be built before any scanning happens; without it
    # the routed interpreter path won't exist.
    try:
        validate_matrix()
    except RuntimeError as e:
        log(f"FATAL: {e}")
        log("Run the sandbox builder (build_env_pool.sh) first.")
        sys.exit(1)

    parser = argparse.ArgumentParser(
        description='HuggingFace model scan pipeline')
    parser.add_argument('--num-models', type=int, default=30000,
                        help='Number of models to scan (default: 30000)')
    parser.add_argument('--resume', action='store_true',
                        help='Resume an interrupted scan')
    parser.add_argument('--reset-discovery', action='store_true',
                        help='Force restart discovery from scratch')
    parser.add_argument('--skip-discovery', action='store_true',
                        help='Use existing model_list.json, skip discovery')
    args = parser.parse_args()

    os.makedirs(WORK_DIR, exist_ok=True)
    os.makedirs(RESULTS_DIR, exist_ok=True)

    if args.reset_discovery and os.path.exists(DISCOVERY_FILE):
        os.remove(DISCOVERY_FILE)
        log("Discovery progress reset.")

    log(f"{'='*70}")
    log(f"HuggingFace Model Scan Pipeline")
    log(f"Target:     {args.num_models} models")
    log(f"File types: {len(MODEL_EXTENSIONS)} extensions supported")
    log(f"Work dir:   {WORK_DIR}")
    log(f"Inspector:  {INSPECTOR_PATH}")
    log(f"Classifier: {CLASSIFIER_PATH}")
    log(f"Traces:     {TRACES_DIR}")
    log(f"{'='*70}")

    list_path = os.path.join(WORK_DIR, 'model_list.json')
    if args.skip_discovery and os.path.exists(list_path):
        with open(list_path) as f:
            models = json.load(f)
        log(f"Loaded {len(models)} models from {list_path}")
    else:
        models = discover_models(num_models=args.num_models)

    results = run_scan(models, resume=args.resume)
    print_summary(results)


if __name__ == '__main__':
    main()