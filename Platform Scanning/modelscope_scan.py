"""
modelscope_scan.py

Scans recent ModelScope model uploads across all supported formats
(pickle, safetensors, ONNX, Keras, TF, etc.) during both LOADING and
EXECUTION phases.

Discovery is resumable: progress is saved to discovery_progress.json
and the scan can be interrupted and resumed at any point.

Usage:
    sudo bash -c "ulimit -u unlimited && ulimit -l unlimited && \\
    python3.9 modelscope_scan.py --num-models 5000"
"""

import os
import sys
import json
import time
import shutil
import subprocess
import argparse
import requests
from datetime import datetime

# =============================================================================
# Configuration
# =============================================================================
SCAN_DIR       = '/path/to/modelscope_scan'
RESULTS_DIR    = os.path.join(SCAN_DIR, 'scan_results')
LOG_FILE       = os.path.join(SCAN_DIR, 'scan_log.txt')
MODEL_TEMP_DIR = os.path.join(SCAN_DIR, 'temp_model')
DISCOVERY_FILE = os.path.join(SCAN_DIR, 'discovery_progress.json')

INSPECTOR_PATH  = '/path/to/model_inspector_runner.py'
CLASSIFIER_PATH = '/path/to/attack_behavior_classifier.py'

# ModelScope exposes both a REST API and a Python SDK. We use REST for
# platform-wide listing (the SDK has no listing endpoint) and the SDK
# as a download fallback when the direct URL methods fail.
MS_API_BASE      = 'https://modelscope.cn/api/v1'
MS_DOWNLOAD_BASE = 'https://modelscope.cn/models'

# Every extension the pipeline will download and inspect.
MODEL_EXTENSIONS = [
    '.pkl', '.pickle', '.joblib',
    '.bin', '.pt', '.pth', '.th',
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
    '.bin', '.pt', '.pth', '.th',
    '.npy', '.npz',
]

# Per-file size limits. Files outside this range are skipped during discovery.
MAX_DOWNLOAD_SIZE = 3 * 1024 * 1024 * 1024
MIN_MODEL_SIZE    = 1000

# Subprocess timeouts, in seconds.
INSPECTOR_TIMEOUT  = 300
CLASSIFIER_TIMEOUT = 60

# Upper bound on files inspected per repo.
MAX_FILES_PER_MODEL = 10

# Only scan models uploaded within this many days. ModelScope uses a longer
# window than Hugging Face because its upload rate is lower.
MAX_AGE_DAYS = 30

# Orgs treated as known-legitimate when computing metadata reasons.
# Used for reporting only; does not affect whether a model is scanned.
_OFFICIAL_ORGS = {
    'damo', 'modelscope', 'AI-ModelScope', 'iic',
    'ZhipuAI', 'qwen', 'Qwen', 'THUDM', 'baichuan-inc',
    'deepseek-ai', 'internlm', 'OpenBMB', 'IDEA-CCNL',
    'TongyiFinance', 'codefuse-ai', 'langboat',
    'shanghai_ai_laboratory', 'FlagAlpha',
}

# Names frequently seen in typosquatted repositories.
_POPULAR_KEYWORDS = [
    'llama', 'gpt', 'mistral', 'gemma', 'phi', 'qwen',
    'stable-diffusion', 'whisper', 'bert', 'roberta',
    'clip', 'deepseek', 'falcon', 'vicuna', 'alpaca',
    'codellama', 'starcoder', 'yi-', 'baichuan', 'chatglm',
    'glm', 'internlm', 'bloom', 'opt-', 'moss',
]


def log(msg):
    ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    line = f"[{ts}] {msg}"
    print(line, flush=True)
    try:
        with open(LOG_FILE, 'a') as f:
            f.write(line + '\n')
    except Exception:
        pass


# =============================================================================
# Discovery progress
# =============================================================================
def load_discovery_progress():
    """Return (found_models, checked_ids, complete, page) from the progress file."""
    if os.path.exists(DISCOVERY_FILE):
        try:
            with open(DISCOVERY_FILE) as f:
                data = json.load(f)
            return (
                data.get('found_models', []),
                set(data.get('checked_ids', [])),
                data.get('discovery_complete', False),
                data.get('page', 1),
            )
        except Exception:
            pass
    return [], set(), False, 1


def save_discovery_progress(found, checked_ids, complete=False, page=1):
    """Atomically save discovery progress via temp-file rename."""
    data = {
        'found_models': found,
        'checked_ids': list(checked_ids),
        'discovery_complete': complete,
        'page': page,
        'last_saved': datetime.now().isoformat(),
        'total_found': len(found),
    }
    tmp = DISCOVERY_FILE + '.tmp'
    with open(tmp, 'w') as f:
        json.dump(data, f, default=str)
    os.replace(tmp, DISCOVERY_FILE)


# =============================================================================
# File extraction
# =============================================================================
def extract_model_files(file_list):
    """Extract all model files from a ModelScope file listing."""
    model_files = []

    for f in file_list:
        fname = f.get('Path', '') or f.get('Name', '') or f.get('name', '') or ''
        fsize = f.get('Size', 0) or f.get('size', 0) or 0
        ftype = f.get('Type', '') or f.get('type', '')

        if ftype in ('tree', 'dir', 'directory'):
            continue

        ext = os.path.splitext(fname)[1].lower()

        if ext in MODEL_EXTENSIONS:
            if fsize and fsize < MIN_MODEL_SIZE:
                continue
            if fsize and fsize > MAX_DOWNLOAD_SIZE:
                continue
            model_files.append({
                'filename': fname,
                'size': fsize,
                'extension': ext,
            })

    # Repos with many checkpoints: keep the files most likely to exercise
    # code paths we care about (pickle first, pytorch second, etc.).
    if len(model_files) > MAX_FILES_PER_MODEL:
        def priority(mf):
            name = mf['filename']
            if any(name.endswith(ext) for ext in ['.pkl', '.pickle', '.joblib']):
                return 0
            if any(name.endswith(ext) for ext in ['.bin', '.pt', '.pth', '.th']):
                return 1
            if any(name.endswith(ext) for ext in ['.npy', '.npz', '.h5', '.keras']):
                return 2
            if any(name.endswith(ext) for ext in ['.onnx', '.pb', '.msgpack']):
                return 3
            return 4
        model_files.sort(key=priority)
        model_files = model_files[:MAX_FILES_PER_MODEL]

    return model_files


def compute_metadata_reasons(model_id, model_files, all_filenames, downloads):
    """
    Record metadata observations about a repo (bare pickle, missing README,
    typosquat name, etc.). Used for reporting only; does not affect whether
    the model is scanned.
    """
    reasons = []

    has_raw_pickle = any(f.endswith(('.pkl', '.pickle')) for f in all_filenames)
    has_joblib = any(f.endswith('.joblib') for f in all_filenames)
    has_numpy = any(f.endswith(('.npy', '.npz')) for f in all_filenames)
    has_config = any(f in ('config.json', 'configuration.json') for f in all_filenames)
    has_safetensors = any(f.endswith('.safetensors') for f in all_filenames)
    has_pt_bin = any(
        f in ('pytorch_model.bin', 'model.bin') or f.endswith(('.pt', '.pth', '.th'))
        for f in all_filenames
    )
    has_readme = any(f.lower() in ('readme.md', 'readme', 'readme.txt')
                     for f in all_filenames)

    org = model_id.split('/')[0] if '/' in model_id else model_id
    is_official = org in _OFFICIAL_ORGS

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
        if mf['size'] and mf['size'] < 10000:
            if mf['extension'] in HIGH_RISK_EXTENSIONS:
                reasons.append(
                    f'tiny high-risk file: {mf["filename"]} ({mf["size"]} bytes)')
                break

    pickle_count = sum(1 for f in all_filenames if f.endswith(('.pkl', '.pickle')))
    if pickle_count >= 2:
        reasons.append(f'{pickle_count} pickle files in repo')

    if not has_safetensors and any(mf['extension'] in HIGH_RISK_EXTENSIONS
                                   for mf in model_files):
        reasons.append('no safetensors alternative')

    if is_official:
        reasons.append('official org')

    return reasons, is_official


# =============================================================================
# Discovery (resumable)
# =============================================================================
def discover_models(num_models):
    """
    Discover up to `num_models` recently uploaded models via ModelScope's
    REST listing endpoint. Resumable: state is persisted to DISCOVERY_FILE
    after every page and on rate-limit sleeps.
    """
    prev_found, prev_checked, discovery_complete, start_page = load_discovery_progress()

    if discovery_complete and prev_found:
        log(f"[discover] Using {len(prev_found)} models from completed run")
        return prev_found

    found = list(prev_found)
    found_ids = {m.get('ms_model_id', '') for m in found}
    checked_ids = set(prev_checked)

    if found:
        log(f"[discover] Resuming: {len(found)} found, "
            f"{len(checked_ids)} checked, starting at page {start_page}")
    else:
        log(f"[discover] Scanning recently uploaded models (target: {num_models})")
    log(f"[discover] Age filter: <={MAX_AGE_DAYS} days old")

    # Requires: pip install modelscope
    from modelscope.hub.api import HubApi
    api = HubApi()

    now_sec = time.time()
    page_size = 50
    page_num = max(start_page, 1)
    total_checked = len(checked_ids)
    api_errors = 0

    while len(found) < num_models:
        try:
            resp = requests.put(
                f'{MS_API_BASE}/models',
                headers={'Content-Type': 'application/json'},
                json={
                    'PageNumber': page_num,
                    'PageSize': page_size,
                    'SortBy': 'gmt_modified',
                },
                timeout=30,
            )

            if resp.status_code != 200:
                log(f"  Page {page_num}: HTTP {resp.status_code}")
                api_errors += 1
                if api_errors > 10:
                    break
                time.sleep(2)
                page_num += 1
                continue

            data = resp.json()
            if data.get('Code') != 200:
                log(f"  Page {page_num}: API code {data.get('Code')}")
                break

            items = (data.get('Data') or {}).get('Models') or []
            if not items:
                log(f"  Page {page_num}: no more models")
                break

            log(f"  Page {page_num}: {len(items)} models (found so far: {len(found)})")

            for model in items:
                if len(found) >= num_models:
                    break

                total_checked += 1

                org_path = model.get('Path', '')
                model_name = model.get('Name', '')
                if not (org_path and model_name):
                    continue
                model_id = f'{org_path}/{model_name}'

                # Prefix the ID with the platform name so ModelScope and
                # Hugging Face results can be pooled into a single corpus
                # without collisions.
                full_id = f'modelscope_{model_id}'
                if full_id in checked_ids or model_id in found_ids:
                    continue
                checked_ids.add(full_id)

                created_sec = model.get('CreatedTime') or 0
                if created_sec:
                    age_days = (now_sec - created_sec) / 86400
                    if age_days > MAX_AGE_DAYS:
                        continue
                else:
                    age_days = None

                # The REST listing doesn't include the file manifest, so
                # fetch it per-model via the SDK.
                try:
                    file_list = api.get_model_files(model_id=model_id, recursive=True)
                    if not file_list:
                        continue

                    all_filenames = []
                    for f in file_list:
                        fn = f.get('Name', '') or f.get('Path', '') or ''
                        if fn:
                            all_filenames.append(fn)

                    model_files = extract_model_files(file_list)
                    if not model_files:
                        continue

                    downloads = model.get('Downloads', 0) or 0
                    creator = model.get('CreatedBy', '') or org_path
                    display_name = model.get('ChineseName', '') or model_name

                    metadata_reasons, is_official = compute_metadata_reasons(
                        model_id, model_files, all_filenames, downloads)

                    entry = {
                        'model_id': full_id,
                        'ms_model_id': model_id,
                        'platform': 'modelscope',
                        'name': display_name,
                        'creator': creator,
                        'downloads': downloads,
                        'created_time': created_sec,
                        'age_days': age_days,
                        'model_files': model_files,
                        'total_size': sum(mf['size'] for mf in model_files if mf['size']),
                        'has_safetensors': any(f.endswith('.safetensors')
                                               for f in all_filenames),
                        'has_pickle': any(mf['extension'] in HIGH_RISK_EXTENSIONS
                                          for mf in model_files),
                        'metadata_reasons': metadata_reasons,
                        'is_official': is_official,
                    }
                    found.append(entry)
                    found_ids.add(model_id)

                    log(f"    found: {model_id} (age {age_days:.1f}d) — "
                        f"{[mf['extension'] for mf in model_files]}")

                except Exception as e:
                    if '429' in str(e) or 'rate' in str(e).lower():
                        log(f"    Rate limited on get_model_files, sleeping 60s")
                        save_discovery_progress(found, checked_ids, False, page_num)
                        time.sleep(60)
                    else:
                        log(f"    Error on {model_id}: {e}")
                    api_errors += 1

                time.sleep(0.3)

            # Save progress after every page.
            save_discovery_progress(found, checked_ids, False, page_num)
            page_num += 1
            time.sleep(0.5)

        except KeyboardInterrupt:
            log("\n  Discovery interrupted. Saving progress...")
            save_discovery_progress(found, checked_ids, False, page_num)
            return found
        except Exception as e:
            log(f"  Page {page_num} error: {e}")
            api_errors += 1
            if api_errors > 20:
                break
            time.sleep(2)
            page_num += 1

    discovery_ok = (len(found) >= num_models)
    save_discovery_progress(found, checked_ids, discovery_ok, page_num)

    log(f"\n[discover] {'complete' if discovery_ok else 'incomplete (will resume next run)'}:")
    log(f"  Pages scanned: {page_num}")
    log(f"  Models checked: {total_checked}")
    log(f"  Found with model files: {len(found)}")
    log(f"  API errors: {api_errors}")
    return found


# =============================================================================
# Download, inspect, classify
# =============================================================================
def download_model(entry):
    """Download model files from ModelScope using a three-method fallback chain."""
    try:
        if os.path.exists(MODEL_TEMP_DIR):
            shutil.rmtree(MODEL_TEMP_DIR)
        os.makedirs(MODEL_TEMP_DIR, exist_ok=True)

        model_id = entry['ms_model_id']
        downloaded = []

        token = os.environ.get('MODELSCOPE_SDK_TOKEN', '')
        headers = {}
        if token:
            headers['Authorization'] = f'Bearer {token}'

        # ModelScope's CDN serves the same file through multiple paths with
        # slightly different availability. Try the direct resolve URL first,
        # fall back to the REST API, then to the SDK. Each method covers
        # cases the others don't.
        for rf in entry.get('model_files', [])[:MAX_FILES_PER_MODEL]:
            fname = rf['filename']
            fpath = os.path.join(MODEL_TEMP_DIR, os.path.basename(fname))

            success = False
            method1_status = None

            # Method 1: direct resolve URL.
            url1 = f'{MS_DOWNLOAD_BASE}/{model_id}/resolve/master/{fname}'
            try:
                resp = requests.get(url1, headers=headers, stream=True,
                                    timeout=(10, 120), allow_redirects=True)
                method1_status = resp.status_code
                if resp.status_code == 200:
                    with open(fpath, 'wb') as f:
                        for chunk in resp.iter_content(chunk_size=8192):
                            f.write(chunk)
                    actual_size = os.path.getsize(fpath)
                    if actual_size > 0:
                        downloaded.append({
                            'filename': fname,
                            'path': fpath,
                            'size': actual_size,
                        })
                        success = True
            except Exception as e:
                log(f"    Method 1 failed for {fname}: {e}")

            # Method 2: REST repo endpoint. Skip if method 1 already saw 404.
            if not success and method1_status != 404:
                url2 = (f'{MS_API_BASE}/models/{model_id}/repo?'
                        f'Revision=master&FilePath={fname}')
                try:
                    resp = requests.get(url2, headers=headers, stream=True,
                                        timeout=(10, 120), allow_redirects=True)
                    if resp.status_code == 200:
                        # Confirm it's a file body, not a JSON error response.
                        content_type = resp.headers.get('Content-Type', '')
                        if 'json' not in content_type:
                            with open(fpath, 'wb') as f:
                                for chunk in resp.iter_content(chunk_size=8192):
                                    f.write(chunk)
                            actual_size = os.path.getsize(fpath)
                            if actual_size > 0:
                                downloaded.append({
                                    'filename': fname,
                                    'path': fpath,
                                    'size': actual_size,
                                })
                                success = True
                except Exception as e:
                    log(f"    Method 2 failed for {fname}: {e}")

            # Method 3: SDK fallback.
            if not success:
                try:
                    from modelscope.hub.file_download import model_file_download
                    dl_path = model_file_download(
                        model_id=model_id,
                        file_path=fname,
                        cache_dir=MODEL_TEMP_DIR,
                        revision='master',
                    )
                    if dl_path and os.path.exists(dl_path):
                        if dl_path != fpath:
                            shutil.copy2(dl_path, fpath)
                        actual_size = os.path.getsize(fpath)
                        downloaded.append({
                            'filename': fname,
                            'path': fpath,
                            'size': actual_size,
                        })
                        success = True
                except ImportError:
                    log(f"    ModelScope SDK not available for fallback")
                except Exception as e:
                    log(f"    SDK fallback failed for {fname}: {e}")

            if not success:
                log(f"    All download methods failed for {fname}")

        # Best-effort fetch of config.json; useful for the inspector.
        try:
            config_url = f'{MS_DOWNLOAD_BASE}/{model_id}/resolve/master/config.json'
            resp = requests.get(config_url, headers=headers, timeout=15)
            if resp.status_code == 200:
                config_path = os.path.join(MODEL_TEMP_DIR, 'config.json')
                with open(config_path, 'w') as f:
                    f.write(resp.text)
        except Exception:
            pass

        return downloaded
    except Exception as e:
        log(f"  Download error: {e}")
        return []


def run_inspector(model_dir):
    """Run the inspector on the downloaded model directory."""
    # ulimit -u / -l raised so the inspector can lock eBPF maps into
    # memory and spawn framework worker threads without hitting kernel
    # limits.
    try:
        cmd = (
            f"ulimit -u unlimited && ulimit -l unlimited && "
            f"python3.9 {INSPECTOR_PATH} {model_dir}"
        )
        result = subprocess.run(['bash', '-c', cmd], capture_output=True,
                                text=True, timeout=INSPECTOR_TIMEOUT)
        if result.returncode != 0:
            log(f"    Inspector returncode={result.returncode}")
            if result.stderr:
                log(f"    Inspector stderr: {result.stderr[:300]}")
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        log(f"    Inspector timed out ({INSPECTOR_TIMEOUT}s)")
        return False
    except Exception as e:
        log(f"    Inspector error: {e}")
        return False


def run_classifier(events_dir, output_json):
    """Run the classifier and return a normalized verdict dict."""
    try:
        result = subprocess.run(
            ['python3.9', CLASSIFIER_PATH, events_dir, '--output', output_json],
            capture_output=True, text=True, timeout=CLASSIFIER_TIMEOUT)

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
    ms_model_id = entry.get('ms_model_id', model_id)
    name = entry.get('name', '???')
    model_files = entry.get('model_files', [])

    file_types = [mf['extension'] for mf in model_files]
    total_size_mb = entry.get('total_size', 0) / (1024 * 1024)

    log(f"\n[{index}/{total}] [ModelScope] {name} ({ms_model_id})")
    log(f"  Creator: {entry.get('creator', '?')}, Downloads: {entry.get('downloads', 0)}")
    log(f"  Files: {len(model_files)} ({total_size_mb:.1f} MB) — types: {file_types}")
    log(f"  SafeTensors: {entry.get('has_safetensors')}, "
        f"Pickle: {entry.get('has_pickle')}")

    if entry.get('metadata_reasons'):
        log(f"  Metadata: {', '.join(entry['metadata_reasons'][:5])}")

    result = {
        'model_id': model_id,
        'ms_model_id': ms_model_id,
        'platform': 'modelscope',
        'name': name,
        'creator': entry.get('creator', ''),
        'downloads': entry.get('downloads', 0),
        'model_files': [mf['filename'] for mf in model_files],
        'file_types': file_types,
        'total_size': entry.get('total_size', 0),
        'has_safetensors': entry.get('has_safetensors'),
        'has_pickle': entry.get('has_pickle'),
        'metadata_reasons': entry.get('metadata_reasons', []),
        'is_official': entry.get('is_official'),
        'timestamp': datetime.now().isoformat(),
        'status': 'pending',
    }

    start_time = time.time()

    # Step 1: download
    log(f"  Downloading {len(model_files)} file(s)...")
    downloaded = download_model(entry)
    if not downloaded:
        result['status'] = 'download_failed'
        cleanup()
        return result

    download_time = time.time() - start_time
    result['downloaded_files'] = [d['filename'] for d in downloaded]
    log(f"  Downloaded {len(downloaded)} file(s) in {download_time:.1f}s")

    # Step 2: inspect (loading + execution phases)
    log(f"  Running inspector (loading + execution)...")
    inspector_start = time.time()
    inspector_ok = run_inspector(MODEL_TEMP_DIR)
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
    cr = run_classifier(events_dir, classifier_json)

    result['status'] = 'completed'
    result['verdict'] = cr['verdict']
    result['behavior_ids'] = cr['behavior_ids']
    result['pattern_ids'] = cr['pattern_ids']
    result['behavior_count'] = cr.get('behavior_count', 0)
    result['loading_events'] = cr.get('loading_events', 0)
    result['execution_events'] = cr.get('execution_events', 0)
    result['inspector_time'] = inspector_time
    result['total_time'] = time.time() - start_time

    # Copy evidence for malicious verdicts to a dedicated folder.
    if cr['verdict'] == 'MALICIOUS':
        malicious_dir = os.path.join(RESULTS_DIR, 'malicious')
        os.makedirs(malicious_dir, exist_ok=True)

        if cr.get('raw_verdict'):
            verdict_path = os.path.join(malicious_dir, f'{safe_name}_verdict.json')
            with open(verdict_path, 'w') as f:
                json.dump(cr['raw_verdict'], f, indent=2, default=str)

        if os.path.exists(events_dir):
            events_save = os.path.join(malicious_dir, f'{safe_name}_events')
            shutil.copytree(events_dir, events_save, dirs_exist_ok=True)

        log(f"  MALICIOUS — saved evidence to {malicious_dir}")

    # Benign verdict files are redundant with the combined results.json
    # and the trace archive. Keep only malicious ones as standalone evidence.
    if cr['verdict'] != 'MALICIOUS' and os.path.exists(classifier_json):
        os.remove(classifier_json)

    log(f"  Verdict: {cr['verdict']}")
    if cr['behavior_ids']:
        log(f"  Behaviors: {', '.join(cr['behavior_ids'])}")
    if cr['pattern_ids']:
        log(f"  Patterns: {', '.join(cr['pattern_ids'][:10])}")

    cleanup()
    return result


# =============================================================================
# Scan runner
# =============================================================================
def save_progress(results):
    """Atomically write the combined results list."""
    path = os.path.join(SCAN_DIR, 'results_modelscope.json')
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

    summary = {
        'platform': 'modelscope',
        'total_models': len(all_results),
        'benign': benign,
        'malicious': malicious,
        'errors': errors,
        'status_breakdown': status_counts,
        'file_types_tested': type_counts,
        'last_updated': datetime.now().isoformat(),
    }

    path = os.path.join(SCAN_DIR, 'summary_modelscope.json')
    tmp = path + '.tmp'
    with open(tmp, 'w') as f:
        json.dump(summary, f, indent=2, default=str)
    os.replace(tmp, path)


# =============================================================================
# Main
# =============================================================================
def main():
    parser = argparse.ArgumentParser(description='ModelScope model scan pipeline')
    parser.add_argument('--num-models', type=int, default=5000,
                        help='Number of models to scan (default: 5000)')
    parser.add_argument('--resume', action='store_true',
                        help='Resume an interrupted scan')
    parser.add_argument('--reset-discovery', action='store_true',
                        help='Force restart discovery from scratch')
    args = parser.parse_args()

    os.makedirs(SCAN_DIR, exist_ok=True)
    os.makedirs(RESULTS_DIR, exist_ok=True)

    if args.reset_discovery and os.path.exists(DISCOVERY_FILE):
        os.remove(DISCOVERY_FILE)
        log("Discovery progress reset.")

    log(f"\n{'='*70}")
    log(f"  ModelScope Model Scan Pipeline")
    log(f"  Target:     {args.num_models} models")
    log(f"  Extensions: {len(MODEL_EXTENSIONS)} formats supported")
    log(f"  Work dir:   {SCAN_DIR}")
    log(f"  Inspector:  {INSPECTOR_PATH}")
    log(f"  Classifier: {CLASSIFIER_PATH}")
    log(f"{'='*70}\n")

    models = discover_models(args.num_models)
    if not models:
        log("No models found.")
        return

    all_results = []
    completed_ids = set()

    # Auto-resume from any existing results file. --resume is kept as an
    # explicit flag for parity with the HF pipeline.
    results_path = os.path.join(SCAN_DIR, 'results_modelscope.json')
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

            # Save after every model. Writes are cheap (atomic rename of
            # small JSON) and this way a crash loses at most the current
            # model.
            save_progress(all_results)
            save_summary(all_results)

            if len(all_results) % 5 == 0:
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
                'platform': 'modelscope',
            })
            cleanup()

    save_progress(all_results)
    save_summary(all_results)

    benign = sum(1 for r in all_results if r.get('verdict') == 'BENIGN')
    malicious = sum(1 for r in all_results if r.get('verdict') == 'MALICIOUS')
    errors = len(all_results) - benign - malicious

    log(f"\n{'='*70}")
    log(f"  MODELSCOPE SCAN COMPLETE")
    log(f"  Scanned:   {len(all_results)}")
    log(f"  Benign:    {benign}")
    log(f"  Malicious: {malicious}")
    log(f"  Errors:    {errors}")
    log(f"{'='*70}")

    if malicious > 0:
        log(f"\n  MALICIOUS MODELS FOUND:")
        for r in all_results:
            if r.get('verdict') == 'MALICIOUS':
                patterns = ', '.join(r.get('pattern_ids', [])[:5])
                metadata = ', '.join(r.get('metadata_reasons', [])[:3])
                log(f"  {r['model_id']} — types={r.get('file_types')}, "
                    f"patterns: {patterns}"
                    f"{f', metadata: {metadata}' if metadata else ''}")

    log(f"\nResults saved to: {SCAN_DIR}")
    log(f"Malicious evidence: {RESULTS_DIR}/malicious/")


if __name__ == '__main__':
    main()