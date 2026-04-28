"""
ModelShield Inspector (Core Runtime Behavioral Analysis Engine)

This is the main execution component of ModelShield. It
orchestrates the full inspection pipeline for a given model artifact:

  1. Format detection and metadata parsing       
  2. Input-requirements analysis & synthetic input 
  3. AOP instrumentation of framework APIs       
  4. eBPF kernel-level syscall monitoring           
  5. Event processing and cross-thread correlation  
  6. JSON event emission for Stage 2 classification

The inspector loads and executes each model file inside a forked child
process with resource limits. The parent continuously drains the eBPF 
perf buffer to prevent event loss during high-volume syscall bursts. 
Captured events are written as per-file JSON pairs 
(*_loading_events.json, *_execution_events.json)
consumed by the downstream behavioral classification stage.

Supported frameworks and formats are documented in the accompanying paper and repository materials.

Usage:
    sudo python modelshield_inspector.py <single_model_dir>
    sudo python modelshield_inspector.py <batch_models_dir>

Requires root for eBPF tracepoint attachment.
"""
import subprocess
import os
import collections
import collections.abc
collections.MutableMapping = collections.abc.MutableMapping
import json
import torch
import pickle
import numpy as np
from pathlib import Path
import warnings
import zipfile
warnings.filterwarnings('ignore')
import signal
import sys

import pdb
# Disable pdb completely
pdb.set_trace = lambda: None
pdb.Pdb.set_trace = lambda self: None
# Also disable sys.breakpointhook
sys.breakpointhook = lambda: None
sys.settrace(None) 
import io
from collections import OrderedDict
import functools 
import multiprocessing
import queue
import resource
import tempfile
import shutil
import uuid
import time
import threading
import ctypes as ct
import traceback
import inspect
import atexit
import ctypes.util
try:
    _LIBC = ct.CDLL(ctypes.util.find_library("c"))
except Exception:
    try:
        # Direct Linux fallback
        _LIBC = ct.CDLL("libc.so.6")
    except Exception:
        _LIBC = None

# Path to the companion eBPF program compiled/loaded by the runtime monitor.
EBPF_PROGRAM_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'ebpf_program.c')

# ==============================================================================
# STEP 1: FORMAT DETECTION 
# Figures out what we're dealing with before loading anything. Reads
# config.json for declared framework/architecture, matches extensions
# against known formats, and falls back to magic-byte inspection for
# ambiguous cases (.bin can be ZIP-packaged pickle, TorchScript,
# torch.package, or raw pickle — each needs a different loader).
# ==============================================================================
class TimeoutException(Exception):
    pass

# Signal handler used by signal.alarm(). When the timeout expires,
# it interrupts the current model-processing routine by raising
# TimeoutException.
def timeout_handler(signum, frame):
    raise TimeoutException("Model execution timed out!")

def with_timeout(seconds=30):
    """
    Apply a hard timeout to model-processing routines.
    Prevents a single artifact from hanging the analysis pipeline during
    loading or inference.
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            signal.signal(signal.SIGALRM, timeout_handler)
            signal.alarm(seconds)
            try:
                result = func(*args, **kwargs)
            except TimeoutException:
                return [{'file': 'unknown', 'execution_status': 'timeout', 'error': f'Timed out after {seconds} seconds'}]
            finally:
                signal.alarm(0)
            return result
        return wrapper
    return decorator



def detect_polyglot(file_path):
    """Heuristically detect files that expose multiple format signatures."""
    try:
        with open(file_path, 'rb') as f:
            header = f.read(2048)
        
        signatures = {
            b'%PDF': 'pdf',
            b'PK\x03\x04': 'zip',
            b'PK\x05\x06': 'zip',
            b'\x89PNG': 'png',
            b'\xff\xd8\xff': 'jpeg',
            b'GIF8': 'gif',
            b'\x1f\x8b': 'gzip',
            b'BM': 'bmp',
            b'\x50\x4b\x03\x04': 'zip/jar'
        }
        
        detected = []
        for sig, fmt in signatures.items():
            if sig in header[:len(sig)*2]:
                detected.append(fmt)
        
        return len(detected) > 1, detected
    except Exception:
        return False, []
        
        
        
def check_for_executables(file_path):
    """Scan the artifact for embedded executable or script signatures."""
    dangerous_patterns = [
        (b'\x4d\x5a', 'Windows EXE'),
        (b'\x7fELF', 'Linux ELF'),
        (b'\xfe\xed\xfa', 'Mach-O 32-bit'),
        (b'\xfe\xed\xfa\xce', 'Mach-O 64-bit'),
        (b'\xce\xfa\xed\xfe', 'Mach-O reverse'),
        (b'#!/bin/', 'Shell script'),
        (b'#!/usr/bin/python', 'Python script'),
        (b'#!/usr/bin/env', 'Env script')
    ]
    
    detected = []
    try:
        with open(file_path, 'rb') as f:
            content = f.read(1024*1024)  # Read first 1MB
            for pattern, desc in dangerous_patterns:
                if pattern in content:
                    detected.append(desc)
    except Exception:
        pass
    
    return detected
    
                    
def _classify_pytorch_bin(file_path):
    """
    .bin/.pt/.pth files are ambiguous. Cracks open the archive and checks
    ZIP structure to distinguish standard state dicts, TorchScript archives,
    torch.package bundles, and raw pickle streams. Each one hits a different
    loading path and AOP join point.
    """
    classification = {
        'kind': 'unknown',
        'is_zip': False,
        'contents': [],
        'safe_for_hf': False,
        'has_custom_class': False,
        'is_checkpoint': False,
        'is_quantized': False,
        'is_distributed': False
    }
    
    try:
        # Check if it's a ZIP file
        with open(file_path, 'rb') as f:
            header = f.read(2)
            if header == b'PK':
                classification['is_zip'] = True
                with zipfile.ZipFile(file_path, 'r') as zf:
                    contents = zf.namelist()
                    classification['contents'] = contents
                    
                    pkl_files = [f for f in contents if f.endswith('.pkl')]
                    classification['pickle_files'] = pkl_files
                    
                    # Check for various PyTorch formats
                    has_data_pkl = 'data.pkl' in contents
                    has_code_dir = any('code/' in name for name in contents)
                    has_archive_dir = any('archive/' in name for name in contents)
                    has_py_files = any('.py' in name for name in contents)
                    has_optimizer = any('optimizer' in name.lower() for name in contents)
                    has_quantized = any('quantized' in name.lower() for name in contents)
                    
                    # Classify based on structure
                    if (has_archive_dir and any('archive/data' in name for name in contents)) or \
                       any(name.endswith('/data.pkl') and any(name.rsplit('/', 1)[0] + '/data/' in c for c in contents) for name in pkl_files):
                        classification['kind'] = 'pytorch_standard'
                        classification['safe_for_hf'] = True
                        classification['main_pickle'] = next(
                            (p for p in pkl_files if p.endswith('data.pkl')),
                            'archive/data/0'
                        )
                    
                    elif has_code_dir:
                        classification['kind'] = 'torchscript'
                        if 'data.pkl' in contents:
                            classification['main_pickle'] = 'data.pkl'
                        elif pkl_files:
                            classification['main_pickle'] = pkl_files[0]
                    
                    elif '.data/' in ' '.join(contents):
                        classification['kind'] = 'torch_package'
                        classification['has_custom_class'] = has_py_files
                        module_pickles = {}
                        for pkl in pkl_files:
                            if '/' in pkl:
                                module = pkl.rsplit('/', 1)[0]
                                if module not in module_pickles:
                                    module_pickles[module] = []
                                module_pickles[module].append(pkl)
                        classification['module_pickles'] = module_pickles
                    
                    # Check for checkpoint/distributed training
                    if has_optimizer:
                        classification['is_checkpoint'] = True
                    if 'rank' in ' '.join(contents) or 'shard' in ' '.join(contents):
                        classification['is_distributed'] = True
                    if has_quantized:
                        classification['is_quantized'] = True
                    
            else:
                classification['kind'] = 'raw_binary'
                try:
                    with open(file_path, 'rb') as f:
                        f.seek(0)
                        first_bytes = f.read(10)
                        if first_bytes.startswith(b'\x80'):
                            classification['kind'] = 'raw_pickle'
                except Exception:
                    pass
                    
    except Exception as e:
        classification['error'] = str(e)
    
    return classification
    
def detect_model_info(model_folder):
    """
    Walk a model folder and resolve framework, format, and file layout.
    Checks config.json, file extensions, magic bytes, and embedded content
    to build the model_info dict that drives everything downstream.
    """
    if not os.path.exists(model_folder):
        return {'error': f'Folder not found: {model_folder}'}
    
    files = os.listdir(model_folder)
    info = {
        'folder': model_folder,
        'files': files,
        'has_config': 'config.json' in files,
        'model_type': 'unknown',
        'framework': 'unknown',
        'model_files': [],
        'config_data': None,
        'bin_classification': {},
        'security_checks': {}
    }
    # TF SavedModel detection (directory-based format)
    if 'saved_model.pb' in files or 'saved_model.pbtxt' in files:
        info['model_type'] = 'tensorflow_saved'
        info['framework'] = 'tensorflow'
        info['model_files'].append('saved_model.pb' if 'saved_model.pb' in files else 'saved_model.pbtxt')
        for subdir in ['variables', 'assets']:
            if subdir in files and os.path.isdir(os.path.join(model_folder, subdir)):
                info.setdefault('savedmodel_subdirs', []).append(subdir)
    
    # Load config.json if exists
    if info['has_config']:
        try:
            with open(os.path.join(model_folder, 'config.json'), 'r') as f:
                info['config_data'] = json.load(f)
        except Exception:
            pass
    
    # Check for HuggingFace models via config
    if info['has_config'] and info['config_data']:
        config = info['config_data']
        architectures = config.get('architectures', [])
        
        # Extended list of known architectures
        known_hf_archs = [
            'BertModel', 'GPT2Model', 'RobertaModel', 'DistilBertModel', 
            'AlbertModel', 'XLMRobertaModel', 'T5Model', 'BartModel',
            'GPTNeoModel', 'GPTJModel', 'LlamaModel', 'MistralModel',
            'PhiModel', 'GemmaModel', 'Qwen2Model', 'StableLmModel'
        ]
        
        # Add all variations (ForSequenceClassification, etc.)
        all_archs = []
        for base in known_hf_archs:
            all_archs.extend([
                base,
                f"{base}ForSequenceClassification",
                f"{base}ForTokenClassification",
                f"{base}ForQuestionAnswering",
                f"{base}ForMaskedLM",
                f"{base}ForCausalLM",
                f"{base}LMHeadModel"
            ])
        
        # TensorFlow versions
        tf_archs = [f"TF{arch}" for arch in all_archs]
        
        is_custom = any('Custom' in arch for arch in architectures)
        
        if not is_custom:
            if any(arch in tf_archs for arch in architectures):
                info['model_type'] = 'transformers_tf'
                info['framework'] = 'tensorflow'
            elif any(arch in all_archs for arch in architectures):
                info['model_type'] = 'pytorch/transformers'
                info['framework'] = 'pytorch'
    
    # Process each file
    for file in files:
        if file in ('saved_model.pb', 'saved_model.pbtxt'):
            continue
        file_path = os.path.join(model_folder, file)
        
        # Security checks
        is_polyglot, formats = detect_polyglot(file_path)
        if is_polyglot:
            info['security_checks'][file] = {'polyglot': True, 'formats': formats}
        
        executables = check_for_executables(file_path)
        if executables:
            info['security_checks'][file] = info['security_checks'].get(file, {})
            info['security_checks'][file]['embedded_executables'] = executables
        
        # PyTorch .pt2 export format
        # Must be handled before generic PyTorch ZIP/package detection.
        if file.endswith('.pt2'):
           classification = _classify_pytorch_bin(file_path)
           info['bin_classification'][file] = classification

           if info['framework'] == 'unknown':
              info['framework'] = 'pytorch'

           if file not in info['model_files']:
              info['model_files'].append(file)

           if info['model_type'] == 'unknown':
              info['model_type'] = 'pytorch_pt2'
       
        # PyTorch formats
        pytorch_extensions = ['.bin', '.pt', '.pth', '.th', '.pt.tar', '.ckpt']
        if any(file.endswith(ext) for ext in pytorch_extensions):
            classification = _classify_pytorch_bin(file_path)
            info['bin_classification'][file] = classification
            
            if info['framework'] == 'unknown':
                info['framework'] = 'pytorch'
            
            info['model_files'].append(file)
            
            if info['model_type'] == 'unknown':
                if classification['kind'] == 'torchscript':
                    info['model_type'] = 'torchscript'
                elif classification['kind'] == 'torch_package':
                    info['model_type'] = 'torch_package'
                elif file == 'pytorch_model.bin' and classification['safe_for_hf']:
                    info['model_type'] = 'pytorch/transformers'
                elif classification['is_checkpoint']:
                    info['model_type'] = 'pytorch_checkpoint'
                elif classification['is_quantized']:
                    info['model_type'] = 'pytorch_quantized'
                elif file.endswith('.th'):
                    info['model_type'] = 'pytorch_th'
                elif file.endswith('.pt2'):
                    info['model_type'] = 'pytorch_pt2'
                else:
                    info['model_type'] = 'pytorch'
        
        # SafeTensors (SAFE format)
        elif file.endswith('.safetensors'):
            info['model_type'] = 'safetensors'
            info['framework'] = 'safetensors'
            info['model_files'].append(file)
        
        # ONNX
        elif file.endswith('.onnx'):
            info['model_type'] = 'onnx'
            info['framework'] = 'onnx'
            info['model_files'].append(file)
        
        # TensorFlow formats
        elif file.endswith('.h5'):
            if info['model_type'] == 'unknown':
                info['model_type'] = 'keras'
                info['framework'] = 'tensorflow'
            info['model_files'].append(file)
        
        elif file.endswith('.keras'):
            info['model_type'] = 'keras'
            info['framework'] = 'tensorflow'
            info['model_files'].append(file)
        
        elif file.endswith('.pb'):
            info['model_type'] = 'tensorflow_saved'
            info['framework'] = 'tensorflow'
            info['model_files'].append(file)
        
        elif file.endswith('.tflite'):
            info['model_type'] = 'tflite'
            info['framework'] = 'tensorflow'
            info['model_files'].append(file)
        
        # JAX/Flax
        elif file.endswith('.msgpack') or file == 'flax_model.msgpack':
            info['model_type'] = 'flax'
            info['framework'] = 'jax'
            info['model_files'].append(file)
        
        # Gradient boosting
        elif file.endswith('.xgb') or file.endswith('.bst') or file.endswith('.ubj'):
            info['model_type'] = 'xgboost'
            info['framework'] = 'xgboost'
            info['model_files'].append(file)
        
        elif file.endswith('.lgb') or (file.endswith('.txt') and 'lightgbm' in file.lower()):
            info['model_type'] = 'lightgbm'
            info['framework'] = 'lightgbm'
            info['model_files'].append(file)
        
        elif file.endswith('.cbm'):
            info['model_type'] = 'catboost'
            info['framework'] = 'catboost'
            info['model_files'].append(file)
        
        # Scikit-learn
        elif file.endswith('.joblib'):
            info['model_type'] = 'sklearn'
            info['framework'] = 'scikit-learn'
            info['model_files'].append(file)
        
        # Pickle files
        elif file.endswith('.pkl') or file.endswith('.pickle'):
            if info['model_type'] == 'unknown':
                info['model_type'] = 'pickle'
                info['framework'] = 'pickle'
            info['model_files'].append(file)
        
        # Dill files (extended pickle)
        elif file.endswith('.dill'):
            if info['model_type'] == 'unknown':
                info['model_type'] = 'dill'
                info['framework'] = 'dill'
            info['model_files'].append(file)
        
        # CoreML
        elif file.endswith('.mlmodel') or file.endswith('.mlpackage'):
            info['model_type'] = 'coreml'
            info['framework'] = 'coreml'
            info['model_files'].append(file)
        
        # MXNet
        elif file.endswith('.params'):
            if 'symbol.json' in files or any(f.endswith('-symbol.json') for f in files):
                info['model_type'] = 'mxnet'
                info['framework'] = 'mxnet'
                info['model_files'].append(file)
        
        # PaddlePaddle
        elif file.endswith('.pdmodel') or file.endswith('.pdiparams'):
            info['model_type'] = 'paddle'
            info['framework'] = 'paddlepaddle'
            info['model_files'].append(file)
        
        # TensorRT
        elif file.endswith('.engine') or file.endswith('.plan') or file.endswith('.trt'):
            info['model_type'] = 'tensorrt'
            info['framework'] = 'tensorrt'
            info['model_files'].append(file)
        
        # NCNN
        elif file.endswith('.param') or file.endswith('.ncnn'):
            info['model_type'] = 'ncnn'
            info['framework'] = 'ncnn'
            info['model_files'].append(file)
        
        # OpenVINO
        elif file.endswith('.xml') and any(f.endswith('.bin') for f in files):
            if 'openvino' in file.lower() or 'model' in file.lower():
                info['model_type'] = 'openvino'
                info['framework'] = 'openvino'
                info['model_files'].append(file)
        
        # Apache TVM
        elif file.endswith('.json') and 'tvm' in file.lower():
            info['model_type'] = 'tvm'
            info['framework'] = 'tvm'
            info['model_files'].append(file)
        
        # MediaPipe
        elif file.endswith('.task'):
            info['model_type'] = 'mediapipe'
            info['framework'] = 'mediapipe'
            info['model_files'].append(file)
        
        # DLPack
        elif file.endswith('.dlpack'):
            info['model_type'] = 'dlpack'
            info['framework'] = 'dlpack'
            info['model_files'].append(file)
        
        # NumPy
        elif file.endswith('.npy') or file.endswith('.npz'):
            info['model_type'] = 'numpy'
            info['framework'] = 'numpy'
            info['model_files'].append(file)
            
        # Archive files
        elif file.endswith('.zip') or file.endswith('.tar') or file.endswith('.tar.gz'):
            info['model_type'] = 'archive' if info['model_type'] == 'unknown' else info['model_type']
            info['model_files'].append(file)
        # PMML
        elif file.endswith('.pmml') or file.endswith('.xml') and 'pmml' in file.lower():
            info['model_type'] = 'pmml'
            info['framework'] = 'pmml'
            info['model_files'].append(file)  
    # Check for tokenizer files
    tokenizer_files = ['tokenizer.json', 'tokenizer_config.json', 'vocab.txt', 
                      'vocab.json', 'merges.txt', 'special_tokens_map.json',
                      'spiece.model', 'tokenizer.model']
    info['has_tokenizer'] = any(f in files for f in tokenizer_files)
    
    # Check for processor files (for multimodal models)
    processor_files = ['preprocessor_config.json', 'processor_config.json',
                      'feature_extractor_config.json']
    info['has_processor'] = any(f in files for f in processor_files)
    
    return info

# ==============================================================================
# STEP 2: INPUT INFERENCE AND SYNTHETIC GENERATION
#
# Pickle-based attacks fire on load, but TF API abuse and compromised
# forward() methods only trigger during inference. We need to actually
# run the model with valid input to see those. This stage figures out
# what shape/type the model expects and builds a throwaway tensor for it.
# ==============================================================================

def determine_input_requirements(model_info):
    """
    Infer what the model expects as input from config fields, framework
    conventions, or folder-name heuristics. Returns a dict with type,
    shape, and a sample input value for synthetic execution.
    """
    requirements = {
        'needs_input': True,
        'input_type': 'unknown',
        'input_shape': None,
        'sample_input': None,
        'additional_info': {},
        'modality': 'unknown' 
    }
    
    # Config-based detection
    if model_info['has_config'] and model_info['config_data']:
        config = model_info['config_data']
        
        model_type = config.get('model_type', '')
        architectures = config.get('architectures', [])
        
        # Text models
        if any(x in model_type.lower() for x in ['bert', 'gpt', 'roberta', 'albert', 
                                                  'xlm', 't5', 'bart', 'llama', 
                                                  'mistral', 'phi', 'gemma', 'qwen']):
            requirements['input_type'] = 'text'
            requirements['modality'] = 'text'
            requirements['input_shape'] = 'text string'
            requirements['sample_input'] = "This is a test sentence for the model"
            requirements['additional_info'] = {
                'max_length': config.get('max_position_embeddings', 512),
                'vocab_size': config.get('vocab_size', 30000)
            }
        
        # Vision models
        elif any(x in model_type.lower() for x in ['vit', 'deit', 'beit', 'swin', 
                                                    'resnet', 'efficientnet', 'convnext',
                                                    'mobilenet', 'densenet']):
            requirements['input_type'] = 'image'
            requirements['modality'] = 'vision'
            img_size = config.get('image_size', 224)
            requirements['input_shape'] = [1, 3, img_size, img_size]
            requirements['sample_input'] = f'torch.randn(1, 3, {img_size}, {img_size})'
        
        # Audio models
        elif any(x in model_type.lower() for x in ['wav2vec', 'whisper', 'audio', 
                                                    'speech', 'hubert']):
            requirements['input_type'] = 'audio'
            requirements['modality'] = 'audio'
            requirements['input_shape'] = [1, 16000]  # 1 second at 16kHz
            requirements['sample_input'] = 'torch.randn(1, 16000)'
            requirements['additional_info'] = {
                'sample_rate': config.get('sample_rate', 16000)
            }
        
        # Multimodal models
        elif any(x in model_type.lower() for x in ['clip', 'align', 'flamingo', 
                                                    'blip', 'bridgetower']):
            requirements['input_type'] = 'multimodal'
            requirements['modality'] = 'multimodal'
            requirements['sample_input'] = {
                'text': "A description of an image",
                'image': 'torch.randn(1, 3, 224, 224)'
            }
    
    # Framework-specific defaults
    elif model_info['framework'] != 'unknown':
        framework = model_info['framework']
        
        if framework == 'onnx':
            requirements['input_type'] = 'tensor'
            requirements['input_shape'] = [1, 224, 224, 3]  # Common for ONNX
            requirements['sample_input'] = 'numpy.random.randn(1, 224, 224, 3).astype(np.float32)'
        
        elif framework == 'tflite':
            requirements['input_type'] = 'tensor'
            requirements['input_shape'] = [1, 224, 224, 3]
            requirements['sample_input'] = 'numpy.random.randn(1, 224, 224, 3).astype(np.float32)'
        
        elif framework == 'coreml':
            requirements['input_type'] = 'image'
            requirements['modality'] = 'vision'
            requirements['input_shape'] = [1, 3, 224, 224]
            requirements['sample_input'] = 'PIL.Image'
        
        elif framework in ['xgboost', 'lightgbm', 'catboost', 'scikit-learn']:
            requirements['input_type'] = 'tabular'
            requirements['modality'] = 'tabular'
            requirements['input_shape'] = [1, 100]  # Generic feature vector
            requirements['sample_input'] = 'numpy.random.randn(1, 100)'
        
        elif framework == 'safetensors':
            # SafeTensors can contain any type of model
            requirements['needs_input'] = False  # Just loading is enough for safety check
            requirements['input_type'] = 'possibly_none'
        
        elif framework == 'pickle':
            requirements['needs_input'] = False
            requirements['input_type'] = 'possibly_none'
            requirements['additional_info']['warning'] = 'Pickle files may execute code on load'
        
        elif framework == 'dill':
            requirements['needs_input'] = False
            requirements['input_type'] = 'possibly_none'
            requirements['additional_info']['warning'] = 'Dill files extend pickle and may execute arbitrary code on load'
        
        elif framework == 'numpy':
            requirements['needs_input'] = False
            requirements['input_type'] = 'possibly_none'
            requirements['additional_info']['warning'] = 'NPY/NPZ files use pickle internally when allow_pickle=True'    
        
        elif framework == 'pmml':
            requirements['input_type'] = 'tabular'
            requirements['modality'] = 'tabular'
            requirements['needs_input'] = False  # pypmml can introspect input fields
            requirements['input_shape'] = [1, 100]
            requirements['sample_input'] = 'numpy.random.randn(1, 100)'
            requirements['additional_info']['warning'] = 'PMML XML may contain XXE/SSRF payloads'
    # Folder name heuristics
    folder_name = os.path.basename(model_info['folder']).lower()
    
    if requirements['input_type'] == 'unknown':
        if any(x in folder_name for x in ['bert', 'gpt', 'roberta', 'transformer', 'nlp', 'text']):
            requirements['input_type'] = 'text'
            requirements['modality'] = 'text'
            requirements['sample_input'] = "Sample text for testing"
        
        elif any(x in folder_name for x in ['vision', 'vit', 'resnet', 'image', 'cnn', 'conv']):
            requirements['input_type'] = 'image'
            requirements['modality'] = 'vision'
            requirements['input_shape'] = [1, 3, 224, 224]
            requirements['sample_input'] = 'torch.randn(1, 3, 224, 224)'
        
        elif any(x in folder_name for x in ['audio', 'wav', 'speech', 'sound']):
            requirements['input_type'] = 'audio'
            requirements['modality'] = 'audio'
            requirements['input_shape'] = [1, 16000]
            requirements['sample_input'] = 'torch.randn(1, 16000)'
        
        elif any(x in folder_name for x in ['video', 'action', 'temporal']):
            requirements['input_type'] = 'video'
            requirements['modality'] = 'video'
            requirements['input_shape'] = [1, 16, 3, 224, 224]  # 16 frames
            requirements['sample_input'] = 'torch.randn(1, 16, 3, 224, 224)'
        
        elif any(x in folder_name for x in ['graph', 'gnn', 'gcn']):
            requirements['input_type'] = 'graph'
            requirements['modality'] = 'graph'
            requirements['sample_input'] = 'Graph with nodes and edges'
        
        elif 'diffusion' in folder_name or 'stable' in folder_name:
            requirements['input_type'] = 'text_to_image'
            requirements['modality'] = 'multimodal'
            requirements['input_shape'] = 'text prompt'
            requirements['sample_input'] = "A beautiful landscape painting"
    
    # Final fallback
    if requirements['input_type'] == 'unknown':
        requirements['input_type'] = 'unknown_try_common'
        requirements['common_options'] = {
            'text': "Try with text: 'Sample text'",
            'image': "Try with image: torch.randn(1, 3, 224, 224)",
            'audio': "Try with audio: torch.randn(1, 16000)",
            'tabular': "Try with tabular: numpy.random.randn(1, 100)",
            'vector': "Try with vector: torch.randn(1, 100)",
            'none': "Try loading without input (for pickle exploits)"
        }
    
    return requirements


# ==============================================================================
# STEP 3: STRUCTURAL VALIDATION
#
# Quick pre-load triage: unusually small artifacts, polyglot signatures,
# embedded executables, and format-specific red flags are surfaced here
# before deserialization begins.
# ==============================================================================

def analyze_model_structure(model_info, requirements):
    """
    Pre-load validation. Flags suspiciously small files, polyglot
    artifacts, embedded executables, and raw pickle formats. This
    runs before any deserialization happens.
    """
    structure = {
        'architecture': 'unknown',
        'layers': [],
        'parameters': 0,
        'file_sizes': {},
        'is_real_model': True,
        'suspicious_indicators': [],
        'security_risks': []
    }
    
    # Check file sizes
    for file in model_info['model_files']:
        file_path = os.path.join(model_info['folder'], file)
        if os.path.exists(file_path):
            size = os.path.getsize(file_path)
            structure['file_sizes'][file] = f"{size / 1024:.2f} KB"
            
            # Suspicious size checks
            if size < 1000:  # Less than 1KB
                structure['suspicious_indicators'].append(f'{file} is suspiciously small ({size} bytes)')
                structure['is_real_model'] = False
            elif size > 10 * 1024**3:  # More than 10GB
                structure['suspicious_indicators'].append(f'{file} is unusually large ({size / 1024**3:.2f} GB)')
    
    # Add security checks
    if model_info.get('security_checks'):
        for file, checks in model_info['security_checks'].items():
            if checks.get('polyglot'):
                structure['security_risks'].append(f'{file} is a polyglot file: {checks["formats"]}')
            if checks.get('embedded_executables'):
                structure['security_risks'].append(f'{file} contains executables: {checks["embedded_executables"]}')
    
    # Framework-specific analysis
    if model_info['framework'] == 'pytorch' and model_info['model_files']:
        model_file = os.path.join(model_info['folder'], model_info['model_files'][0])
        try:
            with open(model_file, 'rb') as f:
                header = f.read(2)
                if header == b'PK':
                    structure['architecture'] = 'pytorch_zip_format'
                    
                    with zipfile.ZipFile(model_file, 'r') as zf:
                        zip_contents = zf.namelist()
                        if 'data.pkl' in ' '.join(zip_contents):
                            structure['suspicious_indicators'].append('Contains data.pkl file')
                        if any('.py' in f for f in zip_contents):
                            structure['suspicious_indicators'].append('Contains Python code files')
                            structure['security_risks'].append('Embedded Python code detected')
                else:
                    structure['architecture'] = 'raw_pickle_format'
                    structure['suspicious_indicators'].append('Raw pickle format (not standard PyTorch)')
                    structure['security_risks'].append('Raw pickle - high risk of arbitrary code execution')
                    
        except Exception as e:
            structure['error'] = str(e)
    
    # SafeTensors is explicitly safe
    elif model_info['framework'] == 'safetensors':
        structure['architecture'] = 'safetensors'
        structure['security_risks'].append('SafeTensors format - designed to be safe from code execution')
    
    # Config-based architecture info
    if model_info['config_data']:
        config = model_info['config_data']
        structure['architecture'] = config.get('architectures', [config.get('model_type', 'unknown')])
        structure['parameters'] = config.get('num_parameters', 0)
        
        if 'num_hidden_layers' in config:
            structure['layers'].append(f"{config['num_hidden_layers']} hidden layers")
        if 'hidden_size' in config:
            structure['layers'].append(f"Hidden size: {config['hidden_size']}")
    
    return structure

# ==============================================================================
# STEP 4: SYNTHETIC INPUT CONSTRUCTION
#
# Builds the actual tensor/string/dict that gets fed to the model.
# The input only needs to be valid enough to reach the model's code
# paths. We don't care about prediction quality.
# ==============================================================================

def create_model_input(requirements):
    """
    Build a synthetic input matching the inferred requirements.
    Just needs to be the right type and shape to trigger execution.
    """
    import torch
    import numpy as np
    
    input_data = None
    
    if requirements['input_type'] == 'text':
        input_data = requirements['sample_input']
    
    elif requirements['input_type'] == 'image':
        if 'torch' in requirements.get('sample_input', ''):
            shape = requirements['input_shape'] or [1, 3, 224, 224]
            input_data = torch.randn(*shape)
        else:
            shape = requirements['input_shape'] or [1, 224, 224, 3]
            input_data = np.random.randn(*shape).astype(np.float32)
            
    elif requirements['input_type'] == 'audio':
        if requirements['input_shape']:
            input_data = torch.randn(*requirements['input_shape'])
        else:
            input_data = torch.randn(1, 16000)  # 1 second at 16kHz
    
    elif requirements['input_type'] == 'video':
        if requirements['input_shape']:
            input_data = torch.randn(*requirements['input_shape'])
        else:
            input_data = torch.randn(1, 16, 3, 224, 224)  # 16 frames
    
    elif requirements['input_type'] == 'tabular':
        if 'numpy' in requirements.get('sample_input', ''):
            shape = requirements['input_shape'] or [1, 100]
            input_data = np.random.randn(*shape).astype(np.float32)
        else:
            input_data = torch.randn(1, 100)
    
    elif requirements['input_type'] == 'tensor':
        if requirements['input_shape']:
            if 'numpy' in requirements.get('sample_input', ''):
                input_data = np.random.randn(*requirements['input_shape']).astype(np.float32)
            else:
                input_data = torch.randn(*requirements['input_shape'])
        else:
            input_data = torch.randn(1, 100)
    
    elif requirements['input_type'] == 'graph':
        # Create simple graph structure
        input_data = {
            'x': torch.randn(10, 16),  # 10 nodes with 16 features
            'edge_index': torch.tensor([[0, 1, 2], [1, 2, 0]], dtype=torch.long),
            'batch': torch.zeros(10, dtype=torch.long)
        }
    
    elif requirements['input_type'] == 'text_to_image':
        input_data = requirements['sample_input']
    
    elif requirements['input_type'] == 'multimodal':
        input_data = {
            'text': "A test description",
            'image': torch.randn(1, 3, 224, 224)
        }
    
    elif requirements['input_type'] == 'possibly_none':
        input_data = None
    
    else:
        # Unknown - try generic tensor
        input_data = torch.randn(1, 100)
    
    return input_data


# ==============================================================================
# STEP 5: MODEL LOADING AND EXECUTION
#
# Walks model_info['model_files'], picks the right loader for each
# file's resolved format, and runs it. This happens inside a forked
# child with resource limits so a malicious payload can crash, call
# sys.exit(), or spin forever without taking down the monitor. The
# parent keeps draining the perf buffer the whole time.
# ==============================================================================
@with_timeout(60)
def execute_model(model_info, requirements, structure, input_data):
  """
  Load and execute each model file under AOP + eBPF monitoring.
  Iterates over model_info['model_files'], selects the loader matching
  the resolved format, and attempts both loading and inference.
  """
  import sys
  import io  
  import zipfile
  import pickle
  original_stdin = sys.stdin
  sys.stdin = io.StringIO('')
  model_results=[]
  import threading
  import signal
  try:
        signal.signal(signal.SIGPIPE, signal.SIG_IGN)
  except Exception:
        pass  # SIGPIPE might not exist on some systems
    
  
    
  for file in model_info.get('model_files', []):
    _loading_start = len(monitor.loading_events) + len(monitor.all_loading_events)
    _execution_start = len(monitor.execution_events) + len(monitor.all_execution_events)

    results = {
        'execution_status': 'not_attempted',
        'output': None,
        'error': None,
        'warnings': [],
        'loading_method': None ,
        'file': file
    }
    if structure['suspicious_indicators']:
        results['warnings'] = structure['suspicious_indicators']
        print("[Inspector] Warnings:")
        for warning in structure['suspicious_indicators']:
            print(f"   - {warning}")
    if structure['security_risks']:
            results['warnings'].extend(structure['security_risks'])
            print("[Inspector] Security risks:")
            for risk in structure['security_risks']:
                print(f"   - {risk}")
   
   
    if not structure['is_real_model']:
        print("   - Artifact appears inconsistent with a normal deployable model")
    
    all_file_results = []
    any_file_executed = False
    model_folder = model_info['folder']
    file_path = os.path.join(model_folder, file)
    # Attempt execution based on model type
    
    file_type = None
    
    # .pt2 must use torch.export.load(), not torch.load() or PackageImporter.
    if file.endswith('.pt2'):
       file_type = 'pytorch_pt2'
    # Check the classification for this specific file
    elif file in model_info.get('bin_classification', {}):
            classification = model_info['bin_classification'][file]
            kind = classification.get('kind', 'unknown')
            
            if classification.get('safe_for_hf') and model_info.get('has_config') and file.endswith(('.bin', '.safetensors')):
                file_type = 'pytorch/transformers'
            elif kind == 'pytorch_standard':
                file_type = 'pytorch'
            elif kind == 'torch_package':
                file_type = 'torch_package'
            elif kind == 'torchscript':
                file_type = 'torchscript'
            elif classification.get('is_checkpoint'):
                file_type = 'pytorch_checkpoint'
            elif classification.get('is_quantized'):
                file_type = 'pytorch_quantized'
            elif kind in ['raw_pickle', 'raw_binary', 'unknown_zip']:
                file_type = 'pytorch_bin_unknown'
            else:
                file_type = 'pytorch'
                
                
    # SafeTensors
    elif file.endswith('.safetensors'):
            file_type = 'safetensors'
        
    # ONNX
    elif file.endswith('.onnx'):
            file_type = 'onnx'
        
    # TensorFlow variants
    elif file.endswith('.h5'):
        if model_info['model_type'] == 'transformers_tf':
           file_type = 'transformers_tf'
        else:
           file_type = 'keras'
    elif file.endswith('.keras'):
         file_type = 'keras'
    elif file.endswith('.pb'):
         file_type = 'tensorflow_saved'
    elif file.endswith('.tflite'):
         file_type = 'tflite'
        
    # JAX/Flax
    elif file.endswith('.msgpack'):
         file_type = 'flax'
        
    # Gradient boosting
    elif file.endswith(('.xgb', '.bst', '.ubj')):
         file_type = 'xgboost'
    elif file.endswith('.lgb') or (file.endswith('.txt') and 'lightgbm' in file.lower()):
         file_type = 'lightgbm'
    elif file.endswith('.cbm'):
         file_type = 'catboost'
        
    # Scikit-learn
    elif file.endswith('.joblib'):
         file_type = 'sklearn'
        
    # Others
    elif file.endswith(('.pkl', '.pickle')):
         file_type = 'pickle'
    elif file.endswith('.dill'):
         file_type = 'dill'
    elif file.endswith('.pmml'):
         file_type = 'pmml'
    elif file.endswith(('.mlmodel', '.mlpackage')):
         file_type = 'coreml'
    elif file.endswith('.params') and model_info['model_type'] == 'mxnet':
         file_type = 'mxnet'
    elif file.endswith(('.pdmodel', '.pdiparams')):
         file_type = 'paddle'
    elif file.endswith(('.engine', '.plan', '.trt')):
         file_type = 'tensorrt'
    elif file.endswith('.pt2'):
         file_type = 'pytorch_pt2'
    elif file.endswith(('.pt', '.pth', '.ckpt')):
         file_type = 'pytorch'
    elif file.endswith('.th'):
         file_type = 'pytorch_th'
    elif file.endswith(('.zip', '.tar', '.tar.gz')):
         file_type = 'archive'
    elif file.endswith(('.npy', '.npz')):
         file_type = 'numpy'
    else:
         file_type = model_info.get('model_type', 'unknown')
        
    print(f"\n  Processing {file} as type: {file_type}")
        

    
    try:
       # SAFETENSORS (SAFE LOADING)
       if file_type == 'safetensors':
                print("Loading SafeTensors model (SAFE format)...")
                results['loading_method'] = 'safetensors'
                
                try:
                    from safetensors import safe_open
                    from safetensors.torch import load_file
                    
                    # Method 1: Load as dict of tensors
                    tensors = load_file(file_path)
                    results['execution_status'] = 'model_loaded'
                    results['output'] = f"SafeTensors loaded: {len(tensors)} tensors"
                    
                    # Check if it's a state dict for a known architecture
                    if model_info.get('has_config') and model_info.get('config_data'):
                        try:
                            from transformers import AutoModel
                            model = AutoModel.from_pretrained(model_folder)
                            model = wrap_model_for_execution(model)
                            results['execution_status'] = 'model_loaded'
                            
                            if requirements['input_type'] == 'text' and model_info['has_tokenizer']:
                                from transformers import AutoTokenizer
                                tokenizer = AutoTokenizer.from_pretrained(model_folder)
                                inputs = tokenizer(input_data, return_tensors="pt")
                                
                                with torch.no_grad():
                                    output = model(**inputs)
                                results['output'] = f"Model executed: {output.last_hidden_state.shape}"
                                results['execution_status'] = 'success'
                        except Exception:
                            pass
                    
                    # List some tensor info
                    tensor_info = []
                    for key, tensor in list(tensors.items())[:5]:
                        tensor_info.append(f"{key}: {tensor.shape}")
                    if tensor_info:
                        results['output'] += f" | Tensors: {', '.join(tensor_info)}"
                    
                except ImportError:
                    results['error'] = "safetensors library not installed"
                    results['execution_status'] = 'failed'
                except Exception as e:
                    results['error'] = f"SafeTensors load failed: {str(e)}"
                    results['execution_status'] = 'failed'
       
                if 'model' in locals():
                    del model
                if 'bin_contents' in locals():
                    del bin_contents
                if 'base_model' in locals():
                    del base_model
                if 'tokenizer' in locals():
                    del tokenizer   
                import gc
                gc.collect()
       elif file_type == 'numpy':
            print(f"Loading NumPy file: {file}...")
            results['loading_method'] = 'numpy'

            import io as io_module
            import contextlib
            import numpy as np
            stdout_capture = io_module.StringIO()
            stderr_capture = io_module.StringIO()

            try:
                with contextlib.redirect_stdout(stdout_capture), contextlib.redirect_stderr(stderr_capture):
                    if file.endswith('.npz'):
                        data = np.load(file_path, allow_pickle=True)
                        data = wrap_model_for_execution(data) if callable(data) else data
                        keys = list(data.keys()) if hasattr(data, 'keys') else []
                        results['output'] = f"NPZ loaded: {len(keys)} arrays, keys={keys[:10]}"
                        for key in keys:
                            try:
                                arr = data[key]
                                print(f"    Array '{key}': shape={arr.shape}, dtype={arr.dtype}")
                            except Exception as arr_err:
                                print(f"    Array '{key}' access error: {arr_err}")
                                results['warnings'].append(f"Malicious payload in array '{key}'")
                    else:
                        data = np.load(file_path, allow_pickle=True)
                        data = wrap_model_for_execution(data) if callable(data) else data
                        if hasattr(data, 'shape'):
                            results['output'] = f"NPY loaded: shape={data.shape}, dtype={data.dtype}"
                        else:
                            results['output'] = f"NPY loaded: type={type(data)}"

                captured_output = stdout_capture.getvalue()
                captured_errors = stderr_capture.getvalue()

                if captured_output:
                    print(f"STDOUT: {captured_output[:200]}")
                    results['warnings'].append(f"Code output: {captured_output}")
                    results['execution_status'] = 'malicious_executed'
                elif captured_errors:
                    print(f"STDERR: {captured_errors[:200]}")
                    results['warnings'].append(f"Errors: {captured_errors}")
                    results['execution_status'] = 'malicious_executed'
                else:
                    results['execution_status'] = 'success'

                if callable(data) and input_data is not None:
                    try:
                        output = data(input_data)
                        results['output'] += f" | Executed callable: {type(output)}"
                    except Exception as exec_err:
                        results['output'] += f" | Callable execution error: {str(exec_err)[:50]}"

            except Exception as e:
                error_msg = str(e)
                print(f"    Error loading numpy file: {error_msg}")

                try:
                    captured_output = stdout_capture.getvalue()
                    captured_errors = stderr_capture.getvalue()
                    if captured_output:
                        print(f"STDOUT during error: {captured_output[:200]}")
                    if captured_errors:
                        print(f"STDERR during error: {captured_errors[:200]}")
                except Exception:
                    pass

                if any(x in error_msg.lower() for x in ['exec', '__reduce__', 'eval', 'import', 'module']):
                    results['execution_status'] = 'malicious_executed'
                    results['output'] = f"Malicious code in numpy file: {error_msg[:100]}"
                    results['warnings'].append("Malicious pickle payload detected in .npy/.npz")
                elif "Network" in error_msg or "Connection" in error_msg:
                    results['execution_status'] = 'malicious_executed'
                    results['output'] = f"Network activity from numpy file: {error_msg[:100]}"
                else:
                    results['execution_status'] = 'failed'
                    results['error'] = f"NumPy load failed: {error_msg}"

            if 'data' in locals():
                del data
            import gc
            gc.collect()
       
       # ONNX
       elif file_type == 'onnx':
                print("Loading ONNX model...")
                results['loading_method'] = 'onnx'
                
                # Step 1: Load via onnx protobuf library (triggers external_data resolution)
                try:
                   import onnx
                   model_proto = onnx.load(file_path)
                   results['execution_status'] = 'model_loaded'
                   results['output'] = f"ONNX protobuf loaded: {len(model_proto.graph.node)} nodes"
                   
                   # Check for malicious content in successfully loaded models
                   # doc_string injection
                   if model_proto.doc_string:
                       if any(x in model_proto.doc_string for x in ['__import__', 'exec(', 'eval(', 'system(', '<script', 'os.system']):
                           results['execution_status'] = 'malicious_executed'
                           results['output'] += f" | Malicious doc_string: {model_proto.doc_string[:80]}"
                           results['warnings'].append(f"Code injection in doc_string")
                   
                   # Tensor name path traversal
                   for init in model_proto.graph.initializer:
                       if '..' in init.name or '/' in init.name:
                           results['execution_status'] = 'malicious_executed'
                           results['output'] += f" | Path traversal in tensor name: {init.name}"
                           results['warnings'].append(f"Path traversal in tensor name: {init.name}")
                   for node in model_proto.graph.node:
                       for inp in list(node.input) + list(node.output):
                           if '..' in inp or '/' in inp:
                               results['warnings'].append(f"Path traversal in node I/O: {inp}")
                   
                except Exception as proto_err:
                   print(f"    onnx.load failed: {str(proto_err)[:200]}")
                   results['warnings'].append(f"onnx.load error: {str(proto_err)[:100]}")
                   error_msg = str(proto_err)
                   if any(x in error_msg for x in ['doesn\'t exist', 'not accessible', 'Connection', 'resolve', 'points outside']):
                      results['execution_status'] = 'malicious_executed'
                      results['output'] = f"Malicious external_data triggered: {error_msg[:100]}"
    
                # Step 2: Try onnxruntime for actual inference
                # Only overwrite status if Step 1 didn't already detect malicious content
                try:
                    import onnxruntime as ort
                    
                    session = ort.InferenceSession(file_path)
                    session = wrap_model_for_execution(session)
                    results['execution_status'] = 'model_loaded'
                    
                    input_info = session.get_inputs()[0]
                    input_name = input_info.name
                    input_shape = input_info.shape
                    
                    if input_shape:
                        shape = [dim if dim else 1 for dim in input_shape]
                        shape = [s if isinstance(s, int) else 1 for s in shape]
                        test_input = np.random.randn(*shape).astype(np.float32)
                    else:
                        test_input = np.random.randn(1, 224, 224, 3).astype(np.float32)
                    
                    outputs = session.run(None, {input_name: test_input})
                    results['output'] = f"ONNX executed: output shape {outputs[0].shape}"
                    results['execution_status'] = 'success'
                    
                except ImportError:
                    if results['execution_status'] not in ('malicious_executed', 'model_loaded'):
                        results['error'] = "onnxruntime not installed"
                        results['execution_status'] = 'failed'
                except Exception as e:
                    if results['execution_status'] not in ('malicious_executed', 'model_loaded'):
                        results['error'] = f"ONNX execution failed: {str(e)}"
                        results['execution_status'] = 'failed'
                
                if 'model' in locals():
                    del model
                import gc
                gc.collect()
       # TENSORFLOW LITE
       elif file_type == 'tflite':
                print("Loading TensorFlow Lite model...")
                results['loading_method'] = 'tflite'
                
                try:
                    import tensorflow as tf
                    
                    interpreter = tf.lite.Interpreter(model_path=file_path)
                    interpreter = wrap_model_for_execution(interpreter)
                    interpreter.allocate_tensors()
                    results['execution_status'] = 'model_loaded'
                    
                    # Get input details
                    input_details = interpreter.get_input_details()
                    output_details = interpreter.get_output_details()
                    
                    # Create input
                    input_shape = input_details[0]['shape']
                    input_dtype = input_details[0]['dtype']
                    test_input = np.random.randn(*input_shape).astype(input_dtype)
                    
                    # Run inference
                    interpreter.set_tensor(input_details[0]['index'], test_input)
                    interpreter.invoke()
                    output = interpreter.get_tensor(output_details[0]['index'])
                    
                    results['output'] = f"TFLite executed: output shape {output.shape}"
                    results['execution_status'] = 'success'
                    
                except ImportError:
                    results['error'] = "TensorFlow not installed"
                    results['execution_status'] = 'failed'
                except Exception as e:
                    results['error'] = f"TFLite execution failed: {str(e)}"
                    results['execution_status'] = 'failed'
                if 'model' in locals():
                    del model
                import gc
                gc.collect()

       # JAX/FLAX
       elif file_type == 'flax':
                print("Loading Flax model...")
                results['loading_method'] = 'flax'
                
                try:
                    import jax
                    import jax.numpy as jnp
                    from flax import serialization
                    
                    with open(file_path, 'rb') as f:
                        state = serialization.msgpack_restore(f.read())
                    
                    results['execution_status'] = 'model_loaded'
                    results['output'] = f"Flax model loaded: {type(state)}"
                    
                    # If there's a config, try to load as HuggingFace model
                    if model_info.get('has_config'):
                        try:
                            from transformers import FlaxAutoModel
                            model = FlaxAutoModel.from_pretrained(model_folder)
                            model = wrap_model_for_execution(model)
                            # Create JAX input
                            if requirements['input_type'] == 'text':
                                test_input = jnp.ones((1, 128), dtype=jnp.int32)
                            else:
                                test_input = jnp.ones((1, 224, 224, 3), dtype=jnp.float32)
                            
                            output = model(test_input)
                            results['output'] += f" | Executed: {output[0].shape}"
                            results['execution_status'] = 'success'
                        except Exception:
                            pass
                    
                except ImportError:
                    results['error'] = "JAX/Flax not installed"
                    results['execution_status'] = 'failed'
                except Exception as e:
                    results['error'] = f"Flax load failed: {str(e)}"
                    results['execution_status'] = 'failed'
                if 'model' in locals():
                    del model
                import gc
                gc.collect()
       # XGBOOST
       elif file_type == 'xgboost':
                print("Loading XGBoost model...")
                results['loading_method'] = 'xgboost'
                
                try:
                    import xgboost as xgb
                    
                    model = xgb.Booster()
                    model.load_model(file_path)
                    model = wrap_model_for_execution(model)
                    results['execution_status'] = 'model_loaded'
                    
                    # Create tabular input
                    test_input = np.random.randn(10, 100).astype(np.float32)
                    dmatrix = xgb.DMatrix(test_input)
                    
                    # Predict
                    predictions = model.predict(dmatrix)
                    results['output'] = f"XGBoost predictions shape: {predictions.shape}"
                    results['execution_status'] = 'success'
                    
                except ImportError:
                    results['error'] = "xgboost not installed"
                    results['execution_status'] = 'failed'
                except Exception as e:
                    results['error'] = f"XGBoost failed: {str(e)}"
                    results['execution_status'] = 'failed'
                if 'model' in locals():
                    del model
                import gc
                gc.collect()
       
       
       # LIGHTGBM
       elif file_type == 'lightgbm':
                print("Loading LightGBM model...")
                results['loading_method'] = 'lightgbm'
                
                try:
                    import lightgbm as lgb
                    
                    model = lgb.Booster(model_file=file_path)
                    model = wrap_model_for_execution(model)
                    results['execution_status'] = 'model_loaded'
                    
                    # Create tabular input
                    test_input = np.random.randn(10, model.num_feature()).astype(np.float32)
                    
                    # Predict
                    predictions = model.predict(test_input)
                    results['output'] = f"LightGBM predictions shape: {predictions.shape}"
                    results['execution_status'] = 'success'
                    
                except ImportError:
                    results['error'] = "lightgbm not installed"
                    results['execution_status'] = 'failed'
                except Exception as e:
                    results['error'] = f"LightGBM failed: {str(e)}"
                    results['execution_status'] = 'failed'
                
                if 'model' in locals():
                    del model
                import gc
                gc.collect()
       # CATBOOST
       elif file_type == 'catboost':
                print("Loading CatBoost model...")
                results['loading_method'] = 'catboost'
                
                try:
                    from catboost import CatBoost
                    
                    model = CatBoost()
                    model.load_model(file_path)
                    model = wrap_model_for_execution(model)
                    results['execution_status'] = 'model_loaded'
                    
                    # Create tabular input
                    test_input = np.random.randn(10, 100).astype(np.float32)
                    
                    # Predict
                    predictions = model.predict(test_input)
                    results['output'] = f"CatBoost predictions shape: {predictions.shape}"
                    results['execution_status'] = 'success'
                    
                except ImportError:
                    results['error'] = "catboost not installed"
                    results['execution_status'] = 'failed'
                except Exception as e:
                    results['error'] = f"CatBoost failed: {str(e)}"
                    results['execution_status'] = 'failed'
                
                if 'model' in locals():
                    del model
                import gc
                gc.collect()
       # SCIKIT-LEARN
       elif file_type == 'sklearn':
                print("Loading scikit-learn model...")
                results['loading_method'] = 'sklearn'
                
                try:
                    import joblib
                    
                    model = joblib.load(file_path)
                    model = wrap_model_for_execution(model)
                    results['execution_status'] = 'model_loaded'
                    results['output'] = f"Sklearn model loaded: {type(model).__name__}"
                    
                    # Try to predict
                    if hasattr(model, 'predict'):
                        test_input = np.random.randn(10, 100).astype(np.float32)
                        try:
                            predictions = model.predict(test_input)
                            results['output'] += f" | Predictions: {predictions.shape}"
                            results['execution_status'] = 'success'
                        except Exception:
                            # Try with different input shape
                            test_input = np.random.randn(10, 10).astype(np.float32)
                            try:
                                predictions = model.predict(test_input)
                                results['output'] += f" | Predictions: {predictions.shape}"
                                results['execution_status'] = 'success'
                            except Exception:
                                pass
                    
                except ImportError:
                    results['error'] = "joblib not installed"
                    results['execution_status'] = 'failed'
                except Exception as e:
                    # Might be malicious pickle
                    error_str = str(e)
                    if any(x in error_str.lower() for x in ['exec', '__reduce__', 'eval']):
                        results['warnings'].append("Malicious code detected in joblib file")
                        results['execution_status'] = 'malicious_executed'
                        results['output'] = f"Malicious code executed: {error_str[:100]}"
                    else:
                        results['error'] = f"Sklearn failed: {error_str}"
                        results['execution_status'] = 'failed'
                if 'model' in locals():
                    del model
                import gc
                gc.collect()
       
       # COREML
       elif file_type == 'coreml':
                print("Loading CoreML model...")
                results['loading_method'] = 'coreml'
                
                try:
                    import coremltools as ct
                    
                    model = ct.models.MLModel(file_path)
                    model = wrap_model_for_execution(model)
                    results['execution_status'] = 'model_loaded'
                    
                    # Get input description
                    spec = model.get_spec()
                    input_desc = spec.description.input[0] if spec.description.input else None
                    
                    results['output'] = f"CoreML model loaded: {model}"
                    
                    # Note: Running CoreML models requires macOS
                    if sys.platform == 'darwin':
                        try:
                            # Create appropriate input
                            if input_desc and 'image' in input_desc.name.lower():
                                from PIL import Image
                                test_image = Image.new('RGB', (224, 224))
                                prediction = model.predict({'image': test_image})
                            else:
                                # Try generic input
                                test_input = np.random.randn(1, 100).astype(np.float32)
                                prediction = model.predict({'input': test_input})
                            
                            results['output'] += f" | Prediction made"
                            results['execution_status'] = 'success'
                        except Exception:
                            pass
                    else:
                        results['output'] += " | Cannot execute (requires macOS)"
                    
                except ImportError:
                    results['error'] = "coremltools not installed"
                    results['execution_status'] = 'failed'
                except Exception as e:
                    results['error'] = f"CoreML failed: {str(e)}"
                    results['execution_status'] = 'failed'
               
                if 'model' in locals():
                    del model
                import gc
                gc.collect()
       # MXNET
       elif file_type == 'mxnet':
                print("Loading MXNet model...")
                results['loading_method'] = 'mxnet'
                
                try:
                    import mxnet as mx
                    
                    # Find symbol file
                    symbol_file = None
                    for f in model_info['files']:
                        if f.endswith('symbol.json'):
                            symbol_file = f
                            break
                    
                    if symbol_file:
                        sym = mx.sym.load(os.path.join(model_folder, symbol_file))
                        # Load parameters
                        params_file = file_path
                        save_dict = mx.nd.load(params_file)
                        
                        # Create the actual executable model (module)
                        mod = mx.mod.Module(symbol=sym, context=mx.cpu())
                        mod.bind(data_shapes=[('data', (1, 3, 224, 224))])  # Example shape
                        mod.init_params()
                        mod.set_params(arg_params=save_dict['arg'], aux_params=save_dict['aux'])

                         # NOW wrap the module
                        mod = wrap_model_for_execution(mod)
                        results['execution_status'] = 'model_loaded'
            
                        # Execute with dummy input
                        input_data = mx.nd.random.uniform(shape=(1, 3, 224, 224))
                        mod.forward(mx.io.DataBatch([input_data]))
                        output = mod.get_outputs()[0]
                        results['output'] = f"MXNet executed: {output.shape}"
                        results['execution_status'] = 'success'
                        
                        # Note: Full execution would require creating module/gluon model
                        
                except ImportError:
                    results['error'] = "mxnet not installed"
                    results['execution_status'] = 'failed'
                except Exception as e:
                    results['error'] = f"MXNet failed: {str(e)}"
                    results['execution_status'] = 'failed'
                
                if 'model' in locals():
                    del model
                import gc
                gc.collect()
       # PADDLEPADDLE
       elif file_type == 'paddle':
                print("Loading PaddlePaddle model...")
                results['loading_method'] = 'paddle'
                
                try:
                    import paddle
                    
                    # Load model
                    model = paddle.jit.load(file_path.replace('.pdiparams', '').replace('.pdmodel', ''))
                    model = wrap_model_for_execution(model)
                    results['execution_status'] = 'model_loaded'
                    results['output'] = "PaddlePaddle model loaded"
                    
                    # Try inference
                    test_input = paddle.randn([1, 3, 224, 224])
                    output = model(test_input)
                    results['output'] += f" | Output: {output.shape}"
                    results['execution_status'] = 'success'
                    
                except ImportError:
                    results['error'] = "paddlepaddle not installed"
                    results['execution_status'] = 'failed'
                except Exception as e:
                    results['error'] = f"PaddlePaddle failed: {str(e)}"
                    results['execution_status'] = 'failed'
                
                if 'model' in locals():
                    del model
                import gc
                gc.collect()
       # TENSORRT
       elif file_type == 'tensorrt':
                print("Loading TensorRT engine...")
                results['loading_method'] = 'tensorrt'
                
                try:
                    import tensorrt as trt
                    import pycuda.driver as cuda
                    import pycuda.autoinit
                    
                    # Load engine
                    with open(file_path, 'rb') as f:
                        engine_data = f.read()
                    
                    runtime = trt.Runtime(trt.Logger(trt.Logger.WARNING))
                    engine = runtime.deserialize_cuda_engine(engine_data)
                    engine = wrap_model_for_execution(engine)
                    results['execution_status'] = 'model_loaded'
                    results['output'] = "TensorRT engine loaded"
                    
                    # Note: Full execution requires CUDA setup
                    # context = engine.create_execution_context()
                    # context = wrap_model_for_execution(context)
                except ImportError:
                    results['error'] = "tensorrt/pycuda not installed"
                    results['execution_status'] = 'failed'
                except Exception as e:
                    results['error'] = f"TensorRT failed: {str(e)}"
                    results['execution_status'] = 'failed'
                
                if 'model' in locals():
                    del model
                import gc
                gc.collect()
       
       # ARCHIVES
       elif file_type == 'archive':
                import zipfile
                import tempfile
                
                print(f"Processing archive: {file}...")
                results['loading_method'] = 'archive'
                
                # Create temp directory for extraction
                with tempfile.TemporaryDirectory() as temp_dir:
                    try:
                        if file.endswith('.zip'):
                            with zipfile.ZipFile(file_path, 'r') as zf:
                                zf.extractall(temp_dir)
                        elif file.endswith(('.tar', '.tar.gz')):
                            import tarfile
                            with tarfile.open(file_path, 'r:*') as tf:
                                tf.extractall(temp_dir)
                        
                        # Recursively analyze extracted content
                        extracted_results = analyze_and_execute_model(temp_dir)
                        results['output'] = f"Archive analyzed: {extracted_results}"
                        results['execution_status'] = 'archive_analyzed'
                        
                    except Exception as e:
                        results['error'] = f"Archive processing failed: {str(e)}"
                        results['execution_status'] = 'failed'
                if 'model' in locals():
                    del model
                import gc
                gc.collect()

       
       # TRANSFORMERS MODELS
       elif file_type  =='pytorch/transformers':
            print("Loading as HuggingFace transformers model...")
            results['loading_method'] = 'huggingface'
            model_file = None
            for fname in os.listdir(model_folder):
                if fname.endswith(('.bin', '.safetensors')):
                   model_file = os.path.join(model_folder, fname)
                   break

            if not model_file:
               raise FileNotFoundError(f"No model weight file (.bin or .safetensors) found in {model_folder}")

            print("\n" + "="*70)
            print("[Inspector] Inspecting model file")
            print("="*70)
    
            import zipfile
            import pickletools
            import io
 
            with open(model_file, 'rb') as f:
              header = f.read(100)
              print(f"\n File header (first 100 bytes):")
              print(f"   Hex: {header[:50].hex()}")
              print(f"   ASCII: {header[:50]}")
    
  
            if header[:2] == b'PK':
              print(f"\n File is a ZIP archive")
              try:
                with zipfile.ZipFile(model_file, 'r') as zf:
                  all_files = zf.namelist()
                  print(f"   Total files in archive: {len(all_files)}")
                  print(f"   Files:")
                  for fname in all_files:
                    info = zf.getinfo(fname)
                    print(f"      - {fname} ({info.file_size} bytes)")
                
                  # 4. Inspect the pickle file(s)
                  pickle_files = [f for f in all_files if f.endswith('.pkl')]
                  print(f"\n Pickle files found: {pickle_files}")
                
                  for pkl_file in pickle_files:
                    print(f"\n   Analyzing: {pkl_file}")
                    pkl_data = zf.read(pkl_file)
                    print(f"   Size: {len(pkl_data)} bytes")
                     
                    # Try to disassemble the pickle opcodes
                    print(f"\n  [Inspector] Pickle opcodes:")
                    print("   " + "-"*60)
                    try:
                        pickletools.dis(io.BytesIO(pkl_data), annotate=1)
                    except Exception as e:
                        print(f"   Error disassembling: {e}")
                    print("   " + "-"*60)
                    
                    # Look for suspicious patterns
                    print(f"\n  [Inspector] Security scan:")
                    suspicious_patterns = {
                        b'posix': 'POSIX module access',
                        b'system': 'system() call',
                        b'subprocess': 'subprocess execution',
                        b'eval': 'eval() execution',
                        b'exec': 'exec() execution',
                        b'__import__': 'dynamic import',
                        b'__reduce__': 'pickle reduce (can execute code)',
                        b'__setstate__': 'pickle setstate',
                        b'cowsay': 'cowsay reference',
                        b'os': 'OS module',
                        b'socket': 'Network socket',
                        b'urllib': 'URL request',
                        b'requests': 'HTTP request',
                    }
                    
                    found_patterns = []
                    for pattern, description in suspicious_patterns.items():
                        if pattern in pkl_data:
                            found_patterns.append(f" {description}: '{pattern.decode()}' found")
                    
                    if found_patterns:
                        print("   Suspicious patterns detected:")
                        for p in found_patterns:
                            print(p)
                    else:
                        print("    No obvious suspicious patterns detected")
        
              except Exception as e:
                print(f"   Error inspecting ZIP: {e}")
    
            else:
             print(f"\n File is not a ZIP (raw pickle or other format)")
             # Try to analyze as raw pickle
             try:
              with open(model_file, 'rb') as f:
                pkl_data = f.read()
                print(f"\n    [Inspector] Pickle opcodes (first 2KB):")
                print("   " + "-"*60)
                pickletools.dis(io.BytesIO(pkl_data[:2048]), annotate=1)
                print("   " + "-"*60)
             except Exception as e:
                print(f"   Error analyzing: {e}")
    
            print("="*70)
            print("[Inspector] Inspection complete")
            print("="*70 + "\n")
            try:
                bin_contents = None
                exit_code = None
                # SAFE INSPECTION: Load the bin file directly to see what it contains
                print("    Inspecting pytorch_model.bin contents...")
                try:
                     bin_contents = torch.load(model_file, map_location='cpu')
                except SystemExit as se:
                     exit_code = se.code
                     print(f"    [Inspector] Pickle called exit({exit_code})")
                
                
                     if monitor.bpf and monitor.monitoring_active:
                        print(f"[Inspector] Malicious exit detected, flushing perf buffer...")
                        for _ in range(30):
                          try:
                             monitor.bpf.perf_buffer_poll(timeout=100)
                          except Exception:
                             pass
                        print(f"[Inspector] Events captured: {len(monitor.loading_events)}")
        
                     results['execution_status'] = 'malicious_exit'
                     results['warnings'].append(f'Pickle called exit({exit_code})')
                     results['output'] = f'Malicious pickle executed exit({exit_code})'
                     bin_contents = None
                
                if monitor.bpf and monitor.monitoring_active:
                   for _ in range(15):
                       monitor.bpf.perf_buffer_poll(timeout=50)
                if isinstance(bin_contents, dict):
                    print("     Contains state_dict (normal case)")
                    # Normal case - use HuggingFace loader
                    from transformers import AutoModel, AutoTokenizer
                    model = AutoModel.from_pretrained(model_folder)
                    model = wrap_model_for_execution(model)
                    results['execution_status'] = 'model_loaded'
                    
                    if requirements['input_type'] == 'text' and model_info['has_tokenizer']:
                        tokenizer = AutoTokenizer.from_pretrained(model_folder)
                        inputs = tokenizer(input_data, return_tensors="pt")
                        
                        with torch.no_grad():
                            output = model(**inputs)
                            results['output'] = f"HF Model output shape: {output.last_hidden_state.shape if hasattr(output, 'last_hidden_state') else 'Success'}"
                            results['execution_status'] = 'success'
                
                else:
                    # MALICIOUS CASE: Contains a model object instead of state_dict
                    print(f"  [Inspector] Contains {type(bin_contents)} object instead of state_dict")
                    results['warnings'].append(f"pytorch_model.bin contains {type(bin_contents)} object, not state_dict")
                    results['loading_method'] = 'direct_malicious_model'
                    
                    # The malicious model is already loaded (code already executed!)
                    model = bin_contents
                    model = wrap_model_for_execution(model)
                    results['execution_status'] = 'malicious_model_loaded'
                    results['output'] = f"Malicious model loaded directly: {type(model)}"
                    
                    # Try to execute it
                    if requirements['input_type'] == 'text' and model_info['has_tokenizer']:
                        print("    Attempting to run malicious model with tokenizer...")
                        try:
                            from transformers import AutoTokenizer
                            tokenizer = AutoTokenizer.from_pretrained(model_folder)
                            inputs = tokenizer(input_data, return_tensors="pt")
                            
                            # Try different execution methods for the malicious model
                            execution_attempts = []
                            
                            # Method 1: Direct call
                            try:
                                with torch.no_grad():
                                    if callable(model):
                                        output = model(**inputs)
                                    elif hasattr(model, '__call__'):
                                        output = model(**inputs)
                                    else:
                                        output = model(inputs['input_ids'])
                                
                                execution_attempts.append("Direct call: SUCCESS")
                                results['output'] += f" | Executed with tokenized input: {output.shape if hasattr(output, 'shape') else type(output)}"
                                results['execution_status'] = 'success'
                                
                            except Exception as e1:
                                execution_attempts.append(f"Direct call failed: {str(e1)[:50]}")
                                
                                # Method 2: Try forward method
                                try:
                                    with torch.no_grad():
                                        output = model.forward(**inputs)
                                    execution_attempts.append("Forward method: SUCCESS")
                                    results['output'] += f" | Forward pass: {output.shape if hasattr(output, 'shape') else type(output)}"
                                    results['execution_status'] = 'success'
                                    
                                except Exception as e2:
                                    execution_attempts.append(f"Forward failed: {str(e2)[:50]}")
                                    
                                    # Method 3: Try with just input_ids
                                    try:
                                        with torch.no_grad():
                                            output = model(inputs['input_ids'])
                                        execution_attempts.append("Input IDs only: SUCCESS")
                                        results['output'] += f" | Input IDs execution: {output.shape if hasattr(output, 'shape') else type(output)}"
                                        results['execution_status'] = 'success'
                                        
                                    except Exception as e3:
                                        execution_attempts.append(f"Input IDs failed: {str(e3)[:50]}")
                            
                            results['execution_attempts'] = execution_attempts
                            print(f"    Execution attempts: {execution_attempts}")
                            
                        except Exception as tokenizer_error:
                            results['output'] += f" | Tokenizer error: {str(tokenizer_error)}"
                    
                    elif input_data is not None:
                        # Try with direct tensor input
                        print("    Attempting to run malicious model with tensor input...")
                        try:
                            with torch.no_grad():
                                if callable(model):
                                    output = model(input_data)
                                elif hasattr(model, 'forward'):
                                    output = model.forward(input_data)
                                else:
                                    output = model(input_data)
                            
                            results['output'] += f" | Tensor execution: {output.shape if hasattr(output, 'shape') else type(output)}"
                            results['execution_status'] = 'success'
                            
                        except Exception as tensor_error:
                            results['output'] += f" | Tensor execution failed: {str(tensor_error)}"
                
            except Exception as inspection_error:
                print(f"    Failed to inspect pytorch_model.bin: {inspection_error}")
                
                # Fallback: Try original HuggingFace method
                try:
                    from transformers import AutoModel, AutoTokenizer
                    model = AutoModel.from_pretrained(model_folder)
                    model = wrap_model_for_execution(model)
                    results['execution_status'] = 'model_loaded'
                    results['loading_method'] = 'huggingface_fallback'
                    
                except Exception as hf_error:
                    results['error'] = f"Both inspection and HuggingFace loading failed: {str(hf_error)}"
                    results['execution_status'] = 'failed'
                    
            if 'model' in locals():
               del model
            import gc
            gc.collect()      
            
       elif file_type  == 'torch_package':
            print(" Loading torch.package model (POTENTIALLY DANGEROUS!)...")
            results['loading_method'] = 'torch_package'
            
            model_file = os.path.join(model_folder, file)
            
            # Track if malicious code has already executed
            malicious_executed = False
            
            # First, create stub classes for common malicious models
            class MaliciousModelStub:
                def __init__(self, *args, **kwargs):
                    print(f"[Inspector] Stub model initialized")
                    self.args = args
                    self.kwargs = kwargs
                
                def __call__(self, *args, **kwargs):
                    print(f"    [Inspector] Stub model called")
                    if args and hasattr(args[0], 'shape'):
                        batch_size = args[0].shape[0] if len(args[0].shape) > 0 else 1
                        return torch.randn(batch_size, 10)
                    return torch.randn(1, 10)
                
                def forward(self, *args, **kwargs):
                    return self.__call__(*args, **kwargs)
                
            # Register potential class names
            import __main__
            for class_name in ['TheModelClass', 'ModelClass', 'Model', 'MaliciousModel', 'Net']:
                setattr(__main__, class_name, MaliciousModelStub)
                globals()[class_name] = MaliciousModelStub
            
            # Try multiple loading strategies
            loading_attempts = []
            
            # Method 1: Try torch.package.PackageImporter
            try:
                from torch.package import PackageImporter
                
                # Try to use PackageImporter
                try:
                    with PackageImporter(model_file) as importer:
                        # Try to list contents (might fail)
                        try:
                            resources = importer.file_structure()
                            print(f"    Package contents preview: {str(resources)[:200]}")
                        except Exception:
                            pass
                        
                        # Common torch.package export names and paths
                        pkl_files = model_info['bin_classification'].get(file, {}).get('pickle_files', [])
                        module_pickles = model_info['bin_classification'].get(file, {}).get('module_pickles', {})

                        # Build possible load paths from actual discovered files
                        possible_loads = []

                        for module, pickles in module_pickles.items():
                            for pkl in pickles:
                                resource = pkl.split('/')[-1]
                                # Try with and without .pkl extension
                                possible_loads.append((module, resource))
                                if resource.endswith('.pkl'):
                                   possible_loads.append((module, resource[:-4]))
                        
                        # Add direct pickle paths
                        for pkl in pkl_files:
                            if '/' in pkl:
                               parts = pkl.rsplit('/', 1)
                               module = parts[0]
                               resource = parts[1]
                               possible_loads.append((module, resource))
                               if resource.endswith('.pkl'):
                                  possible_loads.append((module, resource[:-4]))
                            else:
                               possible_loads.append(('', pkl))
                               if pkl.endswith('.pkl'):
                                  possible_loads.append(('', pkl[:-4]))

                        
                        possible_loads.extend([('__main__', 'model'), ('model', 'model'),])
                        seen = set()
                        unique_loads = []
                        for item in possible_loads:
                            if item not in seen:
                               seen.add(item)
                               unique_loads.append(item)
                        possible_loads = unique_loads
                
                        print(f"    Trying {len(possible_loads)} possible load paths...")
                
                        model = None
                        for package_path, resource_name in possible_loads:
                            try:
                                model = importer.load_pickle(package_path, resource_name)
                                model = wrap_model_for_execution(model)
                                loading_attempts.append(f"PackageImporter({package_path}/{resource_name}): SUCCESS")
                                break
                            except Exception as e:
                               if "No module named" not in str(e) and "not found" not in str(e).lower():
                                   print(f"      Failed {package_path}/{resource_name}: {str(e)[:30]}")
                               continue
                        
                        if model is not None:
                            results['execution_status'] = 'model_loaded'
                            results['output'] = f"torch.package model loaded: {type(model)}"
                            malicious_executed = True  # Code likely executed during load
                            
                            # Try to run model
                            if callable(model) and input_data is not None:
                                try:
                                    with torch.no_grad():
                                        if requirements['input_type'] == 'text':
                                            dummy_input = torch.randint(0, 1000, (1, 10))
                                            output = model(dummy_input)
                                        else:
                                            output = model(input_data)
                                    results['output'] += f", executed: {output.shape if hasattr(output, 'shape') else type(output)}"
                                    results['execution_status'] = 'success'
                                except Exception:
                                    pass
                                    
                except Exception as pkg_error:
                    loading_attempts.append(f"PackageImporter: FAILED - {str(pkg_error)[:50]}")
                    
            except ImportError:
                loading_attempts.append("PackageImporter: Not available")
            
            # Method 2: Try as regular torch file (some torch.packages can be loaded this way)
            if results['execution_status'] == 'not_attempted':
                try:
                    print("    Trying torch.load for torch.package file...")
                    
                    # Create a custom unpickler that handles torch.package specifics
                    original_load = torch.load
                    
                    def custom_torch_load(f, *args, **kwargs):
                        # This might trigger malicious code
                        try:
                            return original_load(f, *args, **kwargs)
                        except Exception as e:
                            # If it fails with package-specific errors, we know code executed
                            if "PytorchStreamReader" in str(e) or "invalid header" in str(e):
                                # The malicious code likely already executed
                                print("  Malicious code likely executed during load attempt")
                                raise e
                            raise e
                    
                    model = custom_torch_load(model_file, map_location='cpu')
                    model = wrap_model_for_execution(model)
                    loading_attempts.append(f"torch.load: SUCCESS - {type(model)}")
                    results['execution_status'] = 'model_loaded'
                    results['output'] = f"Loaded via torch.load: {type(model)}"
                   
                    if isinstance(model, (dict, OrderedDict)):
                       if model_info.get('has_config') and model_info.get('config_data'):
                          print(f"    Loaded state_dict via torch.load, creating HuggingFace model...")
                          try:
                            from transformers import AutoModel, AutoTokenizer
                            base_model = AutoModel.from_pretrained(model_folder)
                            base_model = wrap_model_for_execution(base_model)
                            if model_info.get('has_tokenizer'):
                               tokenizer = AutoTokenizer.from_pretrained(model_folder)
                               inputs = tokenizer("Test text", return_tensors="pt")
                               with torch.no_grad():
                                    output = base_model(**inputs)
                               results['output'] += f", HF model executed: {output.last_hidden_state.shape}"
                               results['execution_status'] = 'success'
                          except Exception as hf_err:
                                 results['output'] += f", HF execution failed: {str(hf_err)[:30]}"
                       else:
                          results['output'] += f", got dict with {len(model)} keys"
                    elif callable(model) and input_data is not None:
                        with torch.no_grad():
                            output = model(input_data)
                        results['output'] += f", executed: {output.shape if hasattr(output, 'shape') else type(output)}"
                        results['execution_status'] = 'success'
                        
                except Exception as torch_error:
                    error_str = str(torch_error)
                    loading_attempts.append(f"torch.load: FAILED - {error_str[:50]}")
                    
                    # Check if malicious code executed before failure
                    if "PytorchStreamReader" in error_str or "invalid header" in error_str:
                       
                        results['warnings'].append("Malicious code executed during failed load attempt")
            
            # Method 3: Direct ZIP inspection and extraction
            if results['execution_status'] in ['not_attempted', 'failed']:
                try:
                    print("    Trying direct ZIP extraction...")
                    import zipfile
                    import pickle
                    import io
                    
                    with zipfile.ZipFile(model_file, 'r') as zf:
                        
                        all_files = zf.namelist()
                        pkl_files = [f for f in all_files if '.pkl' in f]
                        py_files = [f for f in all_files if '.py' in f]
                        
                        print(f"    ZIP contents: {len(all_files)} files, {len(pkl_files)} pickles, {len(py_files)} python files")
                        
                        # If there are .py files, this definitely contains code
                        if py_files:
                            results['warnings'].append(f"Contains Python code files: {py_files[:3]}")
                            
                            # Try to read and show the Python code (for analysis)
                            for py_file in py_files[:2]:  # Just first 2 files
                                try:
                                    with zf.open(py_file) as f:
                                        code = f.read().decode('utf-8', errors='ignore')
                                        print(f"    Python file {py_file} preview: {code[:100]}...")
                                except Exception:
                                    pass
                        main_pickle = model_info['bin_classification'].get(file, {}).get('main_pickle')
                        def pkl_priority(pkl_path):
                           if main_pickle and pkl_path == main_pickle:
                              return 0
                           elif 'archive/' in pkl_path:
                              return 1
                           elif '/' not in pkl_path:
                              return 2
                           elif pkl_path.count('/') == 1:
                              return 3
                           else:
                              return 4

                        pkl_files_sorted = sorted(pkl_files, key=pkl_priority)
                        # Try to load pickle files with custom unpickler
                        model_loaded = False
                        for pkl_file in pkl_files_sorted:
                            if model_loaded:
                               break
                            try:
                                with zf.open(pkl_file) as f:
                                    # Custom unpickler for safety
                                    class CustomUnpickler(pickle.Unpickler):
                                        def find_class(self, module, name):
                                            # Log what's being unpickled
                                            print(f"    Unpickling {module}.{name}")
                                            
                                            # Return stub for unknown classes
                                            if module == '__main__' or module == 'torch.package':
                                                return MaliciousModelStub
                                            
                                            try:
                                                return super().find_class(module, name)
                                            except Exception:
                                                return MaliciousModelStub
                                    
                                    unpickler = CustomUnpickler(io.BytesIO(f.read()))
                                    obj = unpickler.load()
                                    
                                    loading_attempts.append(f"ZIP/{pkl_file}: Loaded {type(obj)}")
                                    
                                    if obj is not None:
                                      model = obj
                                      model = wrap_model_for_execution(model)
                                      results['output'] = f"Extracted from {pkl_file}: {type(obj)}"
                                      results['execution_status'] = 'model_loaded'
                                      model_loaded = True
                                      if isinstance(obj, (dict, OrderedDict)):
                                         # It's a state_dict - need to create actual model
                                         if model_info.get('has_config') and model_info.get('config_data'):
                                            print(f"    Loaded state_dict from {pkl_file}, creating model...")
                                            try:
                                              from transformers import AutoModel, AutoTokenizer
                                              base_model = AutoModel.from_pretrained(model_folder)
                                              base_model = wrap_model_for_execution(base_model)
                                              if model_info.get('has_tokenizer'):
                                                 tokenizer = AutoTokenizer.from_pretrained(model_folder)
                                                 inputs = tokenizer("Test text", return_tensors="pt")
                                                 with torch.no_grad():
                                                      output = base_model(**inputs)
                                                 results['output'] += f", HF model executed: {output.last_hidden_state.shape}"
                                                 results['execution_status'] = 'success'
                                            except Exception as hf_err:
                                                 results['output'] += f", HF execution failed: {str(hf_err)[:30]}"
                                         else:
                                            # Just a dict, can't execute
                                            results['output'] += f", got dict with {len(obj)} keys"
                                      
                                      
                                      
                                      # Try to execute if callable
                                      if callable(obj):
                                        try:
                                          with torch.no_grad():
                                            if requirements['input_type'] == 'text':
                                                test_input = torch.randint(0, 50000, (1, 20))
                                            else:
                                                test_input = input_data if input_data is not None else torch.randn(1, 100)
                                            
                                            output = obj(test_input)
                                            results['output'] += f", executed: {output.shape if hasattr(output, 'shape') else type(output)}"
                                            results['execution_status'] = 'success'
                                        except Exception as exec_err:
                                            results['output'] += f", execution failed: {str(exec_err)[:30]}"
                                
                                      if isinstance(obj, MaliciousModelStub):
                                      
                                         results['warnings'].append("Malicious model class detected and neutralized")
                                
                                      break
                                        
                            except Exception as e:
                                  loading_attempts.append(f"ZIP/{pkl_file}: Failed - {str(e)[:30]}")
                                  if any(x in str(e).lower() for x in ['exec', 'eval', '__reduce__']):
                                     malicious_executed = True
                except zipfile.BadZipFile:
                       loading_attempts.append("Not a valid ZIP file")                
                except Exception as zip_error:
                    loading_attempts.append(f"ZIP extraction: FAILED - {str(zip_error)[:50]}")
            
            # Compile results
            if malicious_executed:
                 if results['execution_status'] == 'not_attempted':
                    results['execution_status'] = 'malicious_executed'
                 elif results['execution_status'] == 'model_loaded':
                    results['execution_status'] = 'malicious_loaded'
                 elif results['execution_status'] == 'success':
                    results['execution_status'] = 'malicious_success'
        
                 results['warnings'].append("Malicious code was executed during loading attempts")
                 if not results['output']:
                    results['output'] = "Malicious code executed but no model was successfully loaded"
    
            
            # Add loading attempts to output
            if loading_attempts:
                attempts_str = " | ".join(loading_attempts)
                if results['output']:
                    results['output'] += f" | Attempts: {attempts_str}"
                else:
                    results['output'] = f"Loading attempts: {attempts_str}"
            
            # If nothing worked, mark as failed
            if results['execution_status'] == 'not_attempted':
                results['execution_status'] = 'failed'
                results['error'] = "All loading methods failed"
            if 'model' in locals():
               del model
            import gc
            gc.collect()
       
       
       elif file_type == 'torchscript':
             print("Loading TorchScript model...")
             results['loading_method'] = 'torchscript'
    
  
             model_file = os.path.join(model_folder, file)
    
             try:
               model = torch.jit.load(model_file, map_location='cpu')
               model = wrap_model_for_execution(model)
               results['execution_status'] = 'model_loaded'
        
               if input_data is not None:
                  with torch.no_grad():
                       output = model(input_data)
                  results['output'] = f"TorchScript output: {output.shape if hasattr(output, 'shape') else type(output)}"
                  results['execution_status'] = 'success'
               else:
                  results['output'] = "TorchScript model loaded successfully"
            
             except Exception as e:
                 results['error'] = f"Failed to load TorchScript: {str(e)}"
                 results['execution_status'] = 'failed'
             
             if 'model' in locals():
               del model
             import gc
             gc.collect()
            
       
       
       
       elif file_type == 'pytorch_checkpoint':
            print("Loading PyTorch checkpoint...")
            results['loading_method'] = 'pytorch_checkpoint'
    
            model_file = os.path.join(model_folder, file)
            try:
              checkpoint = torch.load(model_file, map_location='cpu')
        
              # Checkpoints usually contain model_state_dict and optimizer_state_dict
              if isinstance(checkpoint, dict):
                if 'model_state_dict' in checkpoint:
                   # Need to create model from config if available
                   if model_info.get('has_config'):
                    from transformers import AutoModel
                    model = AutoModel.from_pretrained(model_folder)
                    model.load_state_dict(checkpoint['model_state_dict'])
                    model = wrap_model_for_execution(model)
                   
                    results['execution_status'] = 'model_loaded'
                   else:
                    results['output'] = "Checkpoint loaded but no model config found"
                    results['execution_status'] = 'model_loaded'
              else:
                # Might be just a state dict
                model = checkpoint
                model = wrap_model_for_execution(model) if callable(checkpoint) else None
                results['execution_status'] = 'model_loaded'
            except Exception as e:
               results['error'] = f"Failed to load checkpoint: {str(e)}"
               results['execution_status'] = 'failed'
            if 'model' in locals():
                del model
            import gc
            gc.collect()
       
       elif file_type == 'pytorch_quantized':
           print("Loading quantized PyTorch model...")
           results['loading_method'] = 'pytorch_quantized'
           model_file = os.path.join(model_folder, file)
           try:
             model = torch.load(model_file, map_location='cpu')
             model = wrap_model_for_execution(model)
             results['execution_status'] = 'model_loaded'
             # Try execution with appropriate input
             if callable(model) and input_data is not None:
               with torch.no_grad():
                  output = model(input_data)
               results['output'] = f"Quantized model executed: {output.shape if hasattr(output, 'shape') else type(output)}"
               results['execution_status'] = 'success'
           except Exception as e:
                results['error'] = f"Failed to load quantized model: {str(e)}"
                results['execution_status'] = 'failed'
       
       
           if 'model' in locals():
               del model
           import gc
           gc.collect()
       
       
       
       
       elif file_type  == 'pytorch_bin_unknown':
        print("️  Unknown pytorch_model.bin format, trying multiple methods...")
        results['loading_method'] = 'fallback_attempts'
    
        model_file = os.path.join(model_folder, file) 
        attempts = []
        classification = model_info.get('bin_classification', {}).get(file, {})
        kind = classification.get('kind', 'unknown')
        if kind in ['raw_pickle', 'raw_binary', 'unknown_zip'] or structure.get('architecture') == 'raw_pickle_format':
           print("    Detected raw pickle format - treating as potentially malicious pickle...")
           results['warnings'].append("Raw pickle format detected")
        
           try:
            import io as io_module
            import contextlib
            
            stdout_capture = io_module.StringIO()
            
            with contextlib.redirect_stdout(stdout_capture):
                model = torch.load(model_file, map_location='cpu')
                model = wrap_model_for_execution(model)
            captured = stdout_capture.getvalue()
            if captured:
                print(f"     [Inspector] Output captured: {captured}")
                results['warnings'].append("Malicious code executed during load")
                results['execution_status'] = 'malicious_executed'
            else:
                results['execution_status'] = 'model_loaded'
                
            attempts.append(f"Raw pickle load: SUCCESS - {type(model)}")
            
            # Try to execute if callable
            if callable(model) and input_data is not None:
                try:
                    with torch.no_grad():
                        if requirements['input_type'] == 'text':
                            dummy_input = torch.randint(0, 50000, (1, 20))
                            output = model(dummy_input)
                        else:
                            output = model(input_data)
                    attempts.append(f"Execution: {output.shape if hasattr(output, 'shape') else type(output)}")
                    results['execution_status'] = 'malicious_success' if results.get('execution_status') == 'malicious_executed' else 'success'
                except Exception as exec_err:
                    attempts.append(f"Execution failed: {str(exec_err)[:30]}")
                    
           except Exception as e:
            error_msg = str(e)
            attempts.append(f"Raw pickle: FAILED - {error_msg}")
            
            # Check if malicious code executed before failure
            if "PytorchStreamReader" in error_msg or "Invalid magic number" in error_msg:
                results['execution_status'] = 'malicious_executed'
                results['warnings'].append("Malicious code executed but no valid model returned")
            else:
                results['execution_status'] = 'failed'
    
       
       
        elif kind in ['torch_package', 'torch_package_variant'] and classification.get('has_custom_class'):
                print("    Detected torch.package with custom classes, creating stub class...")

                
                # Create a dynamic stub class for TheModelClass or any custom class
                import types
                
                # Create a generic malicious model class that captures any initialization
                class MaliciousModelStub:
                    def __init__(self, *args, **kwargs):
                        print(f"     [Inspector] Stub model initialized")
                        self.args = args
                        self.kwargs = kwargs
                        # Store any passed objects for analysis
                        for key, value in kwargs.items():
                            setattr(self, key, value)
                    
                    def __call__(self, *args, **kwargs):
                        print(f"     [Inspector] Stub model called with {len(args)} args, kwargs={kwargs.keys() if kwargs else 'none'}")
                        # Return dummy output
                        if args and hasattr(args[0], 'shape'):
                            # If input is a tensor, return tensor of same batch size
                            batch_size = args[0].shape[0] if len(args[0].shape) > 0 else 1
                            return torch.randn(batch_size, 10)  # Return random tensor
                        return torch.randn(1, 10)
                    
                    def forward(self, *args, **kwargs):
                        return self.__call__(*args, **kwargs)
                    
                    def __getattr__(self, name):
                        if name.startswith('_'):
                            raise AttributeError(name)
                        # Catch any attribute access
                        print(f"     [Inspector] Stub model attribute access: '{name}'")
                        return lambda *args, **kwargs: None
                
                # Register the stub class under multiple possible names
                possible_class_names = ['TheModelClass', 'ModelClass', 'Model', 'MaliciousModel', 'Net']
                
                # Add to global namespace
                for class_name in possible_class_names:
                    globals()[class_name] = MaliciousModelStub
                
                # Also add to __main__ module which pickle often uses
                import __main__
                for class_name in possible_class_names:
                    setattr(__main__, class_name, MaliciousModelStub)
                
                # Now try to load with the stub classes available
                try:
                    print(f"    Loading with stub classes...")
                    model = torch.load(model_file, map_location='cpu')
                    model = wrap_model_for_execution(model)
                    attempts.append(f"torch.load with stubs: SUCCESS - {type(model)}")
                    results['execution_status'] = 'model_loaded'
                    results['output'] = f"Loaded with stub class: {type(model)}"
                    
                    # Check what we got
                    if isinstance(model, MaliciousModelStub):
                        results['output'] += " | Model is MaliciousModelStub instance"
                        results['warnings'].append("Model instantiated malicious stub class")
                        
                        # Try to execute the malicious model
                        if input_data is not None:
                            try:
                                with torch.no_grad():
                                    output = model(input_data)
                                results['output'] += f" | Executed: {output.shape if hasattr(output, 'shape') else type(output)}"
                                results['execution_status'] = 'success'
                            except Exception as exec_error:
                                results['output'] += f" | Execution failed: {str(exec_error)[:50]}"
                    
                    elif isinstance(model, dict):
                        # Sometimes the model is wrapped in a dict
                        results['output'] += f" | Got dict with keys: {list(model.keys())[:5]}"
                        
                        # Look for the actual model in the dict
                        for key, value in model.items():
                            if isinstance(value, MaliciousModelStub) or callable(value):
                                results['output'] += f" | Found callable at key '{key}': {type(value)}"
                                if input_data is not None:
                                    try:
                                        with torch.no_grad():
                                            output = value(input_data)
                                        results['output'] += f" | Executed '{key}': {output.shape if hasattr(output, 'shape') else type(output)}"
                                        results['execution_status'] = 'success'
                                        break
                                    except Exception:
                                        pass
                    
                    else:
                        results['output'] += f" | Unexpected type: {type(model)}"
                        
                except Exception as e:
                    error_msg = str(e)
                    attempts.append(f"torch.load with stubs: FAILED - {error_msg}")
                    
                    # If it still can't find a class, create it dynamically based on error
                    if "Can't get attribute" in error_msg:
                        # Extract the class name from error
                        import re
                        match = re.search(r"Can't get attribute '(\w+)'", error_msg)
                        if match:
                            missing_class = match.group(1)
                            print(f"    Creating specific stub for missing class: {missing_class}")
                            
                            # Create the missing class
                            globals()[missing_class] = MaliciousModelStub
                            setattr(__main__, missing_class, MaliciousModelStub)
                            
                            # Try one more time
                            try:
                                model = torch.load(model_file, map_location='cpu')
                                model = wrap_model_for_execution(model)
                                attempts.append(f"torch.load with {missing_class} stub: SUCCESS")
                                results['execution_status'] = 'model_loaded'
                                results['output'] = f"Loaded with dynamic stub for {missing_class}"
                                
                                if callable(model) and input_data is not None:
                                    with torch.no_grad():
                                        output = model(input_data)
                                    results['output'] += f" | Executed: {output.shape if hasattr(output, 'shape') else type(output)}"
                                    results['execution_status'] = 'success'
                                    
                            except Exception as e2:
                                attempts.append(f"Dynamic stub failed: {str(e2)[:50]}")
            
    
        else:
           # Original fallback methods for non-torch.package files
           methods = [
            ('torch.load', lambda: torch.load(model_file, map_location='cpu')),
            ('torch.jit.load', lambda: torch.jit.load(model_file, map_location='cpu')),
           ]
        
           model = None
           for method_name, method_func in methods:
            try:
                print(f"    Trying {method_name}...")
                model = method_func()
                model = wrap_model_for_execution(model)
                attempts.append(f"{method_name}: SUCCESS - {type(model)}")
                results['execution_status'] = 'model_loaded'
                
                # Check if it's a HuggingFace model that needs tokenization
                if 'transformers' in str(type(model)):
                    print(f"    Detected HuggingFace model: {type(model).__name__}")
                    
                    # Try to execute with proper tokenization
                    if requirements['input_type'] == 'text' and isinstance(input_data, str):
                        # Check if tokenizer exists
                        if model_info['has_tokenizer']:
                            try:
                                from transformers import AutoTokenizer
                                print("    Loading tokenizer...")
                                tokenizer = AutoTokenizer.from_pretrained(model_folder)
                                inputs = tokenizer(input_data, return_tensors="pt")
                                
                                with torch.no_grad():
                                    output = model(**inputs)
                                    
                                if hasattr(output, 'last_hidden_state'):
                                    attempts.append(f"Execution: output shape {output.last_hidden_state.shape}")
                                elif hasattr(output, 'logits'):
                                    attempts.append(f"Execution: logits shape {output.logits.shape}")
                                else:
                                    attempts.append(f"Execution: {type(output)}")
                                results['execution_status'] = 'success'
                                
                            except Exception as tok_error:
                                print(f"    Tokenizer failed: {str(tok_error)[:50]}")
                                
                                # Try with dummy token IDs
                                try:
                                    print("    Trying with dummy input_ids...")
                                    dummy_input_ids = torch.randint(0, 50000, (1, 20))
                                    dummy_attention_mask = torch.ones(1, 20)
                                    
                                    with torch.no_grad():
                                        output = model(input_ids=dummy_input_ids, attention_mask=dummy_attention_mask)
                                    
                                    if hasattr(output, 'last_hidden_state'):
                                        attempts.append(f"Dummy execution: output shape {output.last_hidden_state.shape}")
                                    elif hasattr(output, 'logits'):
                                        attempts.append(f"Dummy execution: logits shape {output.logits.shape}")
                                    else:
                                        attempts.append(f"Dummy execution: {type(output)}")
                                    results['execution_status'] = 'success'
                                    
                                except Exception as dummy_error:
                                    attempts.append(f"Dummy input failed: {str(dummy_error)[:30]}")
                        else:
                            # No tokenizer, try with dummy inputs
                            print("    No tokenizer found, using dummy inputs...")
                            try:
                                dummy_input_ids = torch.randint(0, 50000, (1, 20))
                                dummy_attention_mask = torch.ones(1, 20)
                                
                                with torch.no_grad():
                                    output = model(input_ids=dummy_input_ids, attention_mask=dummy_attention_mask)
                                
                                if hasattr(output, 'last_hidden_state'):
                                    attempts.append(f"Execution: output shape {output.last_hidden_state.shape}")
                                elif hasattr(output, 'logits'):
                                    attempts.append(f"Execution: logits shape {output.logits.shape}")
                                else:
                                    attempts.append(f"Execution: {type(output)}")
                                results['execution_status'] = 'success'
                                
                            except Exception as exec_error:
                                attempts.append(f"Execution failed: {str(exec_error)[:30]}")
                    else:
                        # Not text input, try with tensor
                        try:
                            with torch.no_grad():
                                output = model(input_data)
                            attempts.append(f"Tensor execution: {output.shape if hasattr(output, 'shape') else type(output)}")
                            results['execution_status'] = 'success'
                        except Exception:
                            # Try with dummy transformer inputs
                            try:
                                dummy_input_ids = torch.randint(0, 50000, (1, 20))
                                with torch.no_grad():
                                    output = model(dummy_input_ids)
                                attempts.append(f"Dummy execution: success")
                                results['execution_status'] = 'success'
                            except Exception:
                                pass
                
                elif callable(model) and input_data is not None:
                    # Non-transformer model
                    try:
                        with torch.no_grad():
                            output = model(input_data)
                        attempts.append(f"Execution: {output.shape if hasattr(output, 'shape') else type(output)}")
                        results['execution_status'] = 'success'
                    except Exception as exec_error:
                        attempts.append(f"Execution failed: {str(exec_error)[:30]}")
                
                break  # We loaded successfully, don't try other methods
                
            except Exception as e:
                error_msg = str(e)
                attempts.append(f"{method_name}: FAILED - {error_msg}")
                
                # If we get a missing class error, try with stub
                if "Can't get attribute" in error_msg and method_name == 'torch.load':
                    import re
                    match = re.search(r"Can't get attribute '(\w+)'", error_msg)
                    if match:
                        missing_class = match.group(1)
                        print(f"    Creating stub for: {missing_class}")
                        
                        # Create stub class
                        class GenericStub:
                            def __init__(self, *args, **kwargs):
                                pass
                            def __call__(self, *args, **kwargs):
                                return torch.randn(1, 10)
                        
                        import __main__
                        setattr(__main__, missing_class, GenericStub)
                        globals()[missing_class] = GenericStub
                        
                        try:
                            model = torch.load(model_file, map_location='cpu')
                            model = wrap_model_for_execution(model)
                            attempts.append(f"torch.load with {missing_class} stub: SUCCESS")
                            results['execution_status'] = 'model_loaded'
                            break
                        except Exception:
                            pass
                continue
    
        results['output'] = " | ".join(attempts) if attempts else "No successful loading method"
        if 'model' in locals():
               del model
        import gc
        gc.collect()
     
        
    
        
        # KERAS MODELS
       elif file_type  == 'keras':
            print("Loading Keras model...")
            results['loading_method'] = 'keras'
            print(f"    DEBUG: Model files detected: {model_info['model_files']}")
            config_data = model_info.get('config_data')
            if config_data is None:
                 config_data = {}
            architectures = config_data.get('architectures', 'No architectures')
            print(f"    DEBUG: Config data: {architectures}")

            import tensorflow as tf
            import numpy as np
            import json
            import keras
            import h5py
            import gc
            config_candidates = []
            standard_config = os.path.join(model_folder, "config.json")
            if os.path.exists(standard_config):
               config_candidates.append("config.json")

            for f in os.listdir(model_folder):
                if not f.endswith(".json"):
                   continue

                if f in config_candidates:
                   continue

                json_path = os.path.join(model_folder, f)

                try:
                   with open(json_path, "r") as jf:
                         data = json.load(jf)

                   looks_like_keras_config = (data.get("class_name") in ["Functional", "Sequential", "Model"]
                   or "keras" in str(data.get("module", "")).lower()
                   or "layers" in str(data.get("config", {})).lower() )

                   if looks_like_keras_config:
                      config_candidates.append(f)

                except Exception:
                  pass

            config_file = config_candidates[0] if config_candidates else None
            config_path = os.path.join(model_folder, config_file) if config_file else None

            # -----------------------------
            # 2. Find Keras weights H5 file
            # -----------------------------
            weights_candidates = [ f for f in model_info.get("model_files", []) if f.endswith(".h5") and ( "weight" in f.lower() or f.endswith(".weights.h5") ) ]

            if not weights_candidates:
               weights_candidates = [f for f in os.listdir(model_folder) if f.endswith(".h5") and ("weight" in f.lower() or f.endswith(".weights.h5"))]

            weights_file = weights_candidates[0] if weights_candidates else None
            weights_path = os.path.join(model_folder, weights_file) if weights_file else None

            if config_path and os.path.exists(config_path) and weights_path and os.path.exists(weights_path):
               print("    DEBUG: Detected Keras config.json + model.weights.h5 layout.")
               results['loading_method'] = 'keras_config_plus_weights'

               try:
                 with open(config_path, "r") as f:
                     keras_config = json.load(f)

                 # Rebuild architecture from config.json
                 try:
                    model = keras.saving.deserialize_keras_object( keras_config,safe_mode=False)
                 except Exception as deser_error:
                    print(f"    DEBUG: Keras deserialization failed: {str(deser_error)[:200]}")
                    print("    DEBUG: Falling back to manual Functional reconstruction.")
                    # Manual fallback for simple Functional/Sequential configs
                    cfg = keras_config.get("config", {})
                    layers_cfg = cfg.get("layers", [])
                    input_shape = None
                    dense_units = None
                    dense_activation = "linear"
                    dense_use_bias = True
                    for layer in layers_cfg:
                        class_name = layer.get("class_name")
                        layer_config = layer.get("config", {})

                        if class_name == "InputLayer":
                           batch_shape = layer_config.get("batch_shape")
                           if batch_shape and len(batch_shape) > 1:
                              input_shape = tuple(batch_shape[1:])

                        elif class_name == "Dense":
                            dense_units = layer_config.get("units")
                            dense_activation = layer_config.get("activation", "linear")
                            dense_use_bias = layer_config.get("use_bias", True)
                    if input_shape is None or dense_units is None:
                       raise deser_error
                    inputs = tf.keras.Input(shape=input_shape, name="input_layer")
                    outputs = tf.keras.layers.Dense( dense_units, activation=dense_activation, use_bias=dense_use_bias,name="dense")(inputs)
                    model = tf.keras.Model(inputs=inputs, outputs=outputs, name=cfg.get("name", "functional"))
                
                
                
                
                 print("    DEBUG: Model reconstructed from config.json.")

                 # This is the important step for the HDF5/VDS PoC
                 print(f"    DEBUG: Loading weights from {weights_file}.")
                 model.load_weights(weights_path)

                 model = wrap_model_for_execution(model)

                 results['execution_status'] = 'model_loaded'
                 results['output'] = f"Keras model reconstructed from {config_file} and weights loaded from {weights_file}"

                 # Optional: run a tiny forward pass
                 try:
                   test_input = tf.constant(np.random.randn(1, 3).astype(np.float32))
                   output = model(test_input)
                   results['execution_status'] = 'success'
                   results['output'] += f" | Executed forward pass: {getattr(output, 'shape', type(output))}"
                 except Exception as exec_err:
                   results['output'] += f" | Forward pass failed: {str(exec_err)[:100]}"

               except Exception as e:
                  results['execution_status'] = 'failed'
                  results['error'] = f"Keras config+weights loading failed: {str(e)}"

               model_results.append(results)
               continue
            
            
            # Find the keras/h5 file
            keras_file = None
            keras_file = next((f for f in model_info.get('model_files', []) if f.endswith(('.h5', '.keras')) and os.path.exists(os.path.join(model_folder, f))),None)
            print(f"    DEBUG: Selected file to load: {keras_file}")
            if not keras_file:
                results['error'] = "No Keras model file found"
                results['execution_status'] = 'failed'
            else:
                model_file = os.path.join(model_folder, keras_file)
                print(f"    DEBUG: Inspecting {keras_file} structure...")
                print(f"    Loading {keras_file}...")
                try:
                 import h5py
                 with h5py.File(model_file, 'r') as h5file:
                   keys = list(h5file.keys())
                   print(f"    DEBUG: Root HDF5 keys: {keys}")
                
                   # Check what's inside each key
                   for key in keys[:3]:  # First 3 keys
                    if isinstance(h5file[key], h5py.Group):
                        subkeys = list(h5file[key].keys())[:5]
                        print(f"    DEBUG: '{key}' contains subkeys: {subkeys}")
                
                   # Determine file type based on structure
                   is_huggingface = False
                   is_keras = False
                
                   if 'top_level_model_weights' in keys or 'bert' in keys:
                      print("    DEBUG:  This is a HuggingFace TensorFlow model (has 'bert' or 'top_level_model_weights')")
                      is_huggingface = True
                   elif 'model_weights' in keys or 'layer_names' in keys or 'model_config' in keys:
                      print("    DEBUG:  This is a standard Keras model")
                      is_keras = True
                   else:
                      print(f"    DEBUG:  Unknown H5 structure. Keys: {keys}")
                      
                except Exception as inspect_error:
                  print(f"    DEBUG: Failed to inspect H5: {inspect_error}")
                  is_huggingface = False
                  is_keras = True 
                # Now try to load based on what we found
                print(f"    DEBUG: Attempting to load the model...")
                
                
                
                
                # Try different loading methods based on file name and structure
                loading_success = False
                
                # Method 1: Try as Keras model
                if not is_huggingface or is_keras:
                  try:
                     print("    DEBUG: Method 1 - Loading as Keras model...")
                     model = tf.keras.models.load_model(model_file)
                     model = wrap_model_for_execution(model)
                     results['execution_status'] = 'model_loaded'
                     results['output'] = f"Keras model loaded: {type(model)}"
                     loading_success = True
                     print(f"    DEBUG:  Keras loading successful!")
                
                  except Exception as keras_error:
                    print(f"    DEBUG:  Keras loading failed: {str(keras_error)[:200]}")
                    
                    if "bad marshal data" in str(keras_error) or "marshal" in str(keras_error).lower():
                        print(f"     [Inspector] Bad marshal data — code likely executed")
                        results['warnings'].append("Malicious marshal/pickle code detected in .h5 file")
                        results['execution_status'] = 'malicious_executed'
                        results['output'] = f"Malicious marshal code executed: {str(keras_error)[:100]}"
                        loading_success = True  # Don't retry
        
                    elif "Lambda layer" in str(keras_error)  and "arbitrary code execution" in str(keras_error) :
                           print(f"     [Inspector] Lambda layer with arbitrary code detected")
                           results['warnings'].append("Keras Lambda layer with embedded code")
                           results['execution_status'] = 'malicious_lambda'
                           results['output'] = "Malicious Lambda layer - execution blocked by Keras"
                           loading_success = True 
                    elif "pickle" in str(keras_error).lower() or "unpickling" in str(keras_error).lower():
                         print(f"     [Inspector] Pickle error — code likely executed")
                         results['warnings'].append("Malicious pickle code detected in .h5 file")
                         results['execution_status'] = 'malicious_executed'
                         results['output'] = f"Malicious pickle executed: {str(keras_error)[:100]}"
                         loading_success = True
                    
                    elif "timed out" in str(keras_error).lower():
                        # Timeout might mean malicious infinite loop
                        results['warnings'].append("Model loading timed out - possible malicious infinite loop")
                        results['execution_status'] = 'timeout_malicious'
                        results['output'] = f"Timed out after loading attempt - possible malicious code"
                        loading_success = True
                # Method 2: If Keras failed or we detected HuggingFace structure, try HuggingFace
                if not loading_success and (is_huggingface or 'BertModel' in str((model_info.get('config_data') or {}).get('architectures', []))):
                  try:
                     print("    DEBUG: Method 2 - Loading as HuggingFace TensorFlow model...")
                     print(f"    DEBUG: Config architectures: {(model_info.get('config_data') or {}).get('architectures', [])}")
                
                     from transformers import TFAutoModel, AutoTokenizer
                
                     # HuggingFace expects the whole folder, not the file
                     print(f"    DEBUG: Loading from folder: {model_folder}")
                     model = TFAutoModel.from_pretrained(model_folder)
                     model = wrap_model_for_execution(model)
                     results['execution_status'] = 'model_loaded'
                     results['output'] = f"HuggingFace TF model loaded: {type(model).__name__}"
                     results['loading_method'] = 'huggingface_tf'
                     loading_success = True
                     print(f"    DEBUG:  HuggingFace loading successful! Model type: {type(model)}")
                     
                  except ImportError as ie:
                         print(f"    DEBUG: transformers not installed: {ie}")
                         results['error'] = "transformers library not available"
                         results['execution_status'] = 'failed'
        
                  except Exception as hf_error:
                         print(f"    DEBUG: Unexpected error: {str(hf_error)[:200]}")
                         # Even unexpected errors might indicate malicious execution
                         results['warnings'].append("Unexpected error - possible malicious execution")
                         results['execution_status'] = 'malicious_executed'
                         results['output'] = f"Possible malicious execution: {str(hf_error)[:100]}"

                # ALWAYS check for auxiliary malicious files regardless of main model status
                if 'extra_data.pickle' in model_info.get('files', []):
                    print("\n      Loading auxiliary file: extra_data.pickle...")
                    pickle_path = os.path.join(model_folder, 'extra_data.pickle')
                    try:
                      import pickle
                      import io as io_module
                      import contextlib
        
                      stdout_capture = io_module.StringIO()
        
                      with open(pickle_path, 'rb') as f:
                          with contextlib.redirect_stdout(stdout_capture):
                               pickle_data = pickle.load(f)
        
                      captured = stdout_capture.getvalue()
                      if captured:
                         print(f"     [Inspector] Code output from extra_data.pickle: {captured}")
                         results['warnings'].append(f"Malicious execution in extra_data.pickle")
                         results['execution_status'] = 'malicious_executed'
        
                      print(f"    Loaded extra_data.pickle: {pickle_data}")
        
                      if not results.get('auxiliary_payloads'):
                         results['auxiliary_payloads'] = []
                      results['auxiliary_payloads'].append(f"extra_data.pickle: {pickle_data}")
        
                      # Mark as malicious execution
                      if results.get('execution_status') != 'success':
                         results['execution_status'] = 'malicious_executed'
            
                    except Exception as pickle_error:
                           print(f"    extra_data.pickle error: {str(pickle_error)[:100]}")
                           # Even pickle errors might mean code executed
                           if "ran out of input" not in str(pickle_error).lower():
                               results['execution_status'] = 'malicious_executed'
            if 'model' in locals():
               del model
            import gc
            gc.collect()         
                    
                     
        
       elif file_type  == 'transformers_tf':
            print("Loading HuggingFace TensorFlow model...")
            results['loading_method'] = 'huggingface_tf'
            
            try:
                from transformers import TFAutoModel, AutoTokenizer
                architectures = model_info.get('config_data', {}).get('architectures', [])
                model = TFAutoModel.from_pretrained(model_folder)
                model = wrap_model_for_execution(model)
                results['execution_status'] = 'model_loaded'
                
                if requirements['input_type'] == 'text' and model_info['has_tokenizer']:
                    tokenizer = AutoTokenizer.from_pretrained(model_folder)
                    inputs = tokenizer(input_data, return_tensors="tf")
                    
                    output = model(**inputs)
                    results['output'] = f"TF Model output shape: {output.last_hidden_state.shape if hasattr(output, 'last_hidden_state') else 'Success'}"
                    results['execution_status'] = 'success'
                else:
                    # Try with tensor input
                    if input_data is not None:
                        import tensorflow as tf
                        # Convert PyTorch tensor to TensorFlow if needed
                        if hasattr(input_data, 'numpy'):
                            tf_input = tf.constant(input_data.numpy())
                        else:
                            tf_input = tf.constant(input_data)
                        
                        output = model(tf_input)
                        results['output'] = f"TF Model executed: {output.shape if hasattr(output, 'shape') else type(output)}"
                        results['execution_status'] = 'success'
                        
            except ImportError:
                results['error'] = "TensorFlow or transformers[tf] not installed"
                results['execution_status'] = 'failed'
            
            if 'model' in locals():
               del model
            import gc
            gc.collect()
       elif file_type  == 'pytorch_th':
            print("️  Loading legacy .th file (Torch7/Lua format, POTENTIALLY DANGEROUS!)...")
            results['loading_method'] = 'pytorch_th_legacy'
            
            model_file = os.path.join(model_folder, file)
            
            
            try:
                # Method 1: Try as PyTorch file (modern .th files)
                print("    Trying as PyTorch .th file...")
                model = torch.load(model_file, map_location='cpu')
                model = wrap_model_for_execution(model)
                results['execution_status'] = 'model_loaded'
                results['output'] = f".th file loaded: {type(model)}"
                
                # Try to execute if it's a model
                if callable(model) and input_data is not None:
                    with torch.no_grad():
                        output = model(input_data)
                    results['output'] += f", executed: {output.shape if hasattr(output, 'shape') else type(output)}"
                    results['execution_status'] = 'success'
                elif hasattr(model, 'forward') and input_data is not None:
                    with torch.no_grad():
                        output = model(input_data)
                    results['output'] += f", forward pass: {output.shape if hasattr(output, 'shape') else type(output)}"
                    results['execution_status'] = 'success'
                elif isinstance(model, dict):
                    # Might be a state_dict
                    results['output'] += f", appears to be state_dict with keys: {list(model.keys())[:3]}..."
                    
                    # Try to load into a model architecture if config exists
                    if model_info['has_config'] and model_info['config_data']:
                        try:
                            from transformers import AutoModel
                            base_model = AutoModel.from_config(model_info['config_data'])
                            base_model = wrap_model_for_execution(base_model)
                            base_model.load_state_dict(model, strict=False)
                            results['output'] += ", loaded into model architecture"
                            results['execution_status'] = 'success'
                        except Exception:
                            pass
                            
            except Exception as th_error:
                print(f"    Failed to load as PyTorch .th: {th_error}")
                
                # Method 2: Check if it's actually a different format
                try:
                    print("    Checking file format...")
                    with open(model_file, 'rb') as f:
                        header = f.read(16)
                        
                    if header.startswith(b'PK'):
                        print("    .th file is actually a ZIP archive, trying zip methods...")
                        # Treat as ZIP file
                        classification = _classify_pytorch_bin(model_file)
                        if classification['kind'] == 'torch_package':
                            # Handle as torch.package
                            try:
                                from torch.package import PackageImporter
                                with PackageImporter(model_file) as importer:
                                    model = importer.load_pickle('pytorch_model', 'data.pkl')
                                    model = wrap_model_for_execution(model)
                                    results['execution_status'] = 'model_loaded'
                                    results['output'] = f".th torch.package loaded: {type(model)}"
                            except Exception:
                                results['error'] = f"Failed to load .th as torch.package: {str(th_error)}"
                                
                    elif header.startswith(b'\x80'):  # Pickle format
                        print("    .th file appears to be raw pickle...")
                        import pickle
                        with open(model_file, 'rb') as f:
                            model = pickle.load(f)
                            model = wrap_model_for_execution(model)
                        results['execution_status'] = 'model_loaded'
                        results['output'] = f".th pickle loaded: {type(model)}"
                        
                    else:
                        # Unknown binary format
                        results['error'] = f"Unknown .th file format. Header: {header.hex()}"
                        results['execution_status'] = 'failed'
                        
                except Exception as format_error:
                    results['error'] = f"Failed all .th loading methods: {str(format_error)}"
                    results['execution_status'] = 'failed'
                     
        
            if 'model' in locals():
               del model
            import gc
            gc.collect()
      
      
      
      
      
       
       elif file_type == 'tensorflow_saved':
           print("Loading TensorFlow SavedModel...")
           results['loading_method'] = 'tensorflow_saved'
    
           import tensorflow as tf
           import numpy as np
    
           # Check if the SavedModel directory structure is complete
           variables_dir = os.path.join(model_folder, 'variables')
           has_variables = os.path.exists(variables_dir)
    
           if not has_variables:
              print("      Warning: No variables directory found (model might be incomplete or malicious)")
              results['warnings'].append("SavedModel missing variables directory")

           model = None
           load_attempts = []
    
           # Method 1: Standard load
           try:
             print("    Attempting standard load...")
             model = tf.saved_model.load(model_folder)
             model = wrap_model_for_execution(model)
             load_attempts.append("Standard load: SUCCESS")
             results['execution_status'] = 'model_loaded'
             print("     Model loaded successfully")
        
           except Exception as e1:
             load_attempts.append(f"Standard load: FAILED - {str(e1)[:100]}")
        
             # Method 2: Load with options to ignore missing variables
             try:
               print("    Attempting load with LoadOptions...")
               options = tf.saved_model.LoadOptions(
                experimental_io_device='/job:localhost',
                allow_partial_checkpoint=True,
                experimental_skip_checkpoint=True  # Skip checkpoint loading
               )
               model = tf.saved_model.load(model_folder, options=options)
               model = wrap_model_for_execution(model)
               load_attempts.append("Load with options: SUCCESS")
               results['execution_status'] = 'model_loaded'
               print("     Model loaded with options")
            
             except Exception as e2:
               load_attempts.append(f"Load with options: FAILED - {str(e2)[:100]}")
               results['error'] = f"All loading methods failed. Last error: {str(e2)}"
               results['execution_status'] = 'failed'
              
                   
        
           # If we loaded a model, try to run inference
           if model is not None and results['execution_status'] in ['model_loaded']:
                print("    Model loaded, attempting execution...")
        
                execution_success = False
                execution_attempts = []
                expected_inputs = []
                detected_input_shape = None
                # Try to execute with signatures
                if hasattr(model, 'signatures') and model.signatures:
                   print("    Found signatures, trying execution...")
                   for sig_name, sig_func in model.signatures.items():
                      print(f"    Signature '{sig_name}':")
                      
                      # Get the concrete function to inspect inputs
                      if hasattr(sig_func, 'structured_input_signature'):
                          input_sig = sig_func.structured_input_signature
                          print(f"      Input signature: {input_sig}")
                          if isinstance(input_sig, tuple) and len(input_sig) > 1:
                              if isinstance(input_sig[1], dict):
                                 for key, spec in input_sig[1].items():
                                     if isinstance(spec, tf.TensorSpec):
                                        detected_input_shape = spec.shape
                                        expected_inputs.append(key)  # Add the key name here too
                                        print(f"      Detected input '{key}' needs shape: {spec.shape}")
                      if hasattr(sig_func, 'inputs'):
                         for inp in sig_func.inputs:
                            print(f"      Input tensor: {inp}")
                        
                      if hasattr(sig_func, 'structured_outputs'):
                         print(f"      Output signature: {sig_func.structured_outputs}")
                   # Get the serving signature
                   if 'serving_default' in model.signatures:
                       raw_infer = model.signatures['serving_default']
                   else:
                      raw_infer = list(model.signatures.values())[0]
                 
                   infer = monitor.monitor_api(raw_infer, phase="EXECUTION")
                   print(f"    Using signature: {list(model.signatures.keys())}")
            
                   # Method 1: Try with no arguments (some models don't need input)
                   try:
                      print("    Trying execution with no arguments...")
                      output = infer()
                      results['output'] = f"Execution successful with no arguments!"
                      results['execution_status'] = 'success'
                      execution_success = True
                      execution_attempts.append("No args: SUCCESS")
                      print(f"     Execution succeeded with no arguments")
                   except Exception as no_arg_error:
                      execution_attempts.append(f"No args: {str(no_arg_error)}")
                
                      # Extract the expected input name from error message
                      error_msg = str(no_arg_error)
                     
                
                      # Parse error for missing arguments
                      if "missing" in error_msg.lower() and "argument" in error_msg.lower():
                        # Try to extract argument names from error
                        import re
                        # Look for patterns like "missing required arguments: 'input_1'"
                        match = re.search(r"missing.*arguments?:?\s*['\"]?(\w+)['\"]?", error_msg, re.IGNORECASE)
                        if match:
                           expected_inputs.append(match.group(1))
                        # Also look for "got unexpected keyword argument"
                           match = re.search(r"got unexpected keyword argument ['\"]?(\w+)['\"]?", error_msg, re.IGNORECASE)
                           if match:
                              print(f"      Note: '{match.group(1)}' is not a valid input name")
                
                      print(f"    Expected inputs from error: {expected_inputs}")
                      if expected_inputs and not execution_success:
                         print(f"    Creating input for detected parameter: {expected_inputs[0]}")
                         # Extract dtype from the TensorSpec we already walked earlier
                         detected_dtype = None
                         detected_shape_list = None
                         if hasattr(raw_infer, 'structured_input_signature'):
                            sig = raw_infer.structured_input_signature
                            if isinstance(sig, tuple) and len(sig) > 1 and isinstance(sig[1], dict):
                               spec = sig[1].get(expected_inputs[0])
                               if isinstance(spec, tf.TensorSpec):
                                  detected_dtype = spec.dtype
                                  detected_shape_list = [1 if s is None else s for s in spec.shape.as_list()] if spec.shape.rank else []
     
                         # Build input matching dtype
                         if detected_dtype == tf.string:
                             # Must match the signature's rank exactly
                             if detected_shape_list:
                                test_input = tf.constant(["/tmp/probe"] * max(1, detected_shape_list[0]))
                             else:
                                # scalar string (shape=())
                                test_input = tf.constant("/tmp/probe", dtype=tf.string)
                         elif detected_dtype in (tf.int32, tf.int64):
                            test_input = tf.constant(np.zeros(detected_shape_list or [1], dtype=np.int32 if detected_dtype == tf.int32 else np.int64))
                         else:
                            shape = detected_shape_list or [1, 28, 28]
                            test_input = tf.constant(np.random.randn(*shape).astype(np.float32))
     
                         try:
                            output = infer(**{expected_inputs[0]: test_input})
                            results['output'] = f"Execution successful with {expected_inputs[0]}={test_input.dtype}"
                            results['execution_status'] = 'success'
                            execution_success = True
                            print(f"     Execution succeeded with dtype={detected_dtype}")
                         except Exception as detected_error:
                            print(f"    Failed with detected input: {str(detected_error)}")
                            if "Graph execution error" in str(detected_error):
                                results['output'] = "Graph execution error - likely malicious code executed"
                                results['execution_status'] = 'malicious_executed'
                                results['warnings'].append("Graph execution error during model run")
                                execution_success = True
                     
                        
                   # Method 2: Try with common input patterns
                   if not execution_success:
                      # Create various test inputs
                      test_inputs = [
                      (tf.constant(1.0, dtype=tf.float32), "scalar float32"),
                      (tf.constant([1.0], dtype=tf.float32), "[1] float32"),
                      (tf.constant([[1.0]], dtype=tf.float32), "[[1]] float32"),
                      (tf.constant(np.random.randn(1, 10).astype(np.float32)), "(1,10) float32"),
                      (tf.constant(np.random.randn(1, 224, 224, 3).astype(np.float32)), "(1,224,224,3) image"),
                      (tf.constant(np.zeros((1, 100), dtype=np.float32)), "(1,100) zeros"),
                      ]
                      if detected_input_shape:
                         # Convert None dimensions to 1 for testing
                         test_shape = [1 if s is None else s for s in detected_input_shape.as_list()]
                         test_inputs.insert(0, (tf.constant(np.random.randn(*test_shape).astype(np.float32)), f"{test_shape} detected"))
    
                      # Common parameter names in SavedModels
                      param_names = expected_inputs + ['input', 'inputs', 'input_1', 'input_0', 
                              'x', 'input_tensor', 'data', 'images', 'image_tensor',
                              'serving_default_input', 'input_ids', 'features']
                
                      for test_input, input_desc in test_inputs:
                          if execution_success:
                             break
                        
                          # Try as positional argument
                          try:
                            output = infer(test_input)
                            results['output'] = f"Execution successful with positional {input_desc}!"
                            results['execution_status'] = 'success'
                            execution_success = True
                            execution_attempts.append(f"Positional {input_desc}: SUCCESS")
                            print(f"     Execution succeeded with positional {input_desc}")
                            break
                          except Exception as pos_error:
                            pass
                    
                          # Try with each parameter name
                          for param_name in param_names:
                            try:
                              output = infer(**{param_name: test_input})
                              results['output'] = f"Execution successful with {param_name}={input_desc}!"
                              results['execution_status'] = 'success'
                              execution_success = True
                              execution_attempts.append(f"{param_name}={input_desc}: SUCCESS")
                              print(f"     Execution succeeded with {param_name}={input_desc}")
                              break
                            except Exception as kwarg_error:
                              # Check if this error gives us more info about expected inputs
                              if "missing" in str(kwarg_error).lower() and param_name == param_names[0]:
                                execution_attempts.append(f"{param_name}: {str(kwarg_error)[:30]}")
        
                # Method 3: Try direct call on the model object
                if not execution_success and callable(model):
                  print("    Trying direct model call...")
                  test_inputs = [
                  tf.constant(1.0, dtype=tf.float32),
                  tf.constant([[1.0]], dtype=tf.float32),
                  tf.constant(np.random.randn(1, 10).astype(np.float32)),
                  ]
            
                  for test_input in test_inputs:
                   try:
                      output = model(test_input)
                      results['output'] = f"Direct call successful with shape {test_input.shape}!"
                      results['execution_status'] = 'success'
                      execution_success = True
                      execution_attempts.append(f"Direct call {test_input.shape}: SUCCESS")
                      print(f"     Direct call succeeded")
                      break
                   except Exception as call_error:
                      execution_attempts.append(f"Direct {test_input.shape}: {str(call_error)[:30]}")
                
                # Method 3.5: Invoke custom callable attributes (catches payloads like loaded.read)
                if not execution_success:
                   print("    Trying custom callable attributes (.read, .process, etc.)...")
                   import tensorflow as tf_mod
                   for attr_name in ('read', 'process', 'serve', 'call'):
                      if execution_success:
                         break
                      fn = getattr(model, attr_name, None)
                      if not callable(fn):
                         continue
                      # Wrap if not already wrapped
                      if not getattr(fn, '_aop_wrapped', False):
                         fn = monitor.monitor_api(fn, phase="EXECUTION")
                      for probe in (tf_mod.constant("/tmp/probe"),
                                    tf_mod.constant(0.0),
                                    tf_mod.constant([[1.0]])):
                         try:
                            output = fn(probe)
                            results['output'] = f"Custom method .{attr_name}() executed with {probe.dtype}"
                            results['execution_status'] = 'success'
                            execution_success = True
                            execution_attempts.append(f".{attr_name}({probe.dtype}): SUCCESS")
                            print(f"     .{attr_name}() executed — may have triggered embedded ops")
                            break
                         except Exception as e:
                            execution_attempts.append(f".{attr_name}({probe.dtype}): {str(e)[:40]}")
                            continue
                # Method 4: Try to call with TensorSpec if available
                if not execution_success and hasattr(model, '__call__'):
                   print("    Trying to create proper input from TensorSpec...")
                   try:
                     # Get the call function
                     call_fn = model.__call__
                     if hasattr(call_fn, 'concrete_functions'):
                       for cf in call_fn.concrete_functions:
                         if cf.structured_input_signature:
                            # Create input matching the signature
                            input_sig = cf.structured_input_signature
                            if isinstance(input_sig, tuple) and len(input_sig) > 0:
                                if isinstance(input_sig[0], tf.TensorSpec):
                                    # Create tensor matching the spec
                                    spec = input_sig[0]
                                    shape = [1 if s is None else s for s in spec.shape]
                                    test_input = tf.constant(np.random.randn(*shape).astype(np.float32))
                                    
                                    try:
                                        output = model(test_input)
                                        results['output'] = f"Execution with TensorSpec shape {shape} successful!"
                                        results['execution_status'] = 'success'
                                        execution_success = True
                                        print(f"     TensorSpec execution succeeded")
                                        break
                                    except Exception:
                                        pass
                   except Exception as spec_error:
                       execution_attempts.append(f"TensorSpec: {str(spec_error)[:30]}")
        
                # If still no success, try to trigger any code execution
                if not execution_success:
                   print("    Attempting to trigger any embedded code...")
            
                   # Try accessing various attributes that might trigger code
                   try_attributes = ['__dict__', '__class__', '__init__', '__new__', 
                            '__reduce__', '__reduce_ex__', '__getstate__']
            
                   for attr in try_attributes:
                     if hasattr(model, attr):
                      try:
                        value = getattr(model, attr)
                        if callable(value) and attr not in ['__class__', '__new__']:
                            value()
                        print(f"      Accessed {attr}: {type(value)}")
                      except Exception:
                        pass
            
                   # Even if execution failed, malicious code might have been triggered
                   if not has_variables:
                      results['warnings'].append("Model without variables - possible malicious code executed during load")
                      results['execution_status'] = 'possible_malicious'
        
                # Compile execution attempts
                if execution_attempts:
                  attempts_str = " | ".join(execution_attempts[:5])  # First 5 attempts
                  if results.get('output'):
                     results['output'] += f" | Attempts: {attempts_str}"
                  else:
                     results['output'] = f"Model loaded but execution failed. Attempts: {attempts_str}"
                elif not execution_success:
                    results['output'] = "Model loaded but all execution attempts failed"
    
           # Add summary of load attempts if relevant
           if load_attempts and not model:
                results['output'] = f"Load attempts: {' | '.join(load_attempts)}"
          
          
           if 'model' in locals():
              del model
           import gc
           gc.collect()
          
          
          
          
          
                   
       elif file_type  == 'pytorch':
                print("Loading PyTorch model...")
                results['loading_method'] = 'pytorch'
            
                # Track if any malicious code executed
                any_code_executed = False
                loaded_models = []
            
                # Try each .pt/.pth/.keras file until one works
                #for file in model_info['model_files']:
                model_file = os.path.abspath(os.path.join(model_folder, file))
                print(f"  Trying {file}...")
                with open(model_file, 'rb') as f:
                   header = f.read(100)
                   print(f"    Header (first 50 bytes): {header[:50].hex()}")
    
                # 2. If it's a ZIP file, inspect contents
                if header[:2] == b'PK':
                   import zipfile
                   print(f"    [ZIP] Inspecting archive contents...")
                   try:
                     with zipfile.ZipFile(model_file, 'r') as zf:
                       all_files = zf.namelist()
                       print(f"    [ZIP] Contains {len(all_files)} files")
                
                       # Show first 10 files
                       for fname in all_files[:10]:
                          info = zf.getinfo(fname)
                          print(f"      - {fname} ({info.file_size} bytes)")
                
                       # Extract and inspect the pickle
                       if 'unsafe/data.pkl' in all_files:
                          print(f"    [MALICIOUS] Found unsafe/data.pkl!")
                          pkl_data = zf.read('unsafe/data.pkl')
                          print(f"    [Pickle] Size: {len(pkl_data)} bytes")
                          print(f"    [Pickle] First 200 bytes:")
                          print(f"      {pkl_data[:200]}")
                    
                          # Decode the pickle opcodes
                          print(f"    [Pickle] Analyzing opcodes...")
                          import pickletools
                          import io
                         
                       elif 'archive/data.pkl' in all_files:
                          print(f"    [NORMAL] Found archive/data.pkl (standard PyTorch)")
                          pkl_data = zf.read('archive/data.pkl')
                          print(f"    [Pickle] Size: {len(pkl_data)} bytes")
                          print(f"    [Pickle] First 100 bytes: {pkl_data[:100]}")
                    
                   except Exception as zip_err:
                        print(f"    [ZIP] Error: {zip_err}")
                
                if not os.path.exists(model_file):
                   print(f"    File not found: {model_file}")
                   loaded_models.append(f"{file}: file missing")
                   pass

                import io as io_module, contextlib
                error_msg = None
                captured_output = ""
                try:
    
                      model = torch.load(model_file, map_location='cpu')
                      model = wrap_model_for_execution(model)
                      if callable(model):
                           try:
                              if 'transformers' in str(type(model)):
                                 # For transformers: use token IDs, not strings
                                 dummy_tokens = torch.randint(0, 50000, (1, 20))
                                 with torch.no_grad():
                                     output = model(dummy_tokens)
                              else:
                                 # For regular models: use tensor
                                 dummy_input = torch.randn(1, 100)
                                 with torch.no_grad():
                                     output = model(dummy_input)
                    
                              results['execution_status'] = 'success'
                              results['output'] = f"Executed {file}: {output.shape if hasattr(output, 'shape') else type(output)}"
                              
                    
                           except Exception as exec_error:
                              results['execution_status'] = 'model_loaded'
                              results['output'] = f"Loaded {file} but execution failed: {str(exec_error)[:50]}"
                            
                        
                   
                      # Check what we got
                      if model is None:
                        # Malicious code executed but returned None
                        loaded_models.append(f"{file}: Executed malicious code, returned None")
                        results['execution_status'] = 'malicious_executed'
                        any_code_executed = True
                        
                      elif callable(model):
                        loaded_models.append(f"{file}: Loaded callable model {type(model)}")
                        results['execution_status'] = 'model_loaded'
                        
                        # Try to execute
                        if input_data is not None:
                            try:
                                with torch.no_grad():
                                    output = model(input_data)
                                loaded_models.append(f"Executed {file}: {output.shape if hasattr(output, 'shape') else type(output)}")
                                results['execution_status'] = 'success'
                                break  # Success, stop trying other files
                            except Exception as exec_err:
                                loaded_models.append(f"Execution failed for {file}: {str(exec_err)[:30]}")
                                
                      elif hasattr(model, 'forward'):
                        loaded_models.append(f"{file}: Loaded model with forward method")
                        results['execution_status'] = 'model_loaded'
                        
                        # Try to execute
                        if input_data is not None:
                            try:
                                with torch.no_grad():
                                    output = model(input_data)
                                loaded_models.append(f"Executed {file}: {output.shape if hasattr(output, 'shape') else type(output)}")
                                results['execution_status'] = 'success'
                                break
                            except Exception as exec_err:
                                loaded_models.append(f"Forward failed for {file}: {str(exec_err)[:30]}")
                                
                      elif isinstance(model, dict):
                        # Might be a state_dict
                        loaded_models.append(f"{file}: Loaded dict with {len(model)} keys")
                        results['execution_status'] = 'model_loaded'
                        
                      else:
                        # Something else was returned
                        loaded_models.append(f"{file}: Loaded {type(model)}")
                        results['execution_status'] = 'model_loaded'
                        
                except Exception as e:
                    error_msg = str(e)
                    try:
                      captured = stdout_capture.getvalue()
                      if captured:
                         print(f"     Output before failure in {file}: {captured.strip()}")
                         any_code_executed = True
                         loaded_models.append(f"{file}: Malicious code executed, load failed")
                         results['warnings'].append(f"Malicious execution in {file}") 
                         any_code_executed = True  
                      else:
                         loaded_models.append(f"{file} failed: {error_msg}")
                      pass
                    
                    except Exception:
                        pass
                    # Check if the error message indicates code was executed
                    if "Invalid magic number" in error_msg:
                        any_code_executed = True
                        loaded_models.append(f"{file}: Malicious code executed, invalid model returned")
                        results['warnings'].append(f"Malicious execution detected in {file}")
                    elif any(x in error_msg for x in ["No such file or directory", "ConnectionPool", "Failed to establish", "name resolution", 
                    "Connection refused", "Network is unreachable", "urlopen error", "HTTPError", "socket.gaierror"]):
                        any_code_executed = True
                        loaded_models.append(f"{file}: Malicious code executed, suspicious system activity")
                        results['warnings'].append(f"Malicious execution in {file}: {error_msg[:100]}")
                    else:
                        loaded_models.append(f"{file} failed: {error_msg}")
                    pass  # Try next file
            
                # Compile results
                results['output'] = " | ".join(loaded_models) if loaded_models else "No files successfully loaded"
            
                # Update status based on what happened
                if any_code_executed and results['execution_status'] in ['not_attempted', 'model_loaded']:
                  results['execution_status'] = 'malicious_executed'
                  results['warnings'].append("Malicious code was executed")
                elif results['execution_status'] == 'not_attempted':
                  results['execution_status'] = 'failed'
                  results['error'] = "All files failed to load"
                if 'model' in locals():
                   del model
                if 'bin_contents' in locals():
                    del bin_contents
                if 'base_model' in locals():
                    del base_model
                if 'tokenizer' in locals():
                    del tokenizer
                import gc
                gc.collect()
     
       elif file_type == 'pytorch_pt2':
            print("  Loading PyTorch 2 exported model (.pt2)...")
            results['loading_method'] = 'pytorch_pt2'
            
            model_file = os.path.join(model_folder, file)
            
            # Step 1: Inspect ZIP contents (pt2 files are ZIP archives)
            print("\n" + "="*70)
            print(" [Inspector] Inspecting .pt2 file")
            print("="*70)
            
            try:
                import zipfile
                import pickletools
                import io
                
                with zipfile.ZipFile(model_file, 'r') as zf:
                    all_files = zf.namelist()
                    print(f"   Total files in archive: {len(all_files)}")
                    for fname in all_files:
                        info_item = zf.getinfo(fname)
                        print(f"      - {fname} ({info_item.file_size} bytes)")
                    
                    # Find pickle files (constants.pkl, data.pkl, etc.)
                    pkl_files = [f for f in all_files if f.endswith('.pkl') or 'pickle' in f.lower()]
                    print(f"\n Pickle files found: {pkl_files}")
                    
                    for pkl_file in pkl_files:
                        print(f"\n   Analyzing: {pkl_file}")
                        pkl_data = zf.read(pkl_file)
                        print(f"   Size: {len(pkl_data)} bytes")
                        
                        # Disassemble pickle opcodes
                        print(f"\n    [Inspector] Pickle opcodes:")
                        print("   " + "-"*60)
                        try:
                            pickletools.dis(io.BytesIO(pkl_data), annotate=1)
                        except Exception as e:
                            print(f"   Error disassembling: {e}")
                        print("   " + "-"*60)
                        
                        # Security pattern scan
                        print(f"\n    [Inspector] Security scan:")
                        suspicious_patterns = {
                            b'posix': 'POSIX module access',
                            b'system': 'system() call',
                            b'subprocess': 'subprocess execution',
                            b'eval': 'eval() execution',
                            b'exec': 'exec() execution',
                            b'__import__': 'dynamic import',
                            b'__reduce__': 'pickle reduce (can execute code)',
                            b'__setstate__': 'pickle setstate',
                            b'os': 'OS module',
                            b'socket': 'Network socket',
                            b'urllib': 'URL request',
                            b'requests': 'HTTP request',
                        }
                        
                        found_patterns = []
                        for pattern, description in suspicious_patterns.items():
                            if pattern in pkl_data:
                                found_patterns.append(f"        {description}: '{pattern.decode()}' found")
                        
                        if found_patterns:
                            print("   Suspicious patterns detected:")
                            for p in found_patterns:
                                print(p)
                            results['warnings'].extend([f"Suspicious pattern in {pkl_file}: {p}" for p in found_patterns])
                        else:
                            print("    No obvious suspicious patterns detected")
                    
                    # Check for Python code files
                    py_files = [f for f in all_files if f.endswith('.py')]
                    if py_files:
                        print(f"\n     Python code files found: {py_files}")
                        results['warnings'].append(f"Contains Python code files: {py_files}")
                        
            except Exception as inspect_err:
                print(f"   Error inspecting .pt2 archive: {inspect_err}")
            
            print("="*70)
            print(" [Inspector] Inspection complete")
            print("="*70 + "\n")
            
            # Step 2: Try loading with torch.export.load (primary method)
            loading_attempts = []
            
            try:
                print("    Trying torch.export.load()...")
                import io as io_module
                import contextlib
                
                stdout_capture = io_module.StringIO()
                stderr_capture = io_module.StringIO()
                
                model = None
                exit_code = None
                
                try:
                    with contextlib.redirect_stdout(stdout_capture), contextlib.redirect_stderr(stderr_capture):
                        model = torch.export.load(model_file)
                        model = wrap_model_for_execution(model)
                except SystemExit as se:
                    exit_code = se.code
                    print(f"[Inspector] Pickle called exit({exit_code})!")
                    results['execution_status'] = 'malicious_exit'
                    results['warnings'].append(f'Pickle called exit({exit_code})')
                    results['output'] = f'Malicious pickle executed exit({exit_code})'
                    model = None
                
                captured_output = stdout_capture.getvalue()
                captured_errors = stderr_capture.getvalue()
                
                if captured_output:
                    print(f"     STDOUT: {captured_output[:200]}")
                    results['warnings'].append(f"Code output during load: {captured_output}")
                if captured_errors:
                    print(f"     STDERR: {captured_errors[:200]}")
                    results['warnings'].append(f"Errors during load: {captured_errors}")
                
                if model is not None:
                    loading_attempts.append(f"torch.export.load: SUCCESS - {type(model)}")
                    results['execution_status'] = 'model_loaded'
                    results['output'] = f"PT2 model loaded via torch.export.load: {type(model)}"
                    
                    # Try execution
                    if callable(model) and input_data is not None:
                        try:
                            with torch.no_grad():
                                output = model(input_data)
                            results['output'] += f" | Executed: {output.shape if hasattr(output, 'shape') else type(output)}"
                            results['execution_status'] = 'success'
                        except Exception as exec_err:
                            results['output'] += f" | Execution failed: {str(exec_err)[:50]}"
                    
                    # Check for ExportedProgram
                    if hasattr(model, 'module'):
                        try:
                            ep_module = model.module()
                            if callable(ep_module) and input_data is not None:
                                with torch.no_grad():
                                    output = ep_module(input_data)
                                results['output'] += f" | module() executed: {output.shape if hasattr(output, 'shape') else type(output)}"
                                results['execution_status'] = 'success'
                        except Exception as mod_err:
                            results['output'] += f" | module() failed: {str(mod_err)[:50]}"
                    
                elif exit_code is None:
                    loading_attempts.append("torch.export.load: returned None")
                    if captured_output or captured_errors:
                        results['execution_status'] = 'malicious_executed'
                        results['output'] = f"Malicious code executed during torch.export.load"
                        
            except AttributeError:
                loading_attempts.append("torch.export.load: not available (PyTorch < 2.1)")
            except Exception as export_err:
                error_msg = str(export_err)
                loading_attempts.append(f"torch.export.load: FAILED - {error_msg[:80]}")
                
                # Check for malicious indicators in the error
                if any(x in error_msg for x in ['No such file or directory', 'ConnectionPool', 
                    'Failed to establish', 'name resolution', 'Connection refused',
                    'Network is unreachable', 'urlopen error']):
                    results['execution_status'] = 'malicious_executed'
                    results['output'] = f"Malicious code executed during pt2 load: {error_msg[:100]}"
                    results['warnings'].append(f"Malicious execution detected: {error_msg[:100]}")
            
            # Step 3: Fallback to torch.load (the underlying pickle attack surface)
            if results['execution_status'] in ['not_attempted', 'failed']:
                try:
                    print("    Falling back to torch.load()...")
                    
                    stdout_capture2 = io_module.StringIO()
                    stderr_capture2 = io_module.StringIO()
                    
                    try:
                        with contextlib.redirect_stdout(stdout_capture2), contextlib.redirect_stderr(stderr_capture2):
                            model = torch.load(model_file, map_location='cpu')
                            model = wrap_model_for_execution(model)
                    except SystemExit as se:
                        print(f"     [Inspector] torch.load triggered exit({se.code})")
                        results['execution_status'] = 'malicious_exit'
                        results['output'] = f'Malicious pickle in pt2 executed exit({se.code})'
                        model = None
                    
                    captured2 = stdout_capture2.getvalue()
                    if captured2:
                        print(f"     STDOUT from torch.load: {captured2[:200]}")
                        results['warnings'].append(f"Code output from torch.load: {captured2}")
                        results['execution_status'] = 'malicious_executed'
                    
                    if model is not None:
                        loading_attempts.append(f"torch.load fallback: SUCCESS - {type(model)}")
                        if results['execution_status'] == 'not_attempted':
                            results['execution_status'] = 'model_loaded'
                        results['output'] = results.get('output', '') or f"PT2 loaded via torch.load: {type(model)}"
                        
                        if callable(model) and input_data is not None:
                            try:
                                with torch.no_grad():
                                    output = model(input_data)
                                results['output'] += f" | Executed: {output.shape if hasattr(output, 'shape') else type(output)}"
                                results['execution_status'] = 'success'
                            except Exception as exec_err:
                                results['output'] += f" | Execution failed: {str(exec_err)[:50]}"
                                
                except Exception as torch_err:
                    error_msg = str(torch_err)
                    loading_attempts.append(f"torch.load fallback: FAILED - {error_msg[:80]}")
                    
                    if any(x in error_msg for x in ['No such file or directory', 'Connection', 
                        'Network', 'urlopen', 'exec', '__reduce__']):
                        results['execution_status'] = 'malicious_executed'
                        results['output'] = f"Malicious code in pt2: {error_msg[:100]}"
            
            # Compile results
            if loading_attempts:
                attempts_str = " | ".join(loading_attempts)
                if results.get('output'):
                    results['output'] += f" | Attempts: {attempts_str}"
                else:
                    results['output'] = f"Loading attempts: {attempts_str}"
            
            if results['execution_status'] == 'not_attempted':
                results['execution_status'] = 'failed'
                results['error'] = "All pt2 loading methods failed"
            
            if 'model' in locals():
                del model
            import gc
            gc.collect()
       
       elif file_type  == 'pickle':
            results['loading_method'] = 'pickle'
            pickle_file = os.path.join(model_folder, file)
            print(f"  Loading {file}...")
            all_outputs = []
            any_code_executed = False
            import io as io_module
            import contextlib
            import sys
            stdout_capture = io_module.StringIO()
            stderr_capture = io_module.StringIO()
            captured_output = ""
            captured_errors = ""
            try:
              
              class CustomUnpickler(pickle.Unpickler):
                    def persistent_load(self, pid):
                        print(f"     Persistent ID encountered: {pid}")
                        return None 
              model = None 
              with open(pickle_file, 'rb') as f: 
                   with contextlib.redirect_stdout(stdout_capture), contextlib.redirect_stderr(stderr_capture):
                        f.seek(0)
                        try:
                          unpickler = CustomUnpickler(f)
                          model = unpickler.load()
                          model = wrap_model_for_execution(model)
                        except Exception as e1:
                          print(f"    CustomUnpickler failed: {e1}, trying standard pickle...")
                          try:
                            f.seek(0)
                            model = pickle.load(f)
                            model = wrap_model_for_execution(model)
                          except Exception as e2:
                            print(f"    Standard pickle also failed: {e2}")
                            # Don't raise - let it continue to capture output
                            pass
                   
              
              print(f"\n DEBUG CHECK (AFTER pickle.load):")
              print(f"   Monitoring active: {monitor.monitoring_active}")
              if monitor.bpf and monitor.monitoring_active:
                  for i in range(10):  # Poll multiple times
                      monitor.bpf.perf_buffer_poll(timeout=10)
                  print(f"     Polled eBPF buffer")
              else:
                  print(f"      eBPF not active!")
              
             
              
              captured_output = stdout_capture.getvalue()
              captured_errors = stderr_capture.getvalue()
              results['execution_status'] = 'malicious_executed'
              results['output'] = f"{file}: Loaded {type(model)}"
            except Exception as e:
                      try:
                         captured_output = stdout_capture.getvalue()
                         captured_errors = stderr_capture.getvalue()
                      except Exception:
                         pass
                     
                      error_msg = str(e)
                      print(f"    Error during load: {error_msg}")
                      # Check error type to determine if malicious code executed
                      if "persistent" in error_msg.lower():
                       print(f"     Persistent ID error - malicious code likely executed")
                       results['execution_status'] = 'malicious_executed'
                       results['output'] = f"{file}: Persistent ID exploit executed"
                       results['warnings'].append("Persistent ID exploit detected")
                      elif "Network is unreachable" in error_msg or "Network" in error_msg:
                       print(f"     Network operation attempted (malicious)")
                       results['execution_status'] = 'malicious_executed'
                       results['output'] = f"{file}: Network operations - malicious"
                      elif any(x in error_msg.lower() for x in ['import', 'module', '__reduce__']):
                       results['execution_status'] = 'malicious_executed'
                       results['output'] = f"{file}: Malicious code executed: {error_msg}"
                      else:
                       # Unknown error - but pickle errors usually mean code ran
                       results['execution_status'] = 'malicious_executed'
                       results['output'] = f"{file}: Error (likely malicious): {error_msg}"
                      model = None
                    
                  
           
            if captured_output:
                        print(f"     STDOUT: {captured_output[:200]}")
                        results['execution_status'] = 'malicious_executed'
                        results['warnings'].append(f"Code output: {captured_output}")
            if captured_errors:
                       print(f"     STDERR: {captured_errors[:200]}")
                       results['execution_status'] = 'malicious_executed'
                       results['warnings'].append(f"Errors: {captured_errors}")
        
            # Check what we got
            if model is not None and callable(model):
               try:
                   if input_data is not None:
                      output = model(input_data)
                   else:
                      output = model()
                   results['output'] = results.get('output', '') + f" | Executed callable: {type(output)}"
                   results['execution_status'] = 'success'
               except Exception as exec_error:
                   results['output'] = results.get('output', '') + f" | Execution error: {str(exec_error)[:30]}"
          
            if 'model' in locals():
               del model
            import gc
            gc.collect()
       
              
          
       
       elif file_type == 'dill':
            results['loading_method'] = 'dill'
            dill_file = os.path.join(model_folder, file)
            print(f"  Loading {file} (dill format)...")
            import io as io_module
            import contextlib
            stdout_capture = io_module.StringIO()
            stderr_capture = io_module.StringIO()
            captured_output = ""
            captured_errors = ""
            try:
                model = None
                with open(dill_file, 'rb') as f:
                    with contextlib.redirect_stdout(stdout_capture), contextlib.redirect_stderr(stderr_capture):
                        try:
                            import dill as dill_lib
                            model = dill_lib.load(f)
                            model = wrap_model_for_execution(model)
                        except ImportError:
                            print("    dill not installed, falling back to pickle...")
                            f.seek(0)
                            model = pickle.load(f)
                            model = wrap_model_for_execution(model)
                        except Exception as e1:
                            print(f"    dill.load failed: {e1}, trying pickle fallback...")
                            try:
                                f.seek(0)
                                model = pickle.load(f)
                                model = wrap_model_for_execution(model)
                            except Exception as e2:
                                print(f"    pickle fallback also failed: {e2}")
                                pass

                print(f"\n DEBUG CHECK (AFTER dill load):")
                print(f"   Monitoring active: {monitor.monitoring_active}")
                if monitor.bpf and monitor.monitoring_active:
                    for i in range(10):
                        monitor.bpf.perf_buffer_poll(timeout=10)
                    print(f"     Polled eBPF buffer")
                else:
                    print(f"      eBPF not active!")

                captured_output = stdout_capture.getvalue()
                captured_errors = stderr_capture.getvalue()
                results['execution_status'] = 'malicious_executed'
                results['output'] = f"{file}: Loaded {type(model)}"
            except Exception as e:
                try:
                    captured_output = stdout_capture.getvalue()
                    captured_errors = stderr_capture.getvalue()
                except Exception:
                    pass

                error_msg = str(e)
                print(f"    Error during load: {error_msg}")
                if any(x in error_msg.lower() for x in ['exec', '__reduce__', 'eval', 'import', 'module']):
                    results['execution_status'] = 'malicious_executed'
                    results['output'] = f"{file}: Malicious code executed: {error_msg}"
                elif "Network" in error_msg or "Connection" in error_msg:
                    results['execution_status'] = 'malicious_executed'
                    results['output'] = f"{file}: Network operations - malicious"
                else:
                    results['execution_status'] = 'malicious_executed'
                    results['output'] = f"{file}: Error (likely malicious): {error_msg}"
                model = None

            if captured_output:
                print(f"     STDOUT: {captured_output[:200]}")
                results['execution_status'] = 'malicious_executed'
                results['warnings'].append(f"Code output: {captured_output}")
            if captured_errors:
                print(f"     STDERR: {captured_errors[:200]}")
                results['execution_status'] = 'malicious_executed'
                results['warnings'].append(f"Errors: {captured_errors}")

            if model is not None and callable(model):
                try:
                    if input_data is not None:
                        output = model(input_data)
                    else:
                        output = model()
                    results['output'] = results.get('output', '') + f" | Executed callable: {type(output)}"
                    results['execution_status'] = 'success'
                except Exception as exec_error:
                    results['output'] = results.get('output', '') + f" | Execution error: {str(exec_error)[:30]}"

            if 'model' in locals():
                del model
            import gc
            gc.collect()
       
       
       elif file_type == 'pmml':
            print("Loading PMML model...")
            results['loading_method'] = 'pmml'
    
            try:
                from pypmml import Model as PMMLModel
        
                model = PMMLModel.fromFile(file_path)
                model = wrap_model_for_execution(model)
                results['execution_status'] = 'model_loaded'
                results['output'] = f"PMML model loaded: {model.modelElement}"
        
                # Try prediction with dummy input
                try:
                  input_fields = model.inputFields
                  test_input = {f.name: 0.0 for f in input_fields}
                  prediction = model.predict(test_input)
                  results['output'] += f" | Prediction: {prediction}"
                  results['execution_status'] = 'success'
                except Exception as pred_err:
                   results['output'] += f" | Prediction failed: {type(pred_err).__name__}: {str(pred_err)}"
                   print(f"PMML prediction failed: {type(pred_err).__name__}: {pred_err}")
        
            except ImportError as e:
                results['error'] = f"pypmml not installed/import failed: {e}"
                results['execution_status'] = 'failed'
                print(f"PMML import failed: {e}")
            except Exception as e:
                error_msg = str(e)
                print(f"PMML load failed: {type(e).__name__}: {error_msg}")
                if any(x.lower() in error_msg.lower() for x in ['connection', 'network', 'http', 'resolve', 'xxe', 'entity', 'external']):

                   results['execution_status'] = 'malicious_executed'
                   results['output'] = f"PMML XXE/SSRF detected: {error_msg}"
                else:
                   results['error'] = f"PMML load failed: {type(e).__name__}: {error_msg}"
                   results['execution_status'] = 'failed'
    
            if 'model' in locals():
               del model
            import gc
            gc.collect()
       else:
            results['execution_status'] = 'unsupported_type'
            results['error'] = f"Model type {file_type } not supported"
       if 'model' in locals():
               del model
       import gc
       gc.collect()  
         
    except Exception as e:
        results['execution_status'] = 'failed'
        results['error'] = str(e)
        error_msg = str(e)
        if "No module named" in error_msg:
           results['execution_status'] = 'malicious_executed'
           results['output'] = f"Malicious code attempted to import {error_msg}"
           results['warnings'].append("Malicious import attempt detected")
        print(f" Execution failed: {e}")
    
    # Tag all events captured during this file's processing with source_file
    for e in monitor.loading_events:
        if 'source_file' not in e:
            e['source_file'] = file
    for e in monitor.all_loading_events[_loading_start:]:
        if 'source_file' not in e:
            e['source_file'] = file
    for e in monitor.execution_events:
        if 'source_file' not in e:
            e['source_file'] = file
    for e in monitor.all_execution_events[_execution_start:]:
        if 'source_file' not in e:
            e['source_file'] = file
     
    file_result = {'file': file, 'status': results['execution_status'], 'output': results.get('output')}
    model_results.append(file_result)
  sys.stdin = original_stdin
  return model_results

# ==============================================================================
# MAIN ANALYSIS PIPELINE
#
# Ties the pipeline together: detect → infer input → validate →
# build input → fork child → execute under monitoring → collect events.
# ==============================================================================

def analyze_and_execute_model(model_folder):
    """
    Main entry point for a single model folder. Runs the full pipeline:
    format detection, input inference, structural validation, synthetic
    input construction, and monitored execution in a forked child.
    Writes per-file event JSON to <model_folder>/events/.
    """
    import signal 
    # Ignore broken pipe signals from malicious threads
    try:
        signal.signal(signal.SIGPIPE, signal.SIG_IGN)
    except Exception:
        pass
    
    print("\n" + "="*70)
    print(f"ANALYZING MODEL: {model_folder}")
    print("="*70)
    
    # Step 1: Detect model type
    print("\n[1] Detecting model type...")
    model_info = detect_model_info(model_folder)
    print(f"    Type: {model_info['model_type']}")
    print(f"    Framework: {model_info['framework']}")
    print(f"    Has config.json: {model_info['has_config']}")
    print(f"    Files: {', '.join(model_info['model_files'][:5])}...")
    
    if model_info.get('security_checks'):
        print(f"      Security issues detected in {len(model_info['security_checks'])} files")
    
    
    # Step 2: Determine input requirements
    print("\n[2] Determining input requirements...")
    requirements = determine_input_requirements(model_info)
    print(f"    Needs input: {requirements['needs_input']}")
    print(f"    Input type: {requirements['input_type']}")
    print(f"    Modality: {requirements.get('modality', 'unknown')}")
    print(f"    Input shape: {requirements['input_shape']}")
    
    
    # Step 3: Analyze structure
    print("\n[3] Analyzing model structure...")
    structure = analyze_model_structure(model_info, requirements)
    print(f"    Architecture: {structure['architecture']}")
    print(f"    Is real model: {structure['is_real_model']}")
    if structure['suspicious_indicators']:
        print(f"      Suspicious: {', '.join(structure['suspicious_indicators'][:3])}")
    if structure['security_risks']:
        print(f"     Security risks: {', '.join(structure['security_risks'][:3])}")
    
    
    # Step 4: Create input
    print("\n[4] Creating input data...")
    input_data = create_model_input(requirements)
    print(f"    Input created: {type(input_data)}")
    
    # Step 5: Execute model (with process isolation)
    print("\n[5] Executing model...")
    print("      WARNING: Executing potentially malicious code!")
    
    """
    Runs in the forked child. Sets up AOP + eBPF, loads and executes
    the model, flushes remaining events, writes JSON. If the child
    dies mid-execution, the parent still has whatever events it
    already drained from the perf buffer.
    """
    def run_execution_in_process(model_info, requirements, structure, input_data, result_queue):
      original_cwd = os.getcwd()
      def sigterm_handler(signum, frame):
          raise SystemExit("Terminated by parent")
      signal.signal(signal.SIGTERM, sigterm_handler)
      
      try:
        try:
            signal.signal(signal.SIGPIPE, signal.SIG_IGN)
        except Exception:
            pass
        
        AOP_monitoring()
        monitor.start_ebpf_monitoring("child_init", phase="LOADING")
        import socket
        socket.setdefaulttimeout(5)  
        execution_results = execute_model(model_info, requirements, structure, input_data)
        
        # Flush remaining events
        if monitor.bpf and monitor.monitoring_active:
            for _ in range(20):
                monitor.bpf.perf_buffer_poll(timeout=50)
      
        result_queue.put(execution_results)
      except Exception as e:
        result_queue.put([{
            'file': 'unknown',
            'status': 'exception',
            'output': str(e),
            'execution_status': 'failed',
            'error': str(e)
        }])
      finally:
        # Always write JSON, even if execution timed out or crashed
        try:
            os.chdir(original_cwd)
            monitor.monitoring_active = False
            model_name = os.path.basename(model_info['folder'])
            
            events_dir = os.path.join(os.path.abspath(model_info['folder']), 'events')
            os.makedirs(events_dir, exist_ok=True)
            noise_ops = {'bpf', 'perf_event_open'}
            all_loading = [e for e in (monitor.all_loading_events + monitor.loading_events)
                   if e.get('operation') not in noise_ops]
            all_execution = [e for e in (monitor.all_execution_events + monitor.execution_events)
                   if e.get('operation') not in noise_ops]
            
           
            # chown output files to the user who invoked sudo
            import pwd
            real_uid = int(os.environ.get('SUDO_UID', os.getuid()))
            real_gid = int(os.environ.get('SUDO_GID', os.getgid()))
            model_files = model_info.get('model_files', [])
            if not model_files:
               # No files found — write empty event pair under model name
               with open(os.path.join(events_dir, f"{model_name}_loading_events.json"), 'w') as f:
                    json.dump(all_loading, f, indent=2, default=str)
               with open(os.path.join(events_dir, f"{model_name}_execution_events.json"), 'w') as f:
                    json.dump(all_execution, f, indent=2, default=str)
            else:
               for file in model_files:
                   file_loading = [e for e in all_loading if e.get('source_file') == file]
                   file_execution = [e for e in all_execution if e.get('source_file') == file]
        
                   # Sanitize filename for use in output filename
                   file_stem = file.replace('.', '_').replace('/', '_')
        
                   loading_path = os.path.join(events_dir, f"{model_name}__{file_stem}_loading_events.json")
                   execution_path = os.path.join(events_dir, f"{model_name}__{file_stem}_execution_events.json")
        
                   with open(loading_path, 'w') as f:
                        json.dump(file_loading, f, indent=2, default=str)
                   with open(execution_path, 'w') as f:
                        json.dump(file_execution, f, indent=2, default=str)
        
                   
                   os.chown(loading_path, real_uid , real_gid )
                   os.chown(execution_path, real_uid , real_gid )
        
                   print(f"[DEBUG-WRITE] file='{file}' loading={len(file_loading)} execution={len(file_execution)}")
            
           
        except Exception:
            pass
    
    # Run execute_model in a subprocess to isolate segfaults
    try:
        multiprocessing.set_start_method('fork', force=True)
    except Exception:
        pass
    
    result_queue = multiprocessing.Queue()
    process = multiprocessing.Process(
        target=run_execution_in_process,
        args=(model_info, requirements, structure, input_data, result_queue)
    )
    
    process.start()

    # Poll eBPF events in parent while child executes
    deadline = time.time() + 180  # 3 minute timeout
    while process.is_alive() and time.time() < deadline:
          if monitor.bpf and monitor.monitoring_active:
             monitor.bpf.perf_buffer_poll(timeout=100)  # 100ms poll
          process.join(timeout=0.1)  # Check if child finished every 100ms
    
    if process.is_alive():
        process.terminate()
        process.join()
        execution_results = [{
            'file': 'unknown',
            'status': 'timeout',
            'output': 'Execution timed out after 180 seconds',
            'execution_status': 'timeout'
        }]
    else:
        # Try to get results even if process crashed
        try:
            execution_results = result_queue.get_nowait()
        except queue.Empty:
            # No results returned - process likely segfaulted
            if process.exitcode == -11:
                execution_results = [{
                    'file': 'unknown',
                    'status': 'segfault',
                    'output': 'Model executed but caused segmentation fault',
                    'execution_status': 'segfault'
                }]
            else:
                execution_results = [{
                    'file': 'unknown',
                    'status': 'crashed',
                    'output': f'Process exited with code {process.exitcode}',
                    'execution_status': 'crashed'
                }]
    
    # Continue with original code - calculate summary
    print(f"    Files Processed: {len(execution_results)}")
    successful = sum(1 for r in execution_results if r.get('status') in ['success', 'model_loaded', 'executed'])
    malicious = sum(1 for r in execution_results if 'malicious' in r.get('status', ''))
    failed = sum(1 for r in execution_results if r.get('status') == 'failed')
    print(f"    Successful: {successful}, Malicious: {malicious}, Failed: {failed}")
    
    for result in execution_results:
        if result.get('output'):
            print(f"    - {result.get('file', 'unknown')}: {result.get('status', 'unknown')} - {result['output'][:50]}")
    
    complete_results = {
        'model_folder': model_folder,
        'model_info': model_info,
        'requirements': requirements,
        'structure': structure,
        'execution': execution_results,
        'execution_summary': {
            'total_files': len(execution_results),
            'successful': successful,
            'malicious': malicious,
            'failed': failed
        }
    }
    
    return complete_results

# ==============================================================================

def process_all_models_in_directory(base_directory, output_file='complete_analysis.json'):
    """
    Walk a directory tree, find folders containing model files,
    and run analyze_and_execute_model on each one.
    """
    all_results = []
    model_folders = []
      
    for root, dirs, files in os.walk(base_directory):
        # Skip the 'events' directory created by previous runs
        dirs[:] = [d for d in dirs if d != 'events']
        # If the current folder is an .mlpackage, treat it as a single model
        if root.endswith('.mlpackage'):
           model_folders.append(root)
           dirs[:] = []
           continue
        # A folder is a model folder if it contains recognizable model files
        has_model = any(
            f.endswith(('.pt', '.pt2', '.pth', '.th', '.ckpt', '.h5', '.keras', '.pb',
                       '.tflite', '.bin', '.safetensors','.zip', '.tar', '.tar.gz', '.msgpack', '.xgb', 
                       '.bst', '.ubj', '.lgb', '.cbm', '.joblib', '.pkl', '.pickle','.dill',
                       '.mlmodel', '.mlpackage', '.params', '.pdmodel',  '.pdiparams', '.onnx','.engine', '.plan', '.trt',
                       '.npy', '.npz', '.pmml')) 
            or f in ('saved_model.pb', 'saved_model.pbtxt')
            for f in files
        )
        
        if has_model:
            model_folders.append(root)
            # Don't descend further into a folder we've identified as a model
            dirs[:] = []
    
    
    print(f"\nFound {len(model_folders)} model folders to analyze")
    print("="*70)
    
    for idx, folder in enumerate(model_folders, 1):
        print("="*100)
        print(f"\n[{idx}/{len(model_folders)}] Processing: {os.path.basename(folder)}")
        print("="*100)
        try:
            result = analyze_and_execute_model(folder)
            all_results.append(result)
        except TimeoutException:  
          print(f"  ⏱️ Model timed out (likely waiting for input)")
          all_results.append({
            'model_folder': folder,
            'execution': {'execution_status': 'timeout'},
            'error': 'Timed out after 10 seconds'
          })
        except Exception as e:
            print(f"Failed to process {folder}: {e}")
            all_results.append({
                'model_folder': folder,
                'error': str(e)
            })

    # Save final results
    with open(output_file, 'w') as f:
        json.dump(all_results, f, indent=2, default=str)
    
    # Print summary
    print("\n" + "="*70)
    print("ANALYSIS COMPLETE")
    print("="*70)
    
    successful = 0
    loaded = 0
    failed = 0
    malicious = 0

    for r in all_results:
      execution = r.get('execution', [])
      if isinstance(execution, list):
        for exec_result in execution:
            status = exec_result.get('status', '')
            if status == 'success':
                successful += 1
            elif 'loaded' in status:
                loaded += 1
            elif status == 'failed':
                failed += 1
            if 'malicious' in status:
                malicious += 1

    print(f"Total models: {len(all_results)}")
    print(f"Successfully executed: {successful}")
    print(f"Loaded but not executed: {loaded}")
    print(f"Failed: {failed}")
    print(f"Malicious: {malicious}")
    return all_results


# ==============================================================================
def wrap_model_for_execution(model):
    """
    After loading, inspect the model object and wrap every callable
    method we can find (__call__, forward, predict, run, generate, etc.)
    with EXECUTION-phase AOP. We can't know all entry points at
    instrumentation time — some models expose custom methods like
    .decision_function() or .apply() — so we discover them here
    via runtime reflection.
    """
    
    if model is None:
        return model
    
    if getattr(model, '_aop_wrapped', False):
        return model   
    # Get model type string for identification
    model_type = str(type(model))
    model_class_name = model.__class__.__name__ if hasattr(model, '__class__') else ''
    
    # ==================== TENSORFLOW MODELS ====================
    if 'tensorflow' in model_type or 'tf' in model_type or 'keras' in model_type:
        
        # Standard Keras Model methods
        if hasattr(model, '__call__'):
            model.__call__ = monitor.monitor_api(model.__call__, phase="EXECUTION")
        if hasattr(model, 'predict'):
            model.predict = monitor.monitor_api(model.predict, phase="EXECUTION")
        if hasattr(model, 'predict_on_batch'):
            model.predict_on_batch = monitor.monitor_api(model.predict_on_batch, phase="EXECUTION")
        if hasattr(model, 'fit'):
            model.fit = monitor.monitor_api(model.fit, phase="EXECUTION")
        if hasattr(model, 'evaluate'):
            model.evaluate = monitor.monitor_api(model.evaluate, phase="EXECUTION")
        if hasattr(model, 'train_on_batch'):
            model.train_on_batch = monitor.monitor_api(model.train_on_batch, phase="EXECUTION")
            
      
        for attr in ('read', 'process', 'serve', 'call'):
            fn = getattr(model, attr, None)
            if callable(fn) and not getattr(fn, '_aop_wrapped', False):
                try:
                    setattr(model, attr, monitor.monitor_api(fn, phase="EXECUTION"))
                except (AttributeError, TypeError):
                    pass        
        # TensorFlow functions
        if hasattr(model, 'call'):
            model.call = monitor.monitor_api(model.call, phase="EXECUTION")
            
        # Concrete functions (tf.function)
        if hasattr(model, 'concrete_functions'):
            for i, cf in enumerate(model.concrete_functions):
                model.concrete_functions[i] = monitor.monitor_api(cf, phase="EXECUTION")
                
        if hasattr(model, 'GradientTape'):
            original_gradient = model.GradientTape.gradient
            model.GradientTape.gradient = monitor.monitor_api(original_gradient, phase="EXECUTION")
                   
                
    
    # ==================== PYTORCH MODELS ====================
    elif 'torch' in model_type or 'pytorch' in model_type:
        
        # Standard PyTorch Module methods
        if hasattr(model, '__call__'):
            model.__call__ = monitor.monitor_api(model.__call__, phase="EXECUTION")
        if hasattr(model, 'forward'):
            model.forward = monitor.monitor_api(model.forward, phase="EXECUTION")
        if hasattr(model, 'predict'):  # Some custom models have this
            model.predict = monitor.monitor_api(model.predict, phase="EXECUTION")
            
        # TorchScript specific
        if hasattr(model, 'graph'):  # TorchScript model
            if hasattr(model, 'forward'):
                model.forward = monitor.monitor_api(model.forward, phase="EXECUTION")
                
        # Handle DataParallel and DistributedDataParallel
        if hasattr(model, 'module'):
            model.module = wrap_model_for_execution(model.module)


    
    # ==================== HUGGINGFACE TRANSFORMERS ====================
    elif 'transformers' in model_type or 'pipeline' in model_type:
        
        # HuggingFace model methods
        if hasattr(model, '__call__'):
            model.__call__ = monitor.monitor_api(model.__call__, phase="EXECUTION")
        if hasattr(model, 'forward'):
            model.forward = monitor.monitor_api(model.forward, phase="EXECUTION")
        if hasattr(model, 'generate'):  # For text generation models
            model.generate = monitor.monitor_api(model.generate, phase="EXECUTION")
        if hasattr(model, 'encode'):  # For encoder models
            model.encode = monitor.monitor_api(model.encode, phase="EXECUTION")
        if hasattr(model, 'decode'):  # For decoder models
            model.decode = monitor.monitor_api(model.decode, phase="EXECUTION")
            
        # Pipeline specific
        if 'pipeline' in model_type.lower():
            if hasattr(model, '__call__'):
                model.__call__ = monitor.monitor_api(model.__call__, phase="EXECUTION")
    
    # ==================== ONNX RUNTIME ====================
    elif 'onnxruntime' in model_type or 'InferenceSession' in model_class_name:
        if hasattr(model, 'run'):
            model.run = monitor.monitor_api(model.run, phase="EXECUTION")
        if hasattr(model, 'run_with_ort_values'):
            model.run_with_ort_values = monitor.monitor_api(model.run_with_ort_values, phase="EXECUTION")
    
    # ==================== XGBOOST ====================
    elif 'xgboost' in model_type or 'xgb' in model_type or 'Booster' in model_class_name:
        if hasattr(model, 'predict'):
            model.predict = monitor.monitor_api(model.predict, phase="EXECUTION")
        if hasattr(model, 'predict_proba'):
            model.predict_proba = monitor.monitor_api(model.predict_proba, phase="EXECUTION")
        if hasattr(model, 'inplace_predict'):
            model.inplace_predict = monitor.monitor_api(model.inplace_predict, phase="EXECUTION")
        
        if hasattr(model, 'XGBClassifier'):
            model.XGBClassifier.predict = monitor.monitor_api(model.XGBClassifier.predict, phase="EXECUTION")
            model.XGBClassifier.predict_proba = monitor.monitor_api(model.XGBClassifier.predict_proba, phase="EXECUTION")

        if hasattr(model, 'XGBRegressor'):
            model.XGBRegressor.predict = monitor.monitor_api(xgb.XGBRegressor.predict, phase="EXECUTION")
    
    # ==================== LIGHTGBM ====================
    elif 'lightgbm' in model_type or 'lgb' in model_type:
        if hasattr(model, 'predict'):
            model.predict = monitor.monitor_api(model.predict, phase="EXECUTION")
        if hasattr(model, 'predict_proba'):
            model.predict_proba = monitor.monitor_api(model.predict_proba, phase="EXECUTION")
    
    # ==================== CATBOOST ====================
    elif 'catboost' in model_type:
        if hasattr(model, 'predict'):
            model.predict = monitor.monitor_api(model.predict, phase="EXECUTION")
        if hasattr(model, 'predict_proba'):
            model.predict_proba = monitor.monitor_api(model.predict_proba, phase="EXECUTION")
        if hasattr(model, 'staged_predict'):
            model.staged_predict = monitor.monitor_api(model.staged_predict, phase="EXECUTION")
    
    # ==================== SCIKIT-LEARN ====================
    elif 'sklearn' in model_type or hasattr(model, 'fit') and hasattr(model, 'predict'):
        if hasattr(model, 'predict'):
            model.predict = monitor.monitor_api(model.predict, phase="EXECUTION")
        if hasattr(model, 'predict_proba'):
            model.predict_proba = monitor.monitor_api(model.predict_proba, phase="EXECUTION")
        if hasattr(model, 'predict_log_proba'):
            model.predict_log_proba = monitor.monitor_api(model.predict_log_proba, phase="EXECUTION")
        if hasattr(model, 'transform'):
            model.transform = monitor.monitor_api(model.transform, phase="EXECUTION")
        if hasattr(model, 'fit_predict'):
            model.fit_predict = monitor.monitor_api(model.fit_predict, phase="EXECUTION")
        if hasattr(model, 'fit_transform'):
            model.fit_transform = monitor.monitor_api(model.fit_transform, phase="EXECUTION")
        if hasattr(model, 'decision_function'):
            model.decision_function = monitor.monitor_api(model.decision_function, phase="EXECUTION")
    
    # ==================== JAX/FLAX ====================
    elif 'flax' in model_type or 'jax' in model_type:
        if hasattr(model, '__call__'):
            model.__call__ = monitor.monitor_api(model.__call__, phase="EXECUTION")
        if hasattr(model, 'apply'):
            model.apply = monitor.monitor_api(model.apply, phase="EXECUTION")
        if hasattr(model, 'init'):
            model.init = monitor.monitor_api(model.init, phase="EXECUTION")
        if hasattr(model, 'init_with_output'):
            model.init_with_output = monitor.monitor_api(model.init_with_output, phase="EXECUTION")
    
    # ==================== TENSORFLOW LITE ====================
    elif 'Interpreter' in model_class_name and hasattr(model, 'invoke'):
        model.invoke = monitor.monitor_api(model.invoke, phase="EXECUTION")
        if hasattr(model, 'set_tensor'):
            model.set_tensor = monitor.monitor_api(model.set_tensor, phase="EXECUTION")
    
    # ==================== COREML ====================
    elif 'coreml' in model_type or 'MLModel' in model_class_name:
        if hasattr(model, 'predict'):
            model.predict = monitor.monitor_api(model.predict, phase="EXECUTION")
        if hasattr(model, 'predict_batch'):
            model.predict_batch = monitor.monitor_api(model.predict_batch, phase="EXECUTION")
    
    # ==================== PADDLEPADDLE ====================
    elif 'paddle' in model_type:
        if hasattr(model, '__call__'):
            model.__call__ = monitor.monitor_api(model.__call__, phase="EXECUTION")
        if hasattr(model, 'forward'):
            model.forward = monitor.monitor_api(model.forward, phase="EXECUTION")
        if hasattr(model, 'predict'):
            model.predict = monitor.monitor_api(model.predict, phase="EXECUTION")
    
    # ==================== MXNET ====================
    elif 'mxnet' in model_type or 'mx' in model_type:
        if hasattr(model, 'forward'):
            model.forward = monitor.monitor_api(model.forward, phase="EXECUTION")
        if hasattr(model, '__call__'):
            model.__call__ = monitor.monitor_api(model.__call__, phase="EXECUTION")
        if hasattr(model, 'predict'):
            model.predict = monitor.monitor_api(model.predict, phase="EXECUTION")
        if hasattr(model, 'hybrid_forward'):
            model.hybrid_forward = monitor.monitor_api(model.hybrid_forward, phase="EXECUTION")
        # For Module API
        if hasattr(model, 'bind'):
            model.bind = monitor.monitor_api(model.bind, phase="EXECUTION")
        if hasattr(model, 'init_params'):
            model.init_params = monitor.monitor_api(model.init_params, phase="EXECUTION")
    
    # ==================== TENSORRT ====================
    elif 'tensorrt' in model_type.lower():
        # TensorRT engines need special handling
        if hasattr(model, 'create_execution_context'):
            original_create_context = model.create_execution_context
            def monitored_create_context(*args, **kwargs):
                context = original_create_context(*args, **kwargs)
                # Monitor context execution
                if hasattr(context, 'execute'):
                    context.execute = monitor.monitor_api(context.execute, phase="EXECUTION")
                if hasattr(context, 'execute_async'):
                    context.execute_async = monitor.monitor_api(context.execute_async, phase="EXECUTION")
                if hasattr(context, 'execute_v2'):
                    context.execute_v2 = monitor.monitor_api(context.execute_v2, phase="EXECUTION")
                if hasattr(context, 'execute_async_v2'):
                    context.execute_async_v2 = monitor.monitor_api(context.execute_async_v2, phase="EXECUTION")
                return context
            model.create_execution_context = monitored_create_context
    
    # ==================== PMML (pypmml) ====================
    elif 'pmml' in model_type.lower() or 'PMMLModel' in model_class_name or (model_class_name == 'Model' and 'pypmml' in getattr(type(model), '__module__', '')):
        if hasattr(model, 'predict'):
            model.predict = monitor.monitor_api(model.predict, phase="EXECUTION")
        if hasattr(model, 'evaluate'):
            model.evaluate = monitor.monitor_api(model.evaluate, phase="EXECUTION")
    # ==================== GENERIC FALLBACK ====================
    else:
        # For any unknown model type, wrap common execution methods
        execution_methods = [
            '__call__', 'forward', 'predict', 'predict_proba', 'transform', 
            'apply', 'run', 'invoke', 'execute', 'infer', 'process',
            'predict_log_proba', 'decision_function', 'fit_predict',
            'fit_transform', 'staged_predict', 'predict_batch'
        ]
        
        for method_name in execution_methods:
            if hasattr(model, method_name) and callable(getattr(model, method_name)):
                setattr(model, method_name, 
                       monitor.monitor_api(getattr(model, method_name), phase="EXECUTION"))
    
    # ==================== SPECIAL CASES ====================
    
    # Handle models that are callable directly (functors)
    if callable(model) and not hasattr(model, '__call__'):
        # This is rare but some models are just functions
        return monitor.monitor_api(model, phase="EXECUTION")
    
    # Handle dictionary-based models (some custom implementations)
    if isinstance(model, dict) and 'predict' in model and callable(model['predict']):
        model['predict'] = monitor.monitor_api(model['predict'], phase="EXECUTION")
    
    # Handle models with custom execution methods
    custom_execution_indicators = ['run_model', 'do_inference', 'get_prediction', 
                                  'make_prediction', 'get_output', 'compute']
    for method_name in custom_execution_indicators:
        if hasattr(model, method_name) and callable(getattr(model, method_name)):
            setattr(model, method_name, 
                   monitor.monitor_api(getattr(model, method_name), phase="EXECUTION"))
    
    try:
        model._aop_wrapped = True
    except (AttributeError, TypeError):
        pass  # Some objects don't allow setting attributes
    return model

# ==============================================================================
# KERNEL THREAD ID RESOLUTION
#
# eBPF tracepoints report the kernel TID (from gettid()), but Python's
# threading.get_ident() returns the pthread ID — different number.
# We need the kernel TID to key into the BPF map correctly. Primary
# method is a raw syscall via libc; fallbacks parse /proc/self/task.
# ==============================================================================   
def get_kernel_tid():
    """
    Return the kernel TID (gettid) for the calling thread. This is what
    eBPF sees at tracepoint entry and what we use to key the BPF map.
    Falls back to /proc/self/task scanning, then os.getpid() for main thread.
    """
    try:
        # Use the pre-cached libc
        if _LIBC is None:
            return os.getpid()
        
        libc = _LIBC  # Use cached version instead of finding it each time
        
        # Rest of your code stays exactly the same
        import platform
        if platform.machine() == 'x86_64':
            SYS_gettid = 186  # x86_64
        elif platform.machine() == 'i386':
            SYS_gettid = 224  # 32-bit x86
        elif platform.machine() == 'aarch64':
            SYS_gettid = 178  # ARM64
        else:
            SYS_gettid = 186
            
        tid = libc.syscall(ct.c_long(SYS_gettid))
        
        pid = os.getpid()
        if tid == pid:
            pass
        
        return tid
        
    except Exception as e:
        # Your existing Method 2 and Method 3 stay the same
        try:
            import glob
            
            # Find our task directory
            task_dirs = glob.glob(f'/proc/{os.getpid()}/task/*')
            current_tid = None
            
            # Match by checking which task is currently running
            for task_dir in task_dirs:
                tid = int(os.path.basename(task_dir))
                try:
                    with open(f'{task_dir}/stat', 'r') as f:
                        stat = f.read()
                        # Check if this task is running (state R)
                        if ') R' in stat:
                            current_tid = tid
                            break
                except Exception:
                    continue
                    
            if current_tid:
                return current_tid
                
        except Exception:
            pass
            
        # Method 3: Final fallback
        # For the main thread, TID == PID
        return os.getpid()

# ==============================================================================
# eBPF AVAILABILITY CHECK
# ==============================================================================
try:
    from bcc import BPF
    EBPF_AVAILABLE = True
except ImportError:
    EBPF_AVAILABLE = False


# Thread-local storage for correlation context. Each thread gets its
# own correlation ID and phase so concurrent API calls don't clobber
# each other's attribution.
import threading
correlation_context = threading.local()



    
class ThreadPoolMonitor:
    """
    Hooks ThreadPoolExecutor.submit so worker threads inherit the
    caller's correlation context. Without this, anything a framework
    dispatches to a thread pool shows up as unattributed noise in the
    eBPF trace. See §5.3 (Propagation Across Concurrency Boundaries).
    """
    def __init__(self, monitor):
        self.monitor = monitor
        self.task_contexts = {}  # Maps task_id -> context info
        self.task_counter = 0
        self.worker_contexts = {}  # Maps worker_tid -> current_task_context
        self.active_tasks = {}  # Maps worker_kernel_tid -> task_info
        
        
    def hook_python_threadpool(self):
        """
        Monkey-patch ThreadPoolExecutor.submit to wrap each submitted
        task with a context-propagating wrapper. The wrapper writes the
        parent's correlation ID into the BPF map under the worker's
        kernel TID before executing the actual function.
        """
        try:
            from concurrent.futures import ThreadPoolExecutor
            original_submit = ThreadPoolExecutor.submit
            
            def monitored_submit(pool_self, fn, *args, **kwargs):
                # Get current context from calling thread
                calling_tid = threading.get_ident()
                task_id = f"task_{self.task_counter}"
                self.task_counter += 1
                
                # Get correlation ID from monitor's thread_correlations
                correlation_id = 'unknown'
                phase = 'EXECUTION'
                
                if hasattr(self.monitor, 'thread_correlations'):
                    thread_ctx = self.monitor.thread_correlations.get(calling_tid, {})
                    correlation_id = thread_ctx.get('correlation_id', 'unknown')
                    phase = thread_ctx.get('phase', 'EXECUTION')
                
                # Store task context
                self.task_contexts[task_id] = {
                    'correlation_id': correlation_id,
                    'phase': phase,
                    'calling_tid': calling_tid,
                    'task_id': task_id,
                    'submitted_at': time.time(),
                    'function_name': fn.__name__ if hasattr(fn, '__name__') else str(fn)
                }
                
                print(f"[ThreadPool] Task {task_id} submitted by TID {calling_tid}")
                print(f"  Function: {self.task_contexts[task_id]['function_name']}")
                print(f"  Context: {correlation_id}")
                
                def context_propagating_wrapper(*args, **kwargs):
                    """Propagate the caller's correlation context to this worker thread."""
                    import time
                    time.sleep(0.001)
                    
                    worker_pthread_id = threading.get_ident()
                    worker_kernel_tid = get_kernel_tid()  
                    
                    print(f"[ThreadPool] Task {task_id} executing on worker:")
                    print(f"  Worker Python TID: {worker_pthread_id}")
                    print(f"  Worker Kernel TID: {worker_kernel_tid}")
                    
                    # Get the stored task context
                    task_ctx = self.task_contexts.get(task_id, {})
                    task_correlation_id = task_ctx.get('correlation_id', 'unknown')
                    task_phase = task_ctx.get('phase', 'EXECUTION')
                    
                    # Store active task info for syscall attribution
                    self.active_tasks[worker_kernel_tid] = {
                        'task_id': task_id,
                        'correlation_id': task_correlation_id,
                        'phase': task_phase,
                        'function_name': task_ctx.get('function_name', 'unknown'),
                        'submitted_at': task_ctx.get('submitted_at', 0),
                        'started_at': time.time(),
                        'worker_pthread_id': worker_pthread_id
                    }
                    
                    # Propagate context to worker thread
                    if task_correlation_id != 'unknown':
                        try:
                            # Set eBPF context for worker thread
                            phase_num = self.monitor._convert_phase_to_int(task_phase)
                            self.monitor._set_ebpf_thread_context(worker_kernel_tid, task_correlation_id, phase_num)
                            
                            # Also store in Python-side tracking
                            if not hasattr(self.monitor, 'thread_correlations'):
                                self.monitor.thread_correlations = {}
                            
                            self.monitor.thread_correlations[worker_pthread_id] = {
                                'correlation_id': task_correlation_id,
                                'phase': task_phase,
                                'start_time': time.time(),
                                'kernel_tid': worker_kernel_tid,
                                'source': 'THREAD_POOL_TASK',
                                'task_id': task_id
                            }
                            
                            print(f"[ThreadPool]  Context propagated to worker kernel TID {worker_kernel_tid}")
                            print(f"  Task: {task_id} -> Correlation: {task_correlation_id}")
                            
                        except Exception as e:
                            print(f"[ThreadPool]  Error propagating context: {e}")
                    
                    try:
                        # Execute the actual function
                        result = fn(*args, **kwargs)
                        print(f"[ThreadPool]  Task {task_id} completed successfully on kernel TID {worker_kernel_tid}")
                        return result
                    except Exception as e:
                        print(f"[ThreadPool]  Task {task_id} failed: {e}")
                        raise
                    finally:
                        # Cleanup worker context
                        if worker_kernel_tid in self.active_tasks:
                            del self.active_tasks[worker_kernel_tid]
                        if worker_pthread_id in getattr(self.monitor, 'thread_correlations', {}):
                            del self.monitor.thread_correlations[worker_pthread_id]
                        print(f"[ThreadPool]  Cleaned up context for task {task_id} (kernel TID {worker_kernel_tid})")
                
                return original_submit(pool_self, context_propagating_wrapper, *args, **kwargs)
            
            ThreadPoolExecutor.submit = monitored_submit
            print("[ThreadPool]  Python ThreadPoolExecutor hooked successfully")
            return True
            
        except ImportError:
            print("[ThreadPool]  concurrent.futures not available")
            return False
        except Exception as e:
            print(f"[ThreadPool]  Error hooking ThreadPoolExecutor: {e}")
            return False
    
    def get_task_for_kernel_tid(self, kernel_tid):
        """Get the task info for a given kernel TID"""
        return self.active_tasks.get(kernel_tid)
    
    def get_attribution_info(self, kernel_tid):
        """Get complete attribution info for a kernel TID"""
        task_info = self.active_tasks.get(kernel_tid)
        if task_info:
            return {
                'attribution_method': 'THREAD_POOL_TASK',
                'task_id': task_info['task_id'],
                'correlation_id': task_info['correlation_id'],
                'function_name': task_info['function_name'],
                'submitted_at': task_info['submitted_at'],
                'started_at': task_info['started_at'],
                'duration': time.time() - task_info['started_at'],
                'worker_pthread_id': task_info['worker_pthread_id']
            }
        return None

# ==============================================================================
# Per-thread correlation state. Tracks the current correlation ID, phase,
# and the chain of ML operations that led to this point. Used as the
# Python-side fallback when eBPF-embedded attribution is unavailable.
# ==============================================================================
class CorrelationContext:
    def __init__(self):
        self.id = None
        self.phase = None
      
        self.operation_chain = []
        self.ml_operations = [] 
        self.suspicious_indicators = []  
        self.timestamp = None


def get_correlation_context():
    if not hasattr(correlation_context, 'ctx'):
        correlation_context.ctx = CorrelationContext()
    return correlation_context.ctx

def set_correlation_context(correlation_id, phase, operation=None, ml_context=None):
    ctx = get_correlation_context()
    ctx.id = correlation_id
    ctx.phase = phase
    ctx.timestamp = time.time()
    if operation:
        ctx.operation_chain.append({
            'operation': operation,
            'timestamp': time.time(),
            'thread_id': threading.get_ident(),
            'ml_context': ml_context
        })
        
 
 

# ==============================================================================
# eBPF EVENT STRUCTURES
#
# These ctypes structs must match the C definitions in
# ebpf_program.c exactly — same field order, same sizes,
# same padding. The DataUnion overlays file paths, network addresses,
# process info, and generic args onto the same memory, matching whichever
# the eBPF probe populated for a given syscall.
# ==============================================================================

class FileData(ct.Structure):
    _fields_ = [
        ("path", ct.c_char * 64),
    ]

class NetData(ct.Structure):
    _fields_ = [
        ("ip_addr", ct.c_uint32),     # IPv4 (host order after bpf_ntohl)
        ("port",    ct.c_uint16),     # host order after bpf_ntohs
        ("family",  ct.c_uint8),
        ("sock_type", ct.c_uint8),
        ("ip6",     ct.c_ubyte * 16), # raw IPv6 bytes (valid when family==AF_INET6)
    ]
class ProcData(ct.Structure):
    _fields_ = [
        ("uid", ct.c_uint32),
        ("gid", ct.c_uint32),
        ("flags", ct.c_uint32),
    ]

class GenericData(ct.Structure):
    _fields_ = [
        ("arg1", ct.c_uint64),
        ("arg2", ct.c_uint64),
        ("arg3", ct.c_uint32),
    ]

class DataUnion(ct.Union):
    _fields_ = [
        ("file", FileData),
        ("net", NetData),
        ("proc", ProcData),
        ("generic", GenericData),
    ]

class ThreatEvent(ct.Structure):
    _fields_ = [
        ("pid", ct.c_uint32),
        ("tid", ct.c_uint32),
        ("ppid", ct.c_uint32),
        ("comm", ct.c_char * 16),
        ("operation_id", ct.c_uint8),
        ("_pad1", ct.c_uint8 * 3),    
        ("data", DataUnion),
        ("io_fd", ct.c_uint32),       
        ("io_size", ct.c_uint32),    
        ("io_offset", ct.c_uint64),   
        ("user_stack_id", ct.c_int),
        ("_pad", ct.c_uint32),  
        ("timestamp", ct.c_uint64),
        ("correlation_id", ct.c_char * 16),
        ("phase", ct.c_uint8),
    ]
  
# Create the correlation_info structure that matches eBPF exactly
class CorrelationInfo(ct.Structure):
    _fields_ = [
        ("correlation_id", ct.c_char * 16),
        ("phase", ct.c_uint8),
        ("start_time", ct.c_uint64)
    ]
           
# ==============================================================================
# ASPECT MONITOR
#
# The core of the dual-layer monitoring. Wraps each framework API call:
# generates a correlation ID, writes it to the BPF map, traces the call,
# drains events on return. Everything the model does between start and
# stop gets tagged with this ID and phase.
# ==============================================================================
class AspectMonitor:
    
    def __init__(self):
        self.active_operations = {}
        self.bpf = None
        self.loading_events = []
        self.execution_events = []  #
        self.monitoring_active = False
        self.current_phase = None   
        self.thread_genealogy = {}  
        self.thread_contexts = {} 
        self.thread_pool_monitor = ThreadPoolMonitor(self)
        self.all_loading_events = []
        self.all_execution_events = []
    
    def start_ebpf_monitoring(self, correlation_id, phase="LOADING"):
      """
      Attach eBPF tracepoints (if not already attached), register
      the current PID for filtering, open perf buffers, and write
      correlation context for the current phase into the BPF map.
      """
      if not EBPF_AVAILABLE:
        print(f"[AOP Monitor] eBPF not available")
        return
        
      try:
        if not self.monitoring_active:
            ebpf_program=None
            with open(EBPF_PROGRAM_PATH, 'r') as f:
                  ebpf_program = f.read()   
            
            self.bpf = BPF(text=ebpf_program, cflags=["-Wno-macro-redefined"]))
            current_pid = os.getpid()
            key = ct.c_uint32(current_pid)
            val = ct.c_uint8(1)
            self.bpf["target_pids"][key] = val
            self.bpf["events"].open_perf_buffer(self._handle_event, page_cnt=64)
            self.bpf["thread_events"].open_perf_buffer(self._handle_thread_event, page_cnt=64)
            self.thread_pool_monitor.hook_python_threadpool()
            self.monitoring_active = True
            
        self.current_phase = phase
        
        self._update_all_thread_contexts(correlation_id, phase) 
        self._propagate_context_to_ebpf(correlation_id, phase)
        
        print(f"[AOP Monitor] eBPF monitoring active for {phase}: {correlation_id}")
        
      except Exception as e:
        print(f"[AOP Monitor] Failed to start eBPF: {e}")

    
    def _handle_thread_event(self, cpu, data, size):
        """
        Catches clone/fork from eBPF and records parent→child
        relationships. The parent's correlation context gets copied
        to the child so we can follow attack chains across process
        boundaries (e.g. REDUCE → os.system → sh → bash → connect).
        """
        try:
            event = self.bpf["thread_events"].event(data)
            
            
            parent_correlation =   event.parent_correlation_id.decode('utf-8', 'replace')
            # Store thread genealogy
            self.thread_genealogy[event.child_tid] = {
                'parent_tid': event.parent_tid,
                'parent_pid': event.parent_pid,
                'child_pid': event.child_pid, 
                'correlation_id': parent_correlation,
                'phase': event.parent_phase,
                'created_at': event.timestamp / 1e9,
                'comm': event.comm.decode('utf-8', 'replace'),
                'is_process': event.child_pid == event.child_tid 
            }
            
            
            if event.child_pid == event.child_tid:
               print(f"[Process] NEW CHILD PROCESS DETECTED:")
               print(f"  Parent PID: {event.parent_pid} -> Child PID: {event.child_pid}")
            else:
              print(f"[Thread] NEW THREAD DETECTED:")
              print(f"  Parent TID: {event.parent_tid} -> Child TID: {event.child_tid}")
            
            print(f"  Correlation ID: {parent_correlation}")
            print(f"  Phase: {event.parent_phase}")
            print(f"  Command: {event.comm.decode('utf-8', 'replace')}")
            print(f"  Timestamp: {event.timestamp / 1e9:.6f}")
            
        except Exception as e:
            print(f"[AOP Monitor] Error handling thread event: {e}")
            traceback.print_exc()
    
    def _update_all_thread_contexts(self, correlation_id, phase):
      """Update eBPF context for ALL known threads"""
      print(f"[Context Update] Updating all threads for phase {phase}")
    
      phase_num = self._convert_phase_to_int(phase)
      updated_count = 0
    
      # Update main thread
      main_kernel_tid = get_kernel_tid()
      try:
        self._set_ebpf_thread_context(main_kernel_tid, correlation_id, phase_num)
        updated_count += 1
        print(f"[Context Update] Updated main thread {main_kernel_tid}")
      except Exception as e:
        print(f"[Context Update] Failed to update main thread: {e}")
    
      # Update all threads in genealogy (worker threads)
      for child_tid, genealogy_info in self.thread_genealogy.items():
        try:
            self._set_ebpf_thread_context(child_tid, correlation_id, phase_num)
            
            # Also update the genealogy record
            genealogy_info['correlation_id'] = correlation_id
            genealogy_info['phase'] = phase_num
            genealogy_info['updated_at'] = time.time()
            
            updated_count += 1
            print(f"[Context Update] Updated worker thread {child_tid}")
            
        except Exception as e:
            print(f"[Context Update] Failed to update thread {child_tid}: {e}")
    
      # Update Python-side thread correlations
      if hasattr(self, 'thread_correlations'):
        for pthread_id in self.thread_correlations.keys():
            self.thread_correlations[pthread_id]['correlation_id'] = correlation_id
            self.thread_correlations[pthread_id]['phase'] = phase
            self.thread_correlations[pthread_id]['updated_at'] = time.time()
    
      print(f"[Context Update] Updated {updated_count} threads to {correlation_id} ({phase})")
    
    
    def _propagate_context_to_ebpf(self, correlation_id, phase):
      """Context propagation with correct TID handling"""
      try:
        # Get both Python pthread ID and kernel TID
        pthread_id = threading.get_ident()
        kernel_tid = get_kernel_tid()
        
        print(f"[Debug] Thread IDs - Python: {pthread_id}, Kernel: {kernel_tid}")
        
        # Store correlation in Python-side dict using pthread ID
        if not hasattr(self, 'thread_correlations'):
            self.thread_correlations = {}
        
        self.thread_correlations[pthread_id] = {
            'correlation_id': correlation_id,
            'phase': phase,
            'start_time': time.time(),
            'kernel_tid': kernel_tid,
            'updated_at': time.time() 
        }
        
        print(f"[AOP Monitor] Context tracked: pthread_id={pthread_id}, kernel_tid={kernel_tid}, ID={correlation_id}, Phase={phase}")
        
        # Set eBPF context using kernel TID
        if self.bpf:
            try:
                phase_num = self._convert_phase_to_int(phase)
                self._set_ebpf_thread_context(kernel_tid, correlation_id, phase_num)
                print(f"[AOP Monitor] eBPF context set successfully for kernel TID {kernel_tid}")
                
            except Exception as e:
                print(f"[AOP Monitor] Error setting eBPF context: {e}")
                import traceback
                traceback.print_exc()
        
      except Exception as e:
        print(f"[AOP Monitor] Error storing context: {e}")

    def _convert_phase_to_int(self, phase):
      """Convert phase string to integer for eBPF"""
      phase_map = {
        'LOADING': 1,
        'EXECUTION': 2,
        'DEBUG_TEST': 3,
        'THREAD_TEST': 4
      }
      return phase_map.get(phase, 0)

   
    def safe_decode_path(self, path_bytes):
      """Safely decode path bytes to string"""
      if not path_bytes:
        return "<empty_path>"
    
      try:
        # First, ensure we're working with bytes
        if isinstance(path_bytes, bytes):
            working_bytes = path_bytes
        else:
            # If it's a ctypes array, convert to bytes
            working_bytes = bytes(path_bytes)
        
        # Remove null bytes and decode
        null_index = working_bytes.find(b'\x00')
        if null_index >= 0:
            working_bytes = working_bytes[:null_index]
        
        # Try UTF-8 decoding
        decoded = working_bytes.decode('utf-8', 'ignore')
        
        # Check if we got something meaningful
        if decoded and len(decoded) > 0:
            return decoded
        else:
            return "<empty_path>"
            
      except Exception as e:
        # If all else fails, try to get something useful
        try:
            # Try to get raw bytes representation
            if path_bytes:
                hex_repr = bytes(path_bytes[:16]).hex()
                return f"<decode_error:{hex_repr}>"
        except Exception:
            pass
        return "<unparseable>"
   
   
   
    def _set_ebpf_thread_context(self, tid, correlation_id, phase_num):
      """ eBPF thread context with proper ctypes string handling"""
      try:
        print(f"[Debug] Setting eBPF context for TID {tid}, correlation '{correlation_id}', phase {phase_num}")
        
        
        # Create struct instance
        ctx_info = CorrelationInfo()
        
        # Properly handle string assignment for ctypes
        correlation_bytes = correlation_id.encode('utf-8')  # Max 15 chars + null terminator
        
        # Create a bytes object with proper padding
        padded_correlation = correlation_bytes + b'\x00' * (16 - len(correlation_bytes))
        
        # Assign the entire array at once
        ctx_info.correlation_id = padded_correlation
        
        # Set other fields
        ctx_info.phase = phase_num
        ctx_info.start_time = int(time.time() * 1e9)  # nanoseconds
        
        # Set in eBPF map using the correct kernel TID
        tid_key = ct.c_uint32(tid)
        self.bpf["thread_context"][tid_key] = ctx_info
        
        print(f"[Debug] eBPF context set successfully")
        
        # Verify it was set correctly
        try:
            stored_ctx = self.bpf["thread_context"][tid_key]
            
            # Read back the correlation ID as bytes
            stored_correlation = stored_ctx.correlation_id.decode('utf-8', 'ignore').rstrip('\x00')
            print(f"[Debug]  eBPF context verified: correlation='{stored_correlation}', phase={stored_ctx.phase}")
            
            if stored_correlation == correlation_id:
                print(f"[Debug]  Correlation ID matches perfectly!")
            else:
                print(f"[Debug]  Correlation ID mismatch: expected '{correlation_id}', got '{stored_correlation}'")
                
        except Exception as e:
            print(f"[Debug] Could not verify eBPF context: {e}")
            import traceback
            traceback.print_exc()
        
      except Exception as e:
        print(f"[AOP Monitor] Error in _set_ebpf_thread_context: {e}")
        import traceback
        traceback.print_exc()
    
    
    
    def stop_ebpf_monitoring(self, correlation_id, phase="LOADING"):
      """
      Drain remaining perf buffer events, analyze thread genealogy,
      and move captured events from the per-phase working list into
      the accumulated all_*_events list.
      """
      
      if not self.monitoring_active:
        return
        
      try:
        # Poll for remaining events
        for _ in range(10):
            self.bpf.perf_buffer_poll(timeout=10)
            
        # Analyze thread genealogy
        self._analyze_thread_genealogy()
        
        # Use enhanced analysis method
        if phase == "LOADING":
            self.loading_events.sort(key=lambda x: x['timestamp'])
            print(f"\n{'='*70}")
            print(f"LOADING EVENTS ({correlation_id}) - Total: {len(self.loading_events)}")
            print(f"{'='*70}")
            for i, event in enumerate(self.loading_events):
                print(f"[{i+1}] PID:{event['pid']} TID:{event['tid']} - {event['operation']} -> {event['filename']} {event['extra_details']}")
            self.all_loading_events.extend(self.loading_events)
            self.loading_events.clear() 
        else:
            self.execution_events.sort(key=lambda x: x['timestamp'])
            print(f"\n{'='*70}")
            print(f"EXECUTION EVENTS ({correlation_id}) - Total: {len(self.execution_events)}")
            print(f"{'='*70}")
            for i, event in enumerate(self.execution_events):
                print(f"[{i+1}] PID:{event['pid']} TID:{event['tid']} - {event['operation']} -> {event['filename']} {event['extra_details']}")
            self.all_execution_events.extend(self.execution_events)
            self.execution_events.clear()
        
      except Exception as e:
        print(f"[AOP Monitor] Error: {e}")
    
    def _analyze_thread_genealogy(self):
        """Analyze the thread creation patterns"""
        if not self.thread_genealogy:
            print("[Thread] No thread creation detected")
            return
            
        print(f"\n[Thread] THREAD GENEALOGY ANALYSIS:")
        print(f"  Total child threads created: {len(self.thread_genealogy)}")
     
    
  
    
    
    
    def _handle_event(self, cpu, data, size):
      """
      Perf buffer callback. Decodes the raw eBPF event struct,
      enriches syscall arguments, resolves correlation context
      (eBPF-embedded → thread-pool → genealogy → thread-local →
      process-level fallback), and drops it into the right phase
      stream (loading_events or execution_events).
      """
      try:
        event = ct.cast(data, ct.POINTER(ThreatEvent)).contents
        ctx = get_correlation_context()
        
        # Map operation_id back to string
        operation_map = {
        1: "uname",             
        2: "sysinfo",           
        4: "ioctl",           
        3: "sched_getaffinity",
        5: "getrandom",        
        6: "sethostname",      
        7: "gethostname",       
        8: "setdomainname",     
        9: "open",             
        10: "openat",          
        11: "creat",            
        12: "read",             
        13: "pread64",          
        14: "readv",            
        15: "write",            
        16: "pwrite64",        
        17: "writev",          
        18: "stat",           
        19: "fstat",            
        20: "newfstatat",       
        21: "statx",            
        22: "access",           
        23: "faccessat",       
        24: "rename",           
        25: "renameat",        
        26: "renameat2",       
        27: "link",             
        28: "linkat",          
        29: "unlink",          
        30: "unlinkat",        
        31: "symlink",          
        32: "symlinkat",       
        33: "chmod",            
        34: "fchmod",           
        35: "fchmodat",        
        36: "chown",            
        37: "fchown",          
        38: "fchownat",         
        39: "lchown",           
        40: "getdents64",      
        41: "mkdir",           
        42: "mkdirat",         
        43: "rmdir",            
        44: "readlink",        
        45: "readlinkat",       
        46: "truncate",         
        47: "ftruncate",       
        48: "fcntl",           
        49: "chdir",          
        50: "fchdir",          
        51: "sendfile",       
        52: "dup",             
        53: "dup2",            
        54: "dup3",            
        55: "getcwd",          
        56: "lseek",            
        57: "close",          
        58: "setxattr",      
        59: "lsetxattr",        
        60: "fsetxattr",       
        61: "removexattr",    
        62: "lremovexattr",     
        63: "fremovexattr",    
        64: "socket",           
        65: "bind",            
        66: "listen",          
        67: "accept",          
        68: "accept4",         
        69: "connect",          
        70: "sendto",           
        71: "sendmsg",          
        72: "recvfrom",        
        73: "recvmsg",          
        74: "getsockname",     
        75: "getpeername",      
        76: "getsockopt",      
        77: "setsockopt",       
        78: "fork",             
        79: "vfork",            
        80: "clone",            
        81: "clone3",           
        82: "prctl",           
        83: "ptrace",           
        84: "setsid",          
        85: "mmap",             
        86: "mprotect",        
        87: "memfd_create",     
        88: "getuid",           
        89: "geteuid",          
        90: "getgid",           
        91: "getegid",          
        92: "getgroups",        
        93: "setuid",           
        94: "setgid",           
        95: "setreuid",        
        96: "setresuid",        
        97: "setregid",         
        98: "setresgid",       
        99:"setgroups",
        100: "capset",         
        101: "execve",         
        102: "execveat",     
        109: "init_module",   
        110: "finit_module",    
        111: "delete_module",     
        119: "setns",           
        120: "unshare",
        128: "pipe",           
        129: "pipe2", 
        149: "inotify_init",
        150: "inotify_init1",
        151: "inotify_add_watch",
        152: "inotify_rm_watch",         
        }
        operation = operation_map.get(event.operation_id, "unknown")
        
        # Initialize extra details dictionary
        extra_details = {}
        
        # Access filename and details based on operation type
       
        if event.operation_id == 1:  # uname
           filename = "uname"
       
        elif event.operation_id == 2:  # sysinfo
            filename = "sysinfo"
        
        elif event.operation_id == 3:  # sched_getaffinity
             pid = event.data.generic.arg1
             filename = f"sched_getaffinity_pid={pid}"
             extra_details['cpusetsize'] = event.data.generic.arg2
        
        elif event.operation_id == 4:  # ioctl
             fd = event.data.generic.arg1
             cmd = event.data.generic.arg2
             filename = f"ioctl_fd={fd}_cmd={cmd:#x}"
        
        elif event.operation_id == 5:  # getrandom
             buf_size = event.data.generic.arg2
             flags = event.data.generic.arg3
             filename = f"getrandom_size={buf_size}"
             flag_names = []
             if flags & 0x0001: flag_names.append("GRND_NONBLOCK")
             if flags & 0x0002: flag_names.append("GRND_RANDOM")
             if flag_names:
                extra_details['flags'] = '|'.join(flag_names)

        elif event.operation_id == 6:  # sethostname
             hostname = self.safe_decode_path(event.data.file.path)
             filename = f"sethostname_{hostname}"
    
        
        elif event.operation_id == 8:  # setdomainname
             domainname = self.safe_decode_path(event.data.file.path)
             filename = f"setdomainname_{domainname}"
        
        elif event.operation_id in [9, 41, 43]:  # open, mkdir, rmdir
             path = self.safe_decode_path(event.data.file.path)
             filename = path
             if event.operation_id == 9:  # open
                extra_details['flags'] = f"{event.data.generic.arg1:#x}"
                extra_details['mode'] = f"{event.data.generic.arg2:#o}"
             elif event.operation_id == 41:  # mkdir
                extra_details['mode'] = f"{event.data.generic.arg1:#o}"
        
        elif event.operation_id == 10:  # openat
             filename = self.safe_decode_path(event.data.file.path)
             raw_flags = event.io_fd    # flags stored in io_fd
             raw_mode = event.io_size   # mode stored in io_size
    
             # Parse open flags
             flag_names = []
             if raw_flags & 0x0001: flag_names.append("O_WRONLY")
             if raw_flags & 0x0002: flag_names.append("O_RDWR")
             if raw_flags & 0x0040: flag_names.append("O_CREAT")
             if raw_flags & 0x0080: flag_names.append("O_EXCL")
             if raw_flags & 0x0100: flag_names.append("O_NOCTTY")
             if raw_flags & 0x0200: flag_names.append("O_TRUNC")
             if raw_flags & 0x0400: flag_names.append("O_APPEND")
             if raw_flags & 0x0800: flag_names.append("O_NONBLOCK")
             if raw_flags & 0x10000: flag_names.append("O_DIRECTORY")
             if raw_flags & 0x20000: flag_names.append("O_NOFOLLOW")
             if raw_flags & 0x80000: flag_names.append("O_CLOEXEC")
             if not flag_names:
                flag_names.append("O_RDONLY")
    
             extra_details['flags'] = '|'.join(flag_names)
             if raw_mode > 0:
                extra_details['mode'] = f"{raw_mode:#o}"
            
        
        elif event.operation_id == 11:  # creat
             path =self.safe_decode_path(event.data.file.path)
             filename = path
             extra_details['mode'] = f"{event.data.generic.arg1:#o}"
        
        
        elif event.operation_id in [12, 15]:  # read/write
          # fd and size come from io_fd/io_size (outside union, never corrupted)
          fd_val = event.io_fd
          size_val = event.io_size
          
          # Check if we have path info from fd_paths (in the union)
          if len(event.data.file.path) > 0 and event.data.file.path[0]:
             filename = self.safe_decode_path(event.data.file.path)
          else:
            fd_names = {0: "stdin", 1: "stdout", 2: "stderr"}
            filename = fd_names.get(fd_val, f"fd={fd_val}")
    
          extra_details['fd'] = fd_val
          extra_details['size'] = size_val
    
          if event.operation_id == 15:  # write
             if fd_val == 1:
               extra_details['stream'] = 'stdout'
               filename = "stdout"
             elif fd_val == 2:
               extra_details['stream'] = 'stderr'
               filename = "stderr"
             elif fd_val == 0:
               extra_details['stream'] = 'stdin'
               filename = "stdin"
            
        elif event.operation_id in [13, 16]:  # pread64/pwrite64
            fd_val = event.io_fd
            size_val = event.io_size
            offset_val = event.io_offset
            
            # Check if we have path info
            if len(event.data.file.path) > 0 and event.data.file.path[0]:
                filename = self.safe_decode_path(event.data.file.path)
            else:
                filename = f"fd={fd_val}"
            
            extra_details['fd'] = fd_val
            extra_details['size'] = size_val
            extra_details['offset'] = offset_val
            
        elif event.operation_id in [14, 17]:  # readv/writev
            fd_val = event.io_fd
            
            # Check if we have path info (writev does fd_paths lookup)
            if len(event.data.file.path) > 0 and event.data.file.path[0]:
                filename = self.safe_decode_path(event.data.file.path)
            else:
                filename = f"fd={fd_val}"
            
            extra_details['fd'] = fd_val
            extra_details['iovcnt'] = event.io_size
            
        elif event.operation_id == 19:  # fstat
            filename = f"fd={event.data.generic.arg1}"
            extra_details['fd'] = event.data.generic.arg1
        
        elif event.operation_id in [18, 20, 24, 25, 29, 30, 33, 36, 101, 102]:  # File path operations
            filename = self.safe_decode_path(event.data.file.path)
            if event.operation_id == 33:  # chmod
                extra_details['mode'] = f"{event.data.generic.arg1:#o}"
            elif event.operation_id == 36:  # chown
                extra_details['uid'] = event.data.proc.uid
                extra_details['gid'] = event.data.proc.gid
                
        
            
        elif event.operation_id == 21:  # statx
            path = self.safe_decode_path(event.data.file.path)
            filename = path
            dfd = event.data.generic.arg1
            flags = event.data.generic.arg2
            mask = event.data.generic.arg3
            
            # Parse statx flags
            statx_flags = []
            if flags & 0x100: statx_flags.append("AT_SYMLINK_NOFOLLOW")
            if flags & 0x800: statx_flags.append("AT_STATX_SYNC_AS_STAT")
            if flags & 0x1000: statx_flags.append("AT_STATX_FORCE_SYNC")
            if flags & 0x2000: statx_flags.append("AT_STATX_DONT_SYNC")
            
            extra_details['dfd'] = dfd
            extra_details['flags'] = '|'.join(statx_flags) if statx_flags else f"{flags:#x}"
            extra_details['mask'] = f"{mask:#x}"
        
        
        elif event.operation_id == 22:  # access
            raw_path = event.data.file.path
            filename = self.safe_decode_path(event.data.file.path)
            # If filename is still empty, check if it's the first file being checked
            if not filename or filename in ["<empty_path>", "<unparseable>"]:
              # For access syscall at program start, it might be checking the interpreter
              filename = "<interpreter_check>"  # or "/lib64/ld-linux-x86-64.so.2"
    
            mode = event.data.generic.arg1
            mode_flags = []
            if mode & 0x04: mode_flags.append('R_OK')
            if mode & 0x02: mode_flags.append('W_OK')
            if mode & 0x01: mode_flags.append('X_OK')
            if mode == 0x00: mode_flags.append('F_OK')
            extra_details['mode'] = '|'.join(mode_flags) if mode_flags else f"{mode:#x}"
        
        elif event.operation_id == 23:  # faccessat
            path = self.safe_decode_path(event.data.file.path)
            filename = path
            dfd = event.data.generic.arg1
            mode = event.data.generic.arg2
    
            mode_flags = []
            if mode & 0x04: mode_flags.append('R_OK')
            if mode & 0x02: mode_flags.append('W_OK')
            if mode & 0x01: mode_flags.append('X_OK')
            if mode == 0x00: mode_flags.append('F_OK')
    
            extra_details['dfd'] = dfd
            extra_details['mode'] = '|'.join(mode_flags) if mode_flags else f"{mode:#x}"
        
        elif event.operation_id == 26:  # renameat2
             oldpath = self.safe_decode_path(event.data.file.path)
             filename = f"rename_{oldpath}"
             extra_details['olddfd'] = event.data.generic.arg1
             extra_details['newdfd'] = event.data.generic.arg2
             flags = event.data.generic.arg3
             rename_flags = []
             if flags & 0x1: rename_flags.append("NOREPLACE")
             if flags & 0x2: rename_flags.append("EXCHANGE")
             if flags & 0x4: rename_flags.append("WHITEOUT")
             extra_details['flags'] = '|'.join(rename_flags) if rename_flags else f"{flags:#x}"
        
        
        
        elif event.operation_id in [27, 28]:  # link, linkat
             oldpath =self.safe_decode_path(event.data.file.path)
             filename = f"link_{oldpath}"
             if event.operation_id == 28:  # linkat
                extra_details['olddfd'] = event.data.generic.arg1
                extra_details['newdfd'] = event.data.generic.arg2
                extra_details['flags'] = event.data.generic.arg3
        
        
        elif event.operation_id in [31, 32]:  # symlink, symlinkat
           target = self.safe_decode_path(event.data.file.path)
           filename = f"symlink_to_{target}"
           if event.operation_id == 32:  # symlinkat
              extra_details['newdfd'] = event.data.generic.arg1


        elif event.operation_id == 34:  # fchmod
            fd = event.data.generic.arg1
            mode = event.data.generic.arg2
            filename = f"fd={fd}"
            extra_details['fd'] = fd
            extra_details['mode'] = f"{event.data.generic.arg2:#o}"
            
        elif event.operation_id == 35:  # fchmodat
            path = self.safe_decode_path(event.data.file.path)
            filename = path
            dfd = event.data.generic.arg1
            mode = event.data.generic.arg2
            extra_details['dfd'] = dfd
            extra_details['mode'] = f"{event.data.generic.arg2:#o}"
            
        elif event.operation_id == 37:  # fchown
            fd = event.data.generic.arg1
            filename = f"fd={fd}"
            extra_details['fd'] = fd
            extra_details['uid'] = event.data.proc.uid
            extra_details['gid'] = event.data.proc.gid
            
        elif event.operation_id == 38:  # fchownat
            path =self.safe_decode_path(event.data.file.path)
            filename = path
            dfd = event.data.generic.arg1
            extra_details['dfd'] = dfd
            extra_details['uid'] = event.data.proc.uid
            extra_details['gid'] = event.data.proc.gid
            extra_details['flags'] = event.data.proc.flags
            
        elif event.operation_id == 39:  # lchown
            path = self.safe_decode_path(event.data.file.path)
            filename = path
            extra_details['uid'] = event.data.proc.uid
            extra_details['gid'] = event.data.proc.gid
        
        elif event.operation_id == 40:  # getdents64
            fd_val = event.io_fd
            if len(event.data.file.path) > 0 and event.data.file.path[0]:
                filename = self.safe_decode_path(event.data.file.path)
            else:
                filename = f"fd={fd_val}"
            extra_details['fd'] = fd_val
            
        
        
        elif event.operation_id == 42:  # mkdirat
           path = self.safe_decode_path(event.data.file.path)
           filename = path
           extra_details['dfd'] = event.data.generic.arg1
           extra_details['mode'] = f"{event.data.generic.arg2:#o}"
       
            
        elif event.operation_id == 44:  # readlink
            path =self.safe_decode_path(event.data.file.path)
            filename = path
            extra_details['bufsiz'] =  event.data.proc.flags
            
        elif event.operation_id == 45:  # readlinkat
            path = self.safe_decode_path(event.data.file.path)
            filename = path
            dfd = event.data.generic.arg1
            bufsiz = event.data.generic.arg2
            extra_details['dfd'] = dfd
            extra_details['bufsiz'] = bufsiz
        
        
        elif event.operation_id == 46:  # truncate
            path = self.safe_decode_path(event.data.file.path)
            filename = path
            length = event.data.generic.arg1
            extra_details['length'] = length
            
        elif event.operation_id == 47:  # ftruncate
            fd = event.data.generic.arg1
            length = event.data.generic.arg2
            filename = f"fd={fd}"
            extra_details['fd'] = fd
            extra_details['length'] = length
        
        elif event.operation_id == 48:  # fcntl
             fd = event.data.generic.arg1
             cmd = event.data.generic.arg2
    
             fcntl_cmds = {
             0: "F_DUPFD", 1: "F_GETFD", 2: "F_SETFD",
             3: "F_GETFL", 4: "F_SETFL", 5: "F_GETLK",
             6: "F_SETLK", 7: "F_SETLKW"
             }
             cmd_name = fcntl_cmds.get(cmd, f"cmd_{cmd}")
    
             filename = f"fcntl_fd={fd}_{cmd_name}"
             extra_details['arg'] = event.data.generic.arg3

        

        elif event.operation_id in [49, 50]:  # chdir/fchdir
             if event.operation_id == 49:  # chdir
                path = self.safe_decode_path(event.data.file.path)
                filename = f"chdir_{path}"
             else:  # fchdir
                fd = event.data.generic.arg1
                filename = f"fchdir_fd={fd}"
        
        
        elif event.operation_id == 51:  # sendfile
             out_fd = event.data.generic.arg1
             in_fd = event.data.generic.arg2
             count = event.data.generic.arg3
             filename = f"sendfile_{in_fd}->{out_fd}"
             extra_details['count'] = count

        elif event.operation_id in [52, 53, 54]:  # dup/dup2/dup3
             if event.operation_id == 52:  # dup
                oldfd = event.data.generic.arg1
                filename = f"dup_fd={oldfd}"
             else:  # dup2/dup3
                oldfd = event.data.generic.arg1
                newfd = event.data.generic.arg2
                filename = f"dup_{oldfd}->{newfd}"
                if event.operation_id == 54:  # dup3
                   flags = event.data.generic.arg3
                   extra_details['flags'] = f"{flags:#x}"
            
        elif event.operation_id == 55:  # getcwd
            filename = "getcwd"
       
        elif event.operation_id == 56:  # lseek
             fd = event.data.generic.arg1
             offset = event.data.generic.arg2
             whence = event.data.generic.arg3
             whence_map = {0: "SEEK_SET", 1: "SEEK_CUR", 2: "SEEK_END"}
             whence_str = whence_map.get(whence, f"whence_{whence}")
             filename = f"fd={fd}"
             extra_details['offset'] = offset
             extra_details['whence'] = whence_str
    
        elif event.operation_id == 57:  # close
             fd = event.data.generic.arg1
             filename = f"fd={fd}"
             extra_details['fd'] = fd
        
        
        elif event.operation_id in [58, 59, 61, 62]:  # setxattr, lsetxattr, removexattr, lremovexattr
             path = self.safe_decode_path(event.data.file.path)
             op_names = {58: "setxattr", 59: "lsetxattr", 61: "removexattr", 62: "lremovexattr"}
             filename = path
    
        elif event.operation_id in [60, 63]:  # fsetxattr, fremovexattr
             fd = event.data.generic.arg1
             filename = f"fd={fd}"
             extra_details['fd'] = fd
        
        
        elif event.operation_id == 64:  # Socket
            family_map = {1: "AF_UNIX", 2: "AF_INET", 10: "AF_INET6", 17: "AF_PACKET"}
            sock_type_map = {1: "SOCK_STREAM", 2: "SOCK_DGRAM", 3: "SOCK_RAW"}
            protocol_map = {0: "DEFAULT", 6: "TCP", 17: "UDP"}
            
            family = family_map.get(event.data.net.family, f"family_{event.data.net.family}")
            sock_type = sock_type_map.get(event.data.net.sock_type, f"type_{event.data.net.sock_type}")
            protocol = protocol_map.get(event.data.generic.arg3, f"proto_{event.data.generic.arg3}")
            
            filename = f"{family}/{sock_type}/{protocol}"
            extra_details['family'] = family
            extra_details['type'] = sock_type
            extra_details['protocol'] = protocol
        
        
        
        
        
        elif event.operation_id in [65, 69]:  # connect / bind
          import socket, struct, ipaddress

          fam = event.data.net.family

          if fam == 2:  # AF_INET
            ip_bytes = struct.pack('!I', event.data.net.ip_addr)  # host->network
            ip = socket.inet_ntoa(ip_bytes)
            port = int(event.data.net.port)
            filename = f"{ip}:{port}"
            extra_details.update(family='AF_INET', address=ip, port=port)

          elif fam == 10:  # AF_INET6
            ip6_bytes = bytes(event.data.net.ip6)
            ip6 = ipaddress.IPv6Address(ip6_bytes)
            port = int(event.data.net.port)

            # If it's IPv4-mapped (::ffff:x.x.x.x), show IPv4 dotted-decimal
            if ip6.ipv4_mapped is not None:
              v4 = ip6.ipv4_mapped
              filename = f"{v4}:{port}"
              extra_details.update(
                family='AF_INET',        # treat as IPv4 for display
                address=str(v4),
                port=port,
                note='ipv4-mapped-v6'
              )
            else:
              filename = f"[{ip6}]:{port}"
              extra_details.update(family='AF_INET6', address=str(ip6), port=port)

          elif fam == 1:  # AF_UNIX
             filename = "unix"
             extra_details['family'] = 'AF_UNIX'
          else:
             filename = f"[unknown_family:{fam}]"
             extra_details['family'] = f"family_{fam}"
                
          if ':' in filename and not filename.startswith('[unknown_family'):
                try:
                    parts = filename.rsplit(':', 1)
                    ip_part = parts[0].strip('[]')
                    port = int(parts[1])
                    if port < 0 or port > 65535:
                        print(f"[Warning] Invalid port in {operation}: {filename}")
                except (ValueError, IndexError):
                    print(f"[Warning] Invalid address format in {operation}: {filename}")
        
          
          sock_fd = event.io_fd
          if sock_fd and sock_fd != 0:
              extra_details['fd'] = sock_fd
       
       
        
            
        elif event.operation_id in [66, 67, 68]:  # listen/accept
            filename = f"fd={event.data.generic.arg1}"
            extra_details['fd'] = event.data.generic.arg1
            if event.operation_id == 66:  # listen
                extra_details['backlog'] = event.data.generic.arg2
            elif event.operation_id == 68:  # accept4
                extra_details['flags'] = f"{event.data.generic.arg2:#x}"
                
        elif event.operation_id in [70, 72]:  # sendto/recvfrom
             fd = event.io_fd
             msg_len = event.io_size
             flags = int(event.io_offset) & 0xFFFFFFFF  # flags stored in io_offset
    
             filename = f"fd={fd}"
             extra_details['fd'] = fd
             extra_details['len'] = msg_len
             extra_details['flags'] = f"{flags:#x}"
    
             # Decode flags
             flag_names = []
             if flags & 0x01: flag_names.append("MSG_OOB")
             if flags & 0x02: flag_names.append("MSG_PEEK")
             if flags & 0x04: flag_names.append("MSG_DONTROUTE")
             if flags & 0x20: flag_names.append("MSG_DONTWAIT")
             if flags & 0x40: flag_names.append("MSG_EOR")
             if flags & 0x100: flag_names.append("MSG_TRUNC")
             if flags & 0x200: flag_names.append("MSG_CTRUNC")
             if flag_names:
                extra_details['flag_names'] = '|'.join(flag_names)
             msg_content = self.safe_decode_path(event.data.file.path)
             # msg_content = self.safe_decode_path(event.data.file.path)
             if msg_content and msg_content not in ["<empty_path>", "<unparseable>"]:
                safe_preview = ''.join(c if c.isprintable() else f'\\x{ord(c):02x}' 
                             for c in msg_content[:30])
                extra_details['msg_preview'] = safe_preview
                filename = f"fd={fd} [{safe_preview[:20]}]"
    
             op_type = "sendto" if event.operation_id == 70 else "recvfrom"
             extra_details['operation'] = op_type
        
        elif event.operation_id in [71, 73]:  # sendmsg/recvmsg
             fd = event.io_fd
             msg_len = event.io_size
             flags = int(event.io_offset) & 0xFFFFFFFF
    
             # Validate fd (should be small number, typically < 1024)
             if fd > 100000:
                 fd_str = f"invalid_fd({fd:#x})"
                 filename = fd_str
                 extra_details['fd_error'] = 'invalid_fd_value'
             else:
                fd_str = f"fd={fd}"
                filename = fd_str
                extra_details['fd'] = fd
    
             if event.operation_id == 71:  # sendmsg
                 flags = event.data.generic.arg2
                 msg_len = event.data.generic.arg3
             else:  # recvmsg
                flags = event.data.generic.arg2
                msg_len = event.data.generic.arg3  # bytes received
    
             extra_details['flags'] = f"{flags:#x}"
    
             if msg_len > 0:
                 extra_details['total_len'] = msg_len
    
             # Decode flags
             flag_names = []
             if flags & 0x01: flag_names.append("MSG_OOB")
             if flags & 0x02: flag_names.append("MSG_PEEK")
             if flags & 0x04: flag_names.append("MSG_DONTROUTE")
             if flags & 0x20: flag_names.append("MSG_DONTWAIT")
             if flags & 0x40: flag_names.append("MSG_EOR")
             if flags & 0x4000: flag_names.append("MSG_NOSIGNAL")
 
             if flag_names:
                extra_details['flag_names'] = '|'.join(flag_names)
    
             msg_content = self.safe_decode_path(event.data.file.path)
             if msg_content and msg_content not in ["<empty_path>", "<unparseable>", "<decode_error>"]:
                safe_preview = ''.join(c if c.isprintable() else f'\\x{ord(c):02x}' 
                             for c in msg_content[:30])
                extra_details['msg_preview'] = safe_preview
                if fd <= 100000:
                   filename = f"fd={fd} [{safe_preview[:20]}]"
             op_type = "sendmsg" if event.operation_id == 71 else "recvmsg"
             extra_details['operation'] = op_type
        
        elif event.operation_id in [74, 75]:  # getsockname, getpeername
             fd = event.data.generic.arg1
             filename = f"fd={fd}"
             extra_details['fd'] = fd
        
        elif event.operation_id in [76, 77]:  # getsockopt/setsockopt
             fd = event.data.generic.arg1
             level = event.data.generic.arg2
             optname = event.data.generic.arg3
    
             level_names = {1: "SOL_SOCKET", 6: "SOL_TCP", 17: "SOL_UDP"}
             level_str = level_names.get(level, f"level_{level}")
             filename = f"fd={fd}_{level_str}"
             extra_details['optname'] = optname
        
                 
        elif event.operation_id in [78, 79]:  # fork/vfork
            filename = "fork" if event.operation_id == 78 else "vfork"
            
        
        elif event.operation_id in [80, 81]:  # Clone
            if event.data.proc.flags:
                flags = []
                f = event.data.proc.flags
                if f & 0x00000100: flags.append("CLONE_VM")
                if f & 0x00000200: flags.append("CLONE_FS")
                if f & 0x00000400: flags.append("CLONE_FILES")
                if f & 0x00000800: flags.append("CLONE_SIGHAND")
                if f & 0x00010000: flags.append("CLONE_THREAD")
                if f & 0x00200000: flags.append("CLONE_SYSVSEM")
                if f & 0x00400000: flags.append("CLONE_SETTLS")
                if f & 0x00800000: flags.append("CLONE_PARENT_SETTID")
                if f & 0x01000000: flags.append("CLONE_CHILD_CLEARTID")
                
                filename = f"flags={event.data.proc.flags:#x}"
                extra_details['flags'] = '|'.join(flags) if flags else f"{event.data.proc.flags:#x}"
            else:
                filename = "clone"
       
        
        
        # Process manipulation
        elif event.operation_id == 83:  # ptrace
             request = event.data.generic.arg1
             target_pid = event.data.generic.arg2
             addr = event.data.generic.arg3
    
             # Common ptrace requests
             ptrace_requests = {
             0: "PTRACE_TRACEME", 1: "PTRACE_PEEKTEXT", 2: "PTRACE_PEEKDATA",
             3: "PTRACE_PEEKUSER", 4: "PTRACE_POKETEXT", 5: "PTRACE_POKEDATA",
             6: "PTRACE_POKEUSER", 7: "PTRACE_CONT", 8: "PTRACE_KILL",
             9: "PTRACE_SINGLESTEP", 16: "PTRACE_ATTACH", 17: "PTRACE_DETACH",
             24: "PTRACE_SYSCALL", 0x4200: "PTRACE_SEIZE"
             }
    
             req_name = ptrace_requests.get(request, f"request_{request:#x}")
             filename = f"{req_name} -> pid={target_pid}"
             extra_details['request'] = req_name
             if addr: 
                extra_details['addr'] = f"{addr:#x}"
                
        elif event.operation_id == 82:  # prctl (primary - 117 is duplicate)
             prctl_options = {
             1: "PR_SET_PDEATHSIG", 15: "PR_SET_NAME",
             22: "PR_SET_SECCOMP", 38: "PR_SET_NO_NEW_PRIVS"
             }
             option = event.data.generic.arg1
             opt_name = prctl_options.get(option, f"option_{option}")
             filename = f"prctl_{opt_name}"
             extra_details['arg2'] = event.data.generic.arg2
    
        elif event.operation_id == 84:  # setsid
             filename = "setsid"
        
        elif event.operation_id == 85:  # mmap
             addr = event.data.generic.arg1
             length = event.data.generic.arg2
             prot = event.data.generic.arg3
             flags = event.data.proc.flags
    
             # Parse protection flags
             prot_flags = []
             if prot & 0x1: prot_flags.append("PROT_READ")
             if prot & 0x2: prot_flags.append("PROT_WRITE")
             if prot & 0x4: prot_flags.append("PROT_EXEC")
             if prot == 0: prot_flags.append("PROT_NONE")
    
             # Parse MAP flags
             map_flags = []
             if flags & 0x01: map_flags.append("MAP_SHARED")
             if flags & 0x02: map_flags.append("MAP_PRIVATE")
             if flags & 0x10: map_flags.append("MAP_FIXED")
             if flags & 0x20: map_flags.append("MAP_ANONYMOUS")
    
             # Handle address formatting separately
             addr_str = f"{addr:#x}" if addr else "NULL"
             filename = f"addr={addr_str}, len={length}"
             extra_details['protection'] = '|'.join(prot_flags) if prot_flags else f"prot={prot:#x}"
             extra_details['flags'] = '|'.join(map_flags[:3]) if map_flags else f"flags={flags:#x}"
    
        elif event.operation_id == 86:  # mprotect
             addr = event.data.generic.arg1
             length = event.data.generic.arg2
             prot = event.data.generic.arg3
    
             prot_flags = []
             if prot & 0x1: prot_flags.append("PROT_READ")
             if prot & 0x2: prot_flags.append("PROT_WRITE")
             if prot & 0x4: prot_flags.append("PROT_EXEC")
             if prot == 0: prot_flags.append("PROT_NONE")
    
             addr_str = f"{addr:#x}" if addr else "NULL"
             filename = f"addr={addr_str}, len={length}"
             extra_details['protection'] = '|'.join(prot_flags) if prot_flags else f"prot={prot:#x}"
    
        elif event.operation_id == 87:  # memfd_create
             name = self.safe_decode_path(event.data.file.path)
             flags = event.data.generic.arg1
    
             flag_names = []
             if flags & 0x0001: flag_names.append("MFD_CLOEXEC")
             if flags & 0x0002: flag_names.append("MFD_ALLOW_SEALING")
             if flags & 0x0004: flag_names.append("MFD_HUGETLB")
    
             filename = f"name={name}"
             extra_details['flags'] = '|'.join(flag_names) if flag_names else f"flags={flags:#x}"
        elif event.operation_id in [88, 89, 90, 91, 92]:  # getuid/geteuid/getgid/getegid/getgroups
             op_names = {88: "getuid", 89: "geteuid", 90: "getgid", 91: "getegid", 92: "getgroups"}
             filename = op_names[event.operation_id]
             if event.operation_id == 92:
                extra_details['size'] = event.data.generic.arg1
        
        
        elif event.operation_id in [93, 94, 95, 96, 97, 98]:  # UID/GID operations
            if event.operation_id in [93, 95, 96]:  # UID operations
                filename = f"uid={event.data.proc.uid}"
                extra_details['uid'] = event.data.proc.uid
                if event.operation_id in [95, 96]:  # setresuid/setreuid
                    extra_details['euid'] = event.data.proc.gid  # Reused field
                    if event.operation_id == 96:  # setresuid
                        extra_details['suid'] = event.data.proc.flags  # Reused field
            else:  # GID operations
                filename = f"gid={event.data.proc.gid}"
                extra_details['gid'] = event.data.proc.gid
                if event.operation_id in [97, 98]:  # setregid/setresgid
                    extra_details['egid'] = event.data.proc.uid  # Reused field
                    if event.operation_id == 98:  # setresgid
                        extra_details['sgid'] = event.data.proc.flags  # Reused field

        elif event.operation_id == 99:  # setgroups
            size = event.data.generic.arg1
            filename = f"setgroups_size={size}"
            extra_details['size'] = size 
        
        elif event.operation_id == 100:  # capset
             filename = "capset"
             extra_details['operation'] = 'SET_CAPABILITIES'
     

        elif event.operation_id in [109, 110, 111]:  # Module operations
             if event.operation_id == 109:  # init_module
                filename = "load_module"
                extra_details['size'] = event.data.generic.arg2
             elif event.operation_id == 110:  # finit_module
                filename = f"load_module_fd={event.data.generic.arg1}"
                extra_details['flags'] = event.data.generic.arg3
             else:  # delete_module
                module_name = self.safe_decode_path(event.data.file.path)
                filename = f"unload_{module_name}"
                extra_details['flags'] = event.data.generic.arg1

        elif event.operation_id == 119:  # setns
         ns_types = {
         0x00020000: "CLONE_NEWNS",
         0x40000000: "CLONE_NEWNET",
         0x20000000: "CLONE_NEWPID"
         }
         fd = event.data.generic.arg1
         nstype = event.data.generic.arg2
         ns_name = ns_types.get(nstype, f"ns_{nstype:#x}")
         filename = f"setns_fd={fd}_{ns_name}"
       
        elif event.operation_id == 120:  # unshare
          flags = event.data.generic.arg1
          unshare_flags = []
          if flags & 0x00020000: unshare_flags.append("NEWNS")
          if flags & 0x40000000: unshare_flags.append("NEWNET")
          if flags & 0x20000000: unshare_flags.append("NEWPID")
          filename = f"unshare_{','.join(unshare_flags) if unshare_flags else f'flags={flags:#x}'}"


        elif event.operation_id in [128, 129]:  # pipe/pipe2
             filename = "create_pipe"
             if event.operation_id == 129:
                flags = event.data.generic.arg1
                pipe_flags = []
                if flags & 0x80000: pipe_flags.append("O_CLOEXEC")
                if flags & 0x800: pipe_flags.append("O_NONBLOCK")
                extra_details['flags'] = '|'.join(pipe_flags) if pipe_flags else f"{flags:#x}"    
             else:
                filename = ""
       
        elif event.operation_id == 149:  # inotify_init
             filename = "inotify_init"

        elif event.operation_id == 150:  # inotify_init1
             filename = "inotify_init1"
             flags = event.data.generic.arg1
             flag_names = []
             if flags & 0x80000: flag_names.append("IN_CLOEXEC")
             if flags & 0x800: flag_names.append("IN_NONBLOCK")
             extra_details['flags'] = '|'.join(flag_names) if flag_names else f"{flags:#x}"

        elif event.operation_id == 151:  # inotify_add_watch
             filename = self.safe_decode_path(event.data.file.path)
             extra_details['fd'] = event.io_fd
             mask = event.io_size
             mask_names = []
             if mask & 0x00000001: mask_names.append("IN_ACCESS")
             if mask & 0x00000002: mask_names.append("IN_MODIFY")
             if mask & 0x00000004: mask_names.append("IN_ATTRIB")
             if mask & 0x00000008: mask_names.append("IN_CLOSE_WRITE")
             if mask & 0x00000020: mask_names.append("IN_OPEN")
             if mask & 0x00000040: mask_names.append("IN_MOVED_FROM")
             if mask & 0x00000080: mask_names.append("IN_MOVED_TO")
             if mask & 0x00000100: mask_names.append("IN_CREATE")
             if mask & 0x00000200: mask_names.append("IN_DELETE")
             extra_details['mask'] = '|'.join(mask_names) if mask_names else f"{mask:#x}"

        elif event.operation_id == 152:  # inotify_rm_watch
            filename = f"fd={event.io_fd}"
            extra_details['fd'] = event.io_fd
            extra_details['wd'] = event.data.generic.arg1
        
        else:
            filename = ""
        
        # Format details string - only show reasonable values
        details_str = ""
        if extra_details:
            formatted_details = []
            for k, v in extra_details.items():
                # Skip obviously wrong values (huge numbers)
                if isinstance(v, int) and v > 0x7FFFFFFF:
                    continue
                formatted_details.append(f"{k}={v}")
            if formatted_details:
                details_str = " [" + ", ".join(formatted_details) + "]"
        
        # Only print if we have valid data
        if operation != "unknown":
            print(f"PID:{event.pid} TID:{event.tid} -event.operation_id: {event.operation_id}, {event.phase} -> {operation} -> {filename}{details_str}")

       
        # Get the kernel TID from the event
        event_kernel_tid = event.tid
        attribution_details = {'correlation_id': 'unknown'}
        thread_pool_attribution = None
        python_correlation_id = 'unknown'
        thread_correlation_id = 'unknown'
        genealogy_correlation_id = 'unknown'
        ctx = get_correlation_context()
        # PRIMARY SOURCE: eBPF-embedded correlation ID (set by kernel, works across processes)
        ebpf_correlation_id = event.correlation_id.decode('utf-8', 'replace').rstrip('\x00')
        ebpf_phase = event.phase
        
        if ebpf_correlation_id and ebpf_correlation_id not in ('', 'no_context', '\x00' * 16):
            effective_correlation_id = ebpf_correlation_id
            attribution_method = 'EBPF_KERNEL'
            attribution_details = {'correlation_id': ebpf_correlation_id}
        else:
            # FALLBACK: Python-side lookups (only works for events in the same process)
            thread_pool_attribution = None
            if hasattr(self, 'thread_pool_monitor'):
                thread_pool_attribution = self.thread_pool_monitor.get_attribution_info(event_kernel_tid)
            
            genealogy_correlation_id = 'unknown'
            if event_kernel_tid in self.thread_genealogy:
                genealogy_correlation_id = self.thread_genealogy[event_kernel_tid].get('correlation_id', 'unknown')
            
            thread_correlation_id = 'unknown'
            if hasattr(self, 'thread_correlations'):
                for pthread_id, thread_info in self.thread_correlations.items():
                    if thread_info.get('kernel_tid') == event_kernel_tid:
                        thread_correlation_id = thread_info.get('correlation_id', 'unknown')
                        break
            
            ctx = get_correlation_context()
            python_correlation_id = ctx.id if hasattr(ctx, 'id') else 'unknown'
            
            if thread_pool_attribution:
                effective_correlation_id = thread_pool_attribution['correlation_id']
                attribution_method = 'THREAD_POOL_TASK'
            elif genealogy_correlation_id not in ('unknown', 'no_context'):
                effective_correlation_id = genealogy_correlation_id
                attribution_method = 'THREAD_GENEALOGY'
            elif thread_correlation_id != 'unknown':
                effective_correlation_id = thread_correlation_id
                attribution_method = 'THREAD_LOCAL'
            else:
                effective_correlation_id = python_correlation_id
                attribution_method = 'PYTHON_CONTEXT'
        
        # Attribution logging
        if attribution_method == 'THREAD_POOL_TASK' and thread_pool_attribution:
            print(f"[Attribution]  THREAD POOL EVENT DETECTED!")
            print(f"  Task: {thread_pool_attribution['task_id']}")
            print(f"  Function: {thread_pool_attribution['function_name']}")
            print(f"  Correlation: {thread_pool_attribution['correlation_id']}")
            print(f"  Duration: {thread_pool_attribution['duration']:.3f}s")
            print(f"  Syscall: {operation} -> {filename}")
        elif attribution_method == 'THREAD_GENEALOGY':
            if operation in ['openat', 'execve', 'connect', 'clone']:
                print(f"[Attribution] Event from genealogy thread {event_kernel_tid}, inherited: {genealogy_correlation_id}")
        
       
        # Create a temporary event data for attack indicators analysis
        temp_event_data = {
            'operation': operation,
            'filename': filename
        }
        
        # Build event data with all the existing fields
        event_data = {
            'operation': operation,
            'filename': filename,
            'extra_details': extra_details,  # Add the detailed parameters
            'pid': event.pid,
            'tid': event_kernel_tid,
            'timestamp': event.timestamp / 1e9,
            'comm': event.comm.decode('utf-8', 'replace').rstrip('\x00'),
            
            'user_stack_id': event.user_stack_id,
            'phase': self.current_phase,
            
            # Enhanced attribution info
            'effective_correlation_id': effective_correlation_id,
            'attribution_method': attribution_method,
            'attribution_details': attribution_details,
            
            # Thread pool specific info
            'thread_pool_task_id': thread_pool_attribution.get('task_id') if thread_pool_attribution else None,
            'thread_pool_function': thread_pool_attribution.get('function_name') if thread_pool_attribution else None,
            'thread_pool_duration': thread_pool_attribution.get('duration') if thread_pool_attribution else None,
            
            # All correlation sources for debugging
            'python_correlation_id': python_correlation_id,
            'thread_correlation_id': thread_correlation_id,
            'genealogy_correlation_id': genealogy_correlation_id,
            
            # Existing ML context
            'ml_operations': getattr(ctx, 'ml_operations', []),
            'suspicious_indicators': getattr(ctx, 'suspicious_indicators', []),
            'operation_categories': [op.get('operation_category') for op in getattr(ctx, 'ml_operations', [])],
            'triggering_ml_function': self._identify_triggering_function(ctx),
            'attack_indicators': self._analyze_attack_indicators(temp_event_data, ctx),
            'operation_chain': getattr(ctx, 'operation_chain', [])[-3:]
        }
        
        event_phase_num = event.phase  # Get phase from the event itself
           
      
        if event_phase_num == 1:  # LOADING
            self.loading_events.append(event_data)
        elif event_phase_num == 2:  # EXECUTION
           self.execution_events.append(event_data)  
      
      except Exception as e:
        print(f"[AOP Monitor] Error handling event: {e}")
        traceback.print_exc()
    
    
    
 
    
    def _identify_triggering_function(self, ctx):
      """Identify the ML function that likely triggered the syscall"""
      ml_ops = getattr(ctx, 'ml_operations', [])
      if not ml_ops:
        return "unknown"
    
      # Find the most relevant ML operation
      for op in ml_ops:
        if op.get('operation_category') in ['FILE_OP', 'NETWORK_OP', 'SYSTEM_OP']:
            return f"{op.get('function')}() in {op.get('filename', '').split('/')[-1]}"
    
      return f"{ml_ops[0].get('function')}()" if ml_ops else "unknown"

    def _analyze_attack_indicators(self, event_data, ctx):
      """Analyze potential attack indicators"""
      indicators = []
      
      # Check filename patterns
      filename = event_data['filename']  # Changed from event.filename.decode()
      if '.ssh' in filename:
        indicators.append('SSH_ACCESS')
      if 'authorized_keys' in filename:
        indicators.append('SSH_KEY_MANIPULATION')
      if any(pattern in filename for pattern in ['/etc/passwd', '/etc/shadow']):
        indicators.append('SYSTEM_CONFIG_ACCESS')
    
      # Check ML operation context
      suspicious_ops = getattr(ctx, 'suspicious_indicators', [])
      if suspicious_ops:
        indicators.append('SUSPICIOUS_ML_OPERATION')
    
      # Check operation sequences
      if event_data['operation'] == 'getdents64' and '/home' in filename:  # Changed from event.operation.decode()
        indicators.append('DIRECTORY_ENUMERATION')
    
      return indicators
   
   
   
    
    def generate_correlation_id(self):
      """Generate unique correlation ID for each ML operation"""
      return str(uuid.uuid4())[:8]

  

    def cleanup(self):
      """Cleanup eBPF resources"""
      if self.monitoring_active and self.bpf:
        try:
            # Close perf buffer first
            if hasattr(self.bpf, 'perf_buffer_poll'):
                try:
                    self.bpf.perf_buffer_poll(timeout=0)  # Final poll
                except Exception:
                    pass
            
            # Clear our tracking data
            if hasattr(self, 'thread_correlations'):
                self.thread_correlations.clear()
            
            # Clean up BPF
            self.bpf = None  # Let Python handle cleanup
            self.monitoring_active = False
            print(f"[AOP Monitor] eBPF monitoring stopped")
        except Exception as e:
            print(f"[AOP Monitor] Error during cleanup: {e}")
    
    
    

    
    def monitor_api(self, func, phase="LOADING"):
      """
      The AOP advice. Wraps a framework API call: generates a
      correlation ID, writes it to the BPF map, traces the call,
      drains events on return. Everything the model does between
      start and stop gets tagged with this ID and phase.
      """
      def wrapper(*args, **kwargs):
        correlation_id = self.generate_correlation_id()
        fname = getattr(func, '__name__', type(func).__name__)
        fmod  = getattr(func, '__module__', 'tensorflow')
        # Set comprehensive context
        set_correlation_context(
            correlation_id, 
            phase, 
            f"{fmod}.{fname}"
        )

        print(f"\n[AOP Monitor] === {phase} PHASE START ===")
        print(f"[AOP Monitor] Correlation ID: {correlation_id}")
        print(f"[AOP Monitor] API Called: {fmod}.{fname}")
       #print(f"[AOP Monitor] Parameters: args={args}, kwargs={kwargs}")
        # Show relevant Python context
        start_time = time.time()
        self.start_ebpf_monitoring(correlation_id, phase)
        try:
            result = func(*args, **kwargs)
            return result
        finally:
           self.stop_ebpf_monitoring(correlation_id, phase)
           end_time = time.time()
        
           print(f"[AOP Monitor] === {phase} PHASE END ===")
           print(f"[AOP Monitor] Execution Time: {end_time - start_time:.4f} seconds")
         
      return wrapper

    
  
# ==============================================================================
# JOIN POINT REGISTRATION 
#
# One apply_*_aspects() per framework. Each monkey-patches the framework's
# loading API at import time with our monitor_api wrapper. Order doesn't
# matter — they're independent. If a framework isn't installed, the
# apply function silently skips it.
# ==============================================================================

monitor = AspectMonitor()
atexit.register(monitor.cleanup)
def apply_safetensors_aspects():
    try:
        import safetensors.torch
        safetensors.torch.load_file = monitor.monitor_api(safetensors.torch.load_file, phase="LOADING")
        
        # Also cover numpy and tensorflow variants
        import safetensors.numpy
        safetensors.numpy.load_file = monitor.monitor_api(safetensors.numpy.load_file, phase="LOADING")
        
        import safetensors.tensorflow
        safetensors.tensorflow.load_file = monitor.monitor_api(safetensors.tensorflow.load_file, phase="LOADING")
    except ImportError:
        pass

#----------------------------------------------------------------------------------------------
def apply_huggingface_aspects():
    """Monitor HuggingFace loading operations"""
    try:
        import transformers
        
        # Model loading methods
        if hasattr(transformers, 'pipeline'):
            transformers.pipeline = monitor.monitor_api(transformers.pipeline, phase="LOADING")
        
        if hasattr(transformers, 'AutoConfig'):
            transformers.AutoConfig.from_pretrained = monitor.monitor_api(transformers.AutoConfig.from_pretrained, phase="LOADING")
        
        # Dataset loading (can contain embedded models)
        import datasets
        if hasattr(datasets, 'load_dataset'):
            datasets.load_dataset = monitor.monitor_api(datasets.load_dataset, phase="LOADING")
        if hasattr(datasets, 'load_from_disk'):
            datasets.load_from_disk = monitor.monitor_api(datasets.load_from_disk, phase="LOADING")
            
    except ImportError:
        pass

#----------------------------------------------------------------------------------------------
def apply_tensorflow_aspects():
    try:
        import tensorflow as tf
        
        if hasattr(tf.train, 'Checkpoint'):
            tf.train.Checkpoint.restore = monitor.monitor_api(tf.train.Checkpoint.restore, phase="LOADING")
        
        if hasattr(tf.saved_model, 'load'):
            tf.saved_model.load = monitor.monitor_api(tf.saved_model.load, phase="LOADING")
        
        if hasattr(tf.keras.models, 'load_model'):
            tf.keras.models.load_model = monitor.monitor_api(tf.keras.models.load_model, phase="LOADING")
    except ImportError:
        pass


#----------------------------------------------------------------------------------------------
def apply_pytorch_aspects():
    try:
        import torch
        
        if hasattr(torch, 'load'):
            torch.load = monitor.monitor_api(torch.load, phase="LOADING")
        
        if hasattr(torch.jit, 'load'):
            torch.jit.load = monitor.monitor_api(torch.jit.load, phase="LOADING")
        
        if hasattr(torch.nn.utils, 'load_state_dict'):
            torch.nn.utils.load_state_dict = monitor.monitor_api(torch.nn.utils.load_state_dict, phase="LOADING")
        
        if hasattr(torch, 'package') and hasattr(torch.package, 'PackageImporter'):
            torch.package.PackageImporter.load_pickle = monitor.monitor_api(
                torch.package.PackageImporter.load_pickle, phase="LOADING"
            )
        if hasattr(torch, 'export') and hasattr(torch.export, 'load'):
            torch.export.load = monitor.monitor_api(torch.export.load, phase="LOADING")
    except ImportError:
        pass
  

#----------------------------------------------------------------------------------------------
def apply_system_operation_aspects():
    """Hook system operations commonly used by ML frameworks"""
    import os
    import subprocess
    
    os.system = monitor.monitor_api(os.system, phase="EXECUTION")
    subprocess.Popen = monitor.monitor_api(subprocess.Popen, phase="EXECUTION")

#----------------------------------------------------------------------------------------------

def apply_protocol_aspects():
    try:
        import msgpack
        msgpack.load = monitor.monitor_api(msgpack.load, phase="LOADING")
        msgpack.loads = monitor.monitor_api(msgpack.loads, phase="LOADING")
    except ImportError:
        pass
    
    try:
        import google.protobuf.message
        google.protobuf.message.Message.ParseFromString = monitor.monitor_api(
            google.protobuf.message.Message.ParseFromString, phase="LOADING"
        )
    except ImportError:
        pass


#----------------------------------------------------------------------------------------------
def apply_tensor_operation_aspects():
    """Hook low-level tensor operations that might trigger execution"""
    try:
        import tensorflow as tf
        if hasattr(tf, 'function'):
            # Note: tf.function needs special handling since it returns a decorator
            original_tf_function = tf.function
            def monitored_tf_function(func=None, **kwargs):
                if func is None:
                    return lambda f: monitored_tf_function(f, **kwargs)
                wrapped_func = original_tf_function(func, **kwargs)
                return monitor.monitor_api(wrapped_func, phase="EXECUTION")
            tf.function = monitored_tf_function
    except ImportError:
        pass
    
    try:
        import torch
        
        if hasattr(torch.autograd, 'Function'):
            torch.autograd.Function.apply = monitor.monitor_api(
                torch.autograd.Function.apply, phase="EXECUTION"
            )
        
        if hasattr(torch.Tensor, 'backward'):
            torch.Tensor.backward = monitor.monitor_api(torch.Tensor.backward, phase="EXECUTION")
        
        tensor_ops = ['matmul', 'mm', 'bmm', 'addmm', 'conv2d', 'linear']
        for op_name in tensor_ops:
            if hasattr(torch, op_name):
                setattr(torch, op_name, monitor.monitor_api(getattr(torch, op_name), phase="EXECUTION"))
            
            if hasattr(torch.nn.functional, op_name):
                setattr(torch.nn.functional, op_name, 
                       monitor.monitor_api(getattr(torch.nn.functional, op_name), phase="EXECUTION"))
    except ImportError:
        pass
 
 #----------------------------------------------------------------------------------------------
def apply_onnx_aspects():
    """Monitor ONNX model operations"""
    try:
        import onnxruntime as ort
        if hasattr(ort, 'InferenceSession'):
            ort.InferenceSession.__init__ = monitor.monitor_api(
                ort.InferenceSession.__init__, phase="LOADING"
            )
    except ImportError:
        pass

#----------------------------------------------------------------------------------------------
def apply_xgboost_aspects():
    """Monitor XGBoost operations"""
    try:
        import xgboost as xgb
        
        if hasattr(xgb.Booster, 'load_model'):
            xgb.Booster.load_model = monitor.monitor_api(xgb.Booster.load_model, phase="LOADING")
        
        if hasattr(xgb, 'XGBClassifier'):
            xgb.XGBClassifier.load_model = monitor.monitor_api(xgb.XGBClassifier.load_model, phase="LOADING")
        if hasattr(xgb, 'XGBRegressor'):
            xgb.XGBRegressor.load_model = monitor.monitor_api(xgb.XGBRegressor.load_model, phase="LOADING")
        
        # For DMatrix, only monitor file loading
        original_dmatrix_init = xgb.DMatrix.__init__
        def monitored_dmatrix_init(self, *args, **kwargs):
            if args and isinstance(args[0], str):
                return monitor.monitor_api(original_dmatrix_init, phase="LOADING")(self, *args, **kwargs)
            return original_dmatrix_init(self, *args, **kwargs)
        xgb.DMatrix.__init__ = monitored_dmatrix_init
    except ImportError:
        pass

#----------------------------------------------------------------------------------------------
def apply_lightgbm_aspects():
    """Monitor LightGBM operations"""
    try:
        import lightgbm as lgb
        if hasattr(lgb, 'Booster'):
            # Special handling for conditional monitoring
            original_init = lgb.Booster.__init__
            def monitored_init(self, *args, **kwargs):
                if 'model_file' in kwargs or (args and isinstance(args[0], str)):
                    return monitor.monitor_api(original_init, phase="LOADING")(self, *args, **kwargs)
                return original_init(self, *args, **kwargs)
            lgb.Booster.__init__ = monitored_init
    except ImportError:
        pass
#----------------------------------------------------------------------------------------------
def apply_catboost_aspects():
    """Monitor CatBoost operations"""
    try:
        from catboost import CatBoost, CatBoostClassifier, CatBoostRegressor
        
        CatBoost.load_model = monitor.monitor_api(CatBoost.load_model, phase="LOADING")
        CatBoostClassifier.load_model = monitor.monitor_api(CatBoostClassifier.load_model, phase="LOADING")
        CatBoostRegressor.load_model = monitor.monitor_api(CatBoostRegressor.load_model, phase="LOADING")
    except ImportError:
        pass
#----------------------------------------------------------------------------------------------
def apply_sklearn_aspects():
    """Monitor scikit-learn operations"""
    try:
        import joblib
        joblib.load = monitor.monitor_api(joblib.load, phase="LOADING")
    except ImportError:
        pass
    
    try:
        import pickle
        pickle.load = monitor.monitor_api(pickle.load, phase="LOADING")
        pickle.loads = monitor.monitor_api(pickle.loads, phase="LOADING")
    except ImportError:
        pass
    
   
#----------------------------------------------------------------------------------------------
def apply_flax_jax_aspects():
    """Monitor JAX/Flax operations"""
    try:
        from flax import serialization
        serialization.msgpack_restore = monitor.monitor_api(serialization.msgpack_restore, phase="LOADING")
        serialization.from_bytes = monitor.monitor_api(serialization.from_bytes, phase="LOADING")
        serialization.from_state_dict = monitor.monitor_api(serialization.from_state_dict, phase="LOADING")
    except ImportError:
        pass
    
    try:
        import jax
        if hasattr(jax, 'jit'):
            # JAX jit returns a function, so wrap the result
            original_jit = jax.jit
            def monitored_jit(fun, *args, **kwargs):
                jitted = original_jit(fun, *args, **kwargs)
                return monitor.monitor_api(jitted, phase="EXECUTION")
            jax.jit = monitored_jit
    except ImportError:
        pass
#---------------------------------------------------------------------------------------------- 
def apply_tflite_aspects():
    """Monitor TensorFlow Lite operations"""
    try:
        import tensorflow as tf
        if hasattr(tf.lite, 'Interpreter'):
            tf.lite.Interpreter.__init__ = monitor.monitor_api(
                tf.lite.Interpreter.__init__, phase="LOADING"
            )
    except ImportError:
        pass
#---------------------------------------------------------------------------------------------- 
def apply_coreml_aspects():
    """Monitor CoreML operations"""
    try:
        import coremltools as ct
        if hasattr(ct.models, 'MLModel'):
            ct.models.MLModel.__init__ = monitor.monitor_api(
                ct.models.MLModel.__init__, phase="LOADING"
            )
    except ImportError:
        pass
#---------------------------------------------------------------------------------------------- 
def apply_paddlepaddle_aspects():
    """Monitor PaddlePaddle operations"""
    try:
        import paddle
        paddle.jit.load = monitor.monitor_api(paddle.jit.load, phase="LOADING")
        paddle.load = monitor.monitor_api(paddle.load, phase="LOADING")
    except ImportError:
        pass
#----------------------------------------------------------------------------------------------
def apply_mxnet_aspects():
    """Monitor MXNet operations"""
    try:
        import mxnet as mx
        mx.nd.load = monitor.monitor_api(mx.nd.load, phase="LOADING")
        mx.sym.load = monitor.monitor_api(mx.sym.load, phase="LOADING")
    except ImportError:
        pass
        
def apply_numpy_aspects():
    """Monitor NumPy load operations"""
    try:
        np.load = monitor.monitor_api(np.load, phase="LOADING")
    except Exception:
        pass        

def apply_dill_aspects():
    """Monitor dill load operations"""
    try:
        import dill as dill_lib
        dill_lib.load = monitor.monitor_api(dill_lib.load, phase="LOADING")
        dill_lib.loads = monitor.monitor_api(dill_lib.loads, phase="LOADING")
        # dill also has load_module, load_session
        if hasattr(dill_lib, 'load_module'):
            dill_lib.load_module = monitor.monitor_api(dill_lib.load_module, phase="LOADING")
        if hasattr(dill_lib, 'load_session'):
            dill_lib.load_session = monitor.monitor_api(dill_lib.load_session, phase="LOADING")
    except ImportError:
        pass
def apply_onnx_protobuf_aspects():
    try:
        import onnx
        onnx.load = monitor.monitor_api(onnx.load, phase="LOADING")
        onnx.load_model = monitor.monitor_api(onnx.load_model, phase="LOADING")
    except ImportError:
        pass
        
def apply_pmml_aspects():
    """Monitor PMML model operations"""
    try:
        from pypmml import Model as PMMLModel
        PMMLModel.load = monitor.monitor_api(PMMLModel.load, phase="LOADING")
        if hasattr(PMMLModel, 'fromFile'):
            PMMLModel.fromFile = monitor.monitor_api(PMMLModel.fromFile, phase="LOADING")
        if hasattr(PMMLModel, 'fromString'):
            PMMLModel.fromString = monitor.monitor_api(PMMLModel.fromString, phase="LOADING")
    except ImportError:
        pass
#---------------------------------------------------------------------------------------------- 
               
def AOP_monitoring():
    apply_safetensors_aspects()          
    apply_huggingface_aspects() 
    apply_tensorflow_aspects() 
    apply_pytorch_aspects()    
    #apply_system_operation_aspects()  
    #apply_protocol_aspects()            
    #apply_tensor_operation_aspects()
    apply_onnx_aspects()
    apply_onnx_protobuf_aspects()
    apply_pmml_aspects()
    apply_xgboost_aspects()
    apply_lightgbm_aspects()
    apply_catboost_aspects()
    apply_sklearn_aspects()
    apply_flax_jax_aspects()
    apply_tflite_aspects()
    apply_coreml_aspects()
    apply_paddlepaddle_aspects()
    apply_mxnet_aspects()
    apply_numpy_aspects()
    apply_dill_aspects()
    print("[AOP] Comprehensive model loading monitoring active")
    print("   TensorFlow (SavedModel, Keras, Checkpoints, TFLite)")
    print("   PyTorch (torch.load, JIT, State Dict, Package)")
    print("   SafeTensors (torch, numpy, tensorflow)")
    print("   Hugging Face (Models, Pipelines, Datasets)")
    print("   ONNX Runtime")
    print("   Gradient Boosting (XGBoost, LightGBM, CatBoost)")
    print("   Scikit-learn (joblib, pickle)")
    print("   JAX/Flax")
    print("   CoreML")
    print("   PaddlePaddle")
    print("   MXNet")
    print("   NumPy (.npy, .npz)")
    print("   Dill (extended pickle)")
    print("   PMML (pypmml)")
    #print("   Protocol-level (pickle, msgpack, protobuf)")



# ==============================================================================
# CLI ENTRY POINT
# ==============================================================================


if __name__ == "__main__":
    
    AOP_monitoring()
    import sys
    if len(sys.argv) > 1:
        path = sys.argv[1]
        
        # Check if it's a single model or directory of models
        if os.path.isdir(path):
            # Check if it contains model files or subdirectories
            contents = os.listdir(path)
            has_model_files = any(
             f.endswith((
             # PyTorch and TorchScript
             '.pt',  '.pt2', '.pth', '.th','.ckpt',
             # TensorFlow / Keras
             '.h5', '.keras', '.pb', '.tflite',
             # PyTorch serialization / checkpoints
             '.bin', '.safetensors', '.zip',
             '.tar', '.tar.gz',
             # Gradient boosting
             '.xgb', '.bst', '.ubj', '.lgb', '.cbm',
             # JAX / Flax
             '.msgpack',
             # Scikit-learn and general pickles
             '.joblib', '.pkl', '.pickle', '.dill',
             # CoreML
             '.mlmodel', '.mlpackage',
             # MXNet
             '.params',
             # PaddlePaddle
             '.pdmodel', '.pdiparams',
             # TensorRT
             '.engine', '.plan', '.trt',
             # ONNX
             '.onnx',
             # NumPy
             '.npy', '.npz',
             # PMML
             '.pmml'
             )) for f in contents
            )
            
            if has_model_files:
                # Single model folder
                results = analyze_and_execute_model(path)
                print("\n" + "="*70)
                print("FINAL RESULTS:")
                print(json.dumps(results, indent=2, default=str))
            else:
                # Directory containing multiple model folders
                results = process_all_models_in_directory(path)
        else:
            print(f"Error: {path} is not a directory")
    else:
        print("\nUsage:")
        print("  python script.py /path/to/model/folder        # For single model")
        print("  python script.py /path/to/models/directory    # For multiple models")
        print("\nExample:")
        print("  python script.py ./Models/Narsil_totallysafe")
        print("  python script.py ./Models/")
