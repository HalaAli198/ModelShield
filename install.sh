#!/usr/bin/env bash
#
# install.sh
# Sets up ModelShield and all its dependencies on a clean Ubuntu 22.04 box.
# Downloads the code from GitHub.
#
# Run as root:
#   chmod +x install.sh
#   sudo ./install.sh
#
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a

# ── Resolve the real user's home (not /root when run via sudo) ────────────────
REAL_USER="${SUDO_USER:-$(whoami)}"
REAL_HOME=$(eval echo "~$REAL_USER")

# ── Paths ─────────────────────────────────────────────────────────────────────
GITHUB_REPO="https://github.com/HalaAli198/ModelShield.git"
DOWNLOAD_DIR="$REAL_HOME/ModelShield"
REPO_DIR="$REAL_HOME/ModelShield/Code"
ENVS_ROOT="$REAL_HOME/ms_envs/env_pool"
SCANNER_ENV="$REAL_HOME/ms_envs/scanner_env"

export ENVS_ROOT

echo ""
echo "ModelShield installer"
echo "  user        $REAL_USER"
echo "  repo        $GITHUB_REPO"
echo "  clone to    $DOWNLOAD_DIR"
echo "  code dir    $REPO_DIR"
echo "  env pool    $ENVS_ROOT"
echo "  scanner     $SCANNER_ENV"
echo ""

# ── 1. Python 3.9 ────────────────────────────────────────────────────────────
echo "[1/10] Installing Python 3.9 from deadsnakes PPA..."

apt-get update -qq
apt-get install -y -qq software-properties-common
add-apt-repository -y ppa:deadsnakes/ppa
apt-get update -qq
apt-get install -y -qq python3.9 python3.9-venv python3.9-dev build-essential

python3.9 --version
echo "  ok"

# ── 2. Java 11 ───────────────────────────────────────────────────────────────
echo "[2/10] Installing OpenJDK 11 + Ant..."

apt-get install -y -qq openjdk-11-jdk ant

java -version 2>&1 | head -1
echo "  ok"

# ── 3. eBPF tooling ──────────────────────────────────────────────────────────
echo "[3/10] Installing eBPF tools and kernel headers..."

apt-get install -y -qq bpfcc-tools python3-bpfcc "linux-headers-$(uname -r)"

python3 -c "
from bcc import BPF
BPF(text='int kprobe__sys_clone(void *ctx) { return 0; }')
print('  eBPF probe compiled successfully')
"

# ── 4. Extra system packages ─────────────────────────────────────────────────
echo "[4/10] Installing tkinter, virtual framebuffer, and browser support..."

apt-get install -y -qq python3.9-tk xvfb w3m xdg-utils unzip git

python3.9 -c "import tkinter; print('  tkinter ok')"
which w3m > /dev/null && echo "  w3m ok"
echo "  ok"

# ── 5. Clone the repo from GitHub ────────────────────────────────────────────
echo "[5/10] Cloning ModelShield from GitHub..."

if [ -f "$REPO_DIR/ModelShield_Core_Scripts/model_inspector.py" ]; then
    echo "  $REPO_DIR already populated, skipping clone"
else
    rm -rf "$DOWNLOAD_DIR"
    git clone "$GITHUB_REPO" "$DOWNLOAD_DIR"
fi

chown -R "$REAL_USER":"$REAL_USER" "$DOWNLOAD_DIR"

# Detect folder name casing
if [ -d "$REPO_DIR/Runtime_Environments" ]; then
    RT_ENV_DIR="$REPO_DIR/Runtime_Environments"
elif [ -d "$REPO_DIR/runtime_environments" ]; then
    RT_ENV_DIR="$REPO_DIR/runtime_environments"
else
    echo "ERROR: cannot find runtime environments directory"
    find "$REPO_DIR" -maxdepth 1 -type d
    exit 1
fi

if [ -d "$REPO_DIR/Platform_Scanning" ]; then
    SCAN_DIR="$REPO_DIR/Platform_Scanning"
elif [ -d "$REPO_DIR/platform_scanning" ]; then
    SCAN_DIR="$REPO_DIR/platform_scanning"
else
    echo "ERROR: cannot find platform scanning directory"
    find "$REPO_DIR" -maxdepth 1 -type d
    exit 1
fi

[ -f "$RT_ENV_DIR/build_env_pool.sh" ] \
    || { echo "ERROR: build_env_pool.sh not found"; exit 1; }
echo "  ok"

# ── 6. Build the runtime environment pool ─────────────────────────────────────
echo "[6/10] Building runtime environment pool (this takes a while)..."

cd "$RT_ENV_DIR"
chmod +x build_env_pool.sh
./build_env_pool.sh

echo "  verifying each environment..."

"$ENVS_ROOT/torch_current/bin/python3.9" -c \
    "import torch, transformers; print('    torch_current', torch.__version__, transformers.__version__)"

"$ENVS_ROOT/torch_legacy/bin/python3.9" -c \
    "import torch, transformers; print('    torch_legacy', torch.__version__, transformers.__version__)"

"$ENVS_ROOT/tf2/bin/python3.9" -c \
    "import tensorflow as tf; print('    tf2', tf.__version__)"

"$ENVS_ROOT/sklearn/bin/python3.9" -c \
    "import sklearn, joblib, xgboost, lightgbm, catboost, pypmml; print('    sklearn ok')"

"$ENVS_ROOT/onnx/bin/python3.9" -c \
    "import onnxruntime, onnx; print('    onnx', onnxruntime.__version__, onnx.__version__)"

cd "$RT_ENV_DIR"
python3.9 -c "from env_selector import validate_pool; validate_pool()"
echo "  pool validated"

# ── 7. Extra pip packages for evaluation models ──────────────────────────────
echo "[7/10] Installing extra packages needed by evaluation models..."

"$ENVS_ROOT/torch_current/bin/pip" install --quiet pydevd Pillow requests

"$ENVS_ROOT/sklearn/bin/pip" install --quiet ipython mlflow requests cloudpickle
"$ENVS_ROOT/sklearn/bin/pip" install --quiet \
    torch==2.4.0+cpu --index-url https://download.pytorch.org/whl/cpu

"$ENVS_ROOT/onnx/bin/pip" install --quiet \
    torch==2.4.0+cpu --index-url https://download.pytorch.org/whl/cpu

"$ENVS_ROOT/tf2/bin/pip" install --quiet \
    torch==2.4.0+cpu --index-url https://download.pytorch.org/whl/cpu

echo "  ok"

# ── 8. Create bait files for credential-access payloads ──────────────────────
echo "[8/10] Creating bait SSH key for credential-access payloads..."

mkdir -p /home/hala/.ssh
echo "DUMMY_SSH_KEY_FOR_TESTING" > /home/hala/.ssh/id_rsa
chmod 644 /home/hala/.ssh/id_rsa

echo "  ok"

# ── 9. Create scanner environment ────────────────────────────────────────────
echo "[9/10] Creating scanner environment..."

python3.9 -m venv "$SCANNER_ENV"
"$SCANNER_ENV/bin/pip" install --quiet huggingface_hub modelscope kaggle requests

"$SCANNER_ENV/bin/python3.9" -c "import huggingface_hub; print('  scanner env ok')"

chown -R "$REAL_USER":"$REAL_USER" "$REAL_HOME/ms_envs"

# ── 10. Configure scan scripts ───────────────────────────────────────────────
echo "[10/10] Configuring scan script paths..."

INSPECTOR="$REPO_DIR/ModelShield_Core_Scripts/model_inspector.py"
CLASSIFIER="$REPO_DIR/ModelShield_Core_Scripts/attack_behavior_classifier.py"

for script in "$SCAN_DIR"/local_scan*.py; do
    [ -f "$script" ] || continue
    sed -i "s|sys.path.insert(0, '.*[Rr]untime_[Ee]nvironments')|sys.path.insert(0, '$RT_ENV_DIR')|g" "$script"
    sed -i "s|INSPECTOR_PATH = '.*model_inspector.py'|INSPECTOR_PATH = '$INSPECTOR'|g" "$script"
    sed -i "s|CLASSIFIER_PATH = '.*attack_behavior_classifier.py'|CLASSIFIER_PATH = '$CLASSIFIER'|g" "$script"
done

echo "  ok"

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo "Done."
echo ""
echo "WARNING: The evaluation datasets contain malicious model samples."
echo "         Always run experiments inside an isolated VM."
echo ""
echo "See Claims/ for experiment instructions and expected results."
echo "See README.md for the full evaluation guide."
echo ""
