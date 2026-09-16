#!/usr/bin/env bash
#
# run_quick_test.sh
# Runs local_scan_quick_test.py using the Quick_Test_Samples from the repo.
#
# Run as root:
#   chmod +x run_quick_test.sh
#   sudo ./run_quick_test.sh
#
set -euo pipefail

REAL_USER="${SUDO_USER:-$(whoami)}"
REAL_HOME=$(eval echo "~$REAL_USER")

REPO_DIR="$REAL_HOME/ModelShield/Code"
SCANNER_ENV="$REAL_HOME/ms_envs/scanner_env"
ENVS_ROOT="$REAL_HOME/ms_envs/env_pool"
SAMPLES_DIR="$REAL_HOME/ModelShield/Quick_Test_Samples"

export ENVS_ROOT

if [ -d "$REPO_DIR/Platform_Scanning" ]; then
    SCAN_DIR="$REPO_DIR/Platform_Scanning"
elif [ -d "$REPO_DIR/platform_scanning" ]; then
    SCAN_DIR="$REPO_DIR/platform_scanning"
else
    echo "ERROR: cannot find Platform_Scanning in $REPO_DIR"; exit 1
fi

SCAN_SCRIPT="$SCAN_DIR/local_scan_quick_test.py"
SCANNER_PYTHON="$SCANNER_ENV/bin/python3.9"

[ -f "$SCAN_SCRIPT" ]    || { echo "ERROR: $SCAN_SCRIPT not found. Run install.sh first."; exit 1; }
[ -f "$SCANNER_PYTHON" ] || { echo "ERROR: $SCANNER_PYTHON not found. Run install.sh first."; exit 1; }
[ -d "$SAMPLES_DIR" ]    || { echo "ERROR: $SAMPLES_DIR not found. Check the repo clone."; exit 1; }

echo "Samples dir: $SAMPLES_DIR"

mkdir -p "$REAL_HOME/quick_test_results"
chown -R "$REAL_USER":"$REAL_USER" "$REAL_HOME/quick_test_results"

echo "Running local_scan_quick_test.py..."
echo ""

ulimit -u unlimited
ulimit -l unlimited

"$SCANNER_PYTHON" "$SCAN_SCRIPT" --local-dir "$SAMPLES_DIR"
