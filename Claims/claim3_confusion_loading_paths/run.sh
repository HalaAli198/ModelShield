#!/usr/bin/env bash
#
# run.sh - C3: Loading-Path Obfuscation
#
set -euo pipefail

REAL_USER="${SUDO_USER:-$(whoami)}"
REAL_HOME=$(eval echo "~$REAL_USER")

if [ -d "$REAL_HOME/ModelShield/Code" ]; then
    REPO_DIR="$REAL_HOME/ModelShield/Code"
elif [ -d "$REAL_HOME/ModelShield/code" ]; then
    REPO_DIR="$REAL_HOME/ModelShield/code"
else
    echo "ERROR: cannot find Code/ directory"; exit 1
fi

if [ -d "$REAL_HOME/ms_envs/env_pool" ]; then
    ENVS_ROOT="$REAL_HOME/ms_envs/env_pool"
    SCANNER_ENV="$REAL_HOME/ms_envs/scanner_env"
elif [ -d "$REAL_HOME/modelshield/env_pool" ]; then
    ENVS_ROOT="$REAL_HOME/modelshield/env_pool"
    SCANNER_ENV="$REAL_HOME/modelshield/scanner_env"
else
    echo "ERROR: cannot find env_pool. Run install.sh first."; exit 1
fi

export ENVS_ROOT

if [ -d "$REPO_DIR/Platform_Scanning" ]; then
    SCAN_DIR="$REPO_DIR/Platform_Scanning"
elif [ -d "$REPO_DIR/platform_scanning" ]; then
    SCAN_DIR="$REPO_DIR/platform_scanning"
else
    echo "ERROR: cannot find Platform_Scanning in $REPO_DIR"; exit 1
fi

DATA_DIR=""
for path in "$REAL_HOME/ModelShield/Test_Suites/Pickle_Paths" \
            "$REAL_HOME/ModelShield/evaluation_data/Pickle_Paths"; do
    if [ -d "$path" ]; then
        DATA_DIR="$path"
        break
    fi
done
[ -n "$DATA_DIR" ] || { echo "ERROR: cannot find Pickle_Paths test data"; exit 1; }

SCAN_SCRIPT="$SCAN_DIR/local_scan_pickle_paths.py"
SCANNER_PYTHON="$SCANNER_ENV/bin/python3.9"

[ -f "$SCAN_SCRIPT" ]    || { echo "ERROR: $SCAN_SCRIPT not found"; exit 1; }
[ -f "$SCANNER_PYTHON" ] || { echo "ERROR: $SCANNER_PYTHON not found"; exit 1; }

echo ""
echo "C3: Loading-Path Obfuscation"
echo "  user       $REAL_USER"
echo "  code       $REPO_DIR"
echo "  env pool   $ENVS_ROOT"
echo "  scanner    $SCANNER_ENV"
echo "  data       $DATA_DIR"
echo ""

ulimit -u unlimited
ulimit -l unlimited

"$SCANNER_PYTHON" "$SCAN_SCRIPT" --local-dir "$DATA_DIR"
