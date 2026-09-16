#!/usr/bin/env bash
#
# run.sh - C4: TensorFlow SavedModel API Abuse
#
# Two of the four attacks require listener servers running on localhost.
# This script starts them automatically before the scan and kills them after.
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
for path in "$REAL_HOME/ModelShield/Test_Suites/TF_Abuse" \
            "$REAL_HOME/ModelShield/evaluation_data/TF_Abuse"; do
    if [ -d "$path" ]; then
        DATA_DIR="$path"
        break
    fi
done
[ -n "$DATA_DIR" ] || { echo "ERROR: cannot find TF_Abuse test data"; exit 1; }

# Locate the server scripts inside the test data
IP_SERVER=""
FILE_SERVER=""
for base in "$DATA_DIR/TF_Abuse/IP_exposure" "$DATA_DIR/IP_exposure" "$DATA_DIR/IP_Exposure"; do
    if [ -f "$base/server_for_hack.py" ]; then
        IP_SERVER="$base/server_for_hack.py"
        break
    fi
done
for base in "$DATA_DIR/TF_Abuse/file_leak" "$DATA_DIR/file_leak"; do
    if [ -f "$base/server.py" ]; then
        FILE_SERVER="$base/server.py"
        break
    fi
done

SCAN_SCRIPT="$SCAN_DIR/local_scan_tf_abuse_attacks.py"
SCANNER_PYTHON="$SCANNER_ENV/bin/python3.9"

[ -f "$SCAN_SCRIPT" ]    || { echo "ERROR: $SCAN_SCRIPT not found"; exit 1; }
[ -f "$SCANNER_PYTHON" ] || { echo "ERROR: $SCANNER_PYTHON not found"; exit 1; }

echo ""
echo "C4: TensorFlow SavedModel API Abuse"
echo "  user       $REAL_USER"
echo "  code       $REPO_DIR"
echo "  env pool   $ENVS_ROOT"
echo "  scanner    $SCANNER_ENV"
echo "  data       $DATA_DIR"
echo "  IP server  ${IP_SERVER:-not found}"
echo "  file server ${FILE_SERVER:-not found}"
echo ""

# Start listener servers for IP_exposure and file_leak attacks
SERVER_PID_1=""
SERVER_PID_2=""

if [ -n "$IP_SERVER" ]; then
    echo "Starting IP_exposure server on port 1236..."
    python3 "$IP_SERVER" &
    SERVER_PID_1=$!
fi

if [ -n "$FILE_SERVER" ]; then
    echo "Starting file_leak server on port 1234..."
    python3 "$FILE_SERVER" &
    SERVER_PID_2=$!
fi

sleep 2

cleanup() {
    [ -n "$SERVER_PID_1" ] && kill "$SERVER_PID_1" 2>/dev/null
    [ -n "$SERVER_PID_2" ] && kill "$SERVER_PID_2" 2>/dev/null
}
trap cleanup EXIT

ulimit -u unlimited
ulimit -l unlimited

echo "Running local_scan_tf_abuse_attacks.py..."
echo ""

"$SCANNER_PYTHON" "$SCAN_SCRIPT" --local-dir "$DATA_DIR"
