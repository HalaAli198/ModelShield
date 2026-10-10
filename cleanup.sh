#!/usr/bin/env bash
set -euo pipefail

REAL_USER="${SUDO_USER:-$(whoami)}"
REAL_HOME=$(eval echo "~$REAL_USER")

echo "Full cleanup of ModelShield install for user: $REAL_USER"

# ModelShield directories
rm -rf /root/ModelShield /root/ms_envs
rm -rf "$REAL_HOME/ModelShield" "$REAL_HOME/ms_envs"
echo "  removed ModelShield directories"

# Bait SSH key
rm -f /home/hala/.ssh/id_rsa
echo "  removed bait SSH key"

# gdown
pip uninstall -y gdown 2>/dev/null || true
rm -rf /root/.cache/gdown "$REAL_HOME/.cache/gdown"
echo "  removed gdown"

# Python 3.9 (deadsnakes)
apt-get remove --purge -y python3.9 python3.9-venv python3.9-dev python3.9-tk 2>/dev/null || true
add-apt-repository --remove -y ppa:deadsnakes/ppa 2>/dev/null || true
echo "  removed Python 3.9 + deadsnakes PPA"

# Java 11 + Ant
apt-get remove --purge -y openjdk-11-jdk ant 2>/dev/null || true
echo "  removed Java 11 + Ant"

# eBPF tools
apt-get remove --purge -y bpfcc-tools python3-bpfcc 2>/dev/null || true
echo "  removed eBPF tools"

# Extra system packages
apt-get remove --purge -y xvfb w3m xdg-utils 2>/dev/null || true
echo "  removed xvfb, w3m, xdg-utils"

# Clean up orphaned dependencies
apt-get autoremove --purge -y
apt-get clean
echo "  autoremoved orphan packages"

echo ""
echo "Done. Everything from install.sh has been removed."
