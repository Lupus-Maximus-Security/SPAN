#!/usr/bin/env bash
#
# Create the SPAN virtual environment and install the package.
#
# Mirrors the steps in the README:
#   1. Install setools system RPM (requires sudo).
#   2. Create a venv with --system-site-packages so the setools bindings
#      installed by the RPM are visible inside the venv.
#   3. pip install . inside the venv.
#
# Usage:
#   ./install.sh          # standard install
#   ./install.sh --dev    # editable install (pip install -e .)

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
VENV_DIR="$SCRIPT_DIR/venv"

DEV=0
for arg in "$@"; do
    [[ "$arg" == "--dev" ]] && DEV=1
done

# ── setools system package ────────────────────────────────────────────────────

if ! command -v dnf >/dev/null 2>&1; then
    echo "warning: dnf not found — skipping 'sudo dnf install setools'." >&2
    echo "         Install setools manually before continuing." >&2
else
    echo ">> installing setools system package"
    sudo dnf install -y setools
fi

# ── virtual environment ───────────────────────────────────────────────────────

if [[ -d "$VENV_DIR" ]]; then
    echo ">> venv already exists at $VENV_DIR — skipping creation"
else
    echo ">> creating venv with --system-site-packages"
    python3 -m venv --system-site-packages "$VENV_DIR"
fi

# ── pip install ───────────────────────────────────────────────────────────────

PIP="$VENV_DIR/bin/pip"

echo ">> upgrading pip"
"$PIP" install --quiet --upgrade pip

if (( DEV )); then
    echo ">> installing SPAN in editable mode (pip install -e .)"
    "$PIP" install -e "$SCRIPT_DIR"
else
    echo ">> installing SPAN (pip install .)"
    "$PIP" install "$SCRIPT_DIR"
fi

echo
echo "Done. To use SPAN, activate the environment in your shell:"
echo "  source venv/bin/activate"
