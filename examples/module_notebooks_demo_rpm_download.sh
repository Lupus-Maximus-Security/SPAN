#!/usr/bin/env bash
#
# Download the demo RPMs (nginx, postgresql, postgresql-server) into
# examples/rpms/ so that build_module_notebooks_demo.sh can consume them.
#
# Requires: dnf-plugins-core (for `dnf download`), an RPM-based distro.

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
RPM_DIR="$SCRIPT_DIR/rpms"

if ! command -v dnf >/dev/null 2>&1; then
    echo "error: dnf not found — this demo expects an RPM-based distro." >&2
    exit 1
fi

mkdir -p "$RPM_DIR"

echo ">> downloading RPMs into $RPM_DIR"
dnf download --destdir="$RPM_DIR" nginx postgresql postgresql-server

echo ">> done. RPMs are in $RPM_DIR"
