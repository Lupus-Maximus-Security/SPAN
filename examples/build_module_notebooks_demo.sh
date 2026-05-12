#!/usr/bin/env bash
#
# Build per-module review notebooks from whatever RPMs live in examples/rpms/.
#
# Each RPM's NVR name is parsed to derive a module name (the package name
# portion before the first '-' in the version field).  All RPMs that share
# the same package name are grouped into one module.
#
# Run module_notebooks_demo_rpm_download.sh first if examples/rpms/ is empty.
#
# Requires: policycoreutils (for SELinux policy + file_contexts), span
#           installed in the active Python environment.

set -euo pipefail
shopt -s nullglob

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
PROJECT_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)
cd "$PROJECT_ROOT"

RPM_DIR="$SCRIPT_DIR/rpms"
CSV="$SCRIPT_DIR/modules.csv"
OUTDIR="$SCRIPT_DIR/module_notebooks_output"
TEMPLATE="$SCRIPT_DIR/module_review_template.ipynb"

POLICY_DIR=/etc/selinux/targeted/policy
FILE_CONTEXTS=/etc/selinux/targeted/contexts/files/file_contexts

# ── preflight ────────────────────────────────────────────────────────────────

RPMS=( "$RPM_DIR"/*.rpm )
if (( ${#RPMS[@]} == 0 )); then
    echo "error: no *.rpm files found in $RPM_DIR" >&2
    echo "       run module_notebooks_demo_rpm_download.sh first." >&2
    exit 1
fi

if [[ ! -d "$POLICY_DIR" ]]; then
    echo "error: $POLICY_DIR not found — is SELinux installed?" >&2
    exit 1
fi
if [[ ! -f "$FILE_CONTEXTS" ]]; then
    echo "error: $FILE_CONTEXTS not found — is policycoreutils installed?" >&2
    exit 1
fi

mkdir -p "$OUTDIR"

# ── build CSV ────────────────────────────────────────────────────────────────
# Derive module name from the RPM filename: strip arch + .rpm suffix, then
# take the package name (everything up to the first '-<digit>' version field).
#
#   nginx-1.24.0-1.el9.x86_64.rpm  →  nginx
#   postgresql-server-15.6-1.el9.x86_64.rpm  →  postgresql-server

echo ">> found ${#RPMS[@]} RPM(s) in $RPM_DIR"
echo ">> writing $CSV"

{
    echo "module_name,rpm_path"
    for rpm in "${RPMS[@]}"; do
        basename=$(basename "$rpm" .rpm)             # strip .rpm
        basename=${basename%.*}                       # strip .arch
        # strip trailing -<version>-<release>  (first field starting with a digit)
        pkg=$(sed 's/-[0-9].*//' <<< "$basename")
        echo "$pkg,$(realpath "$rpm")"
    done
} > "$CSV"

# ── run builder ──────────────────────────────────────────────────────────────

POLICY=$(ls -1v "$POLICY_DIR"/policy.* | tail -n 1)
echo ">> using policy:        $POLICY"
echo ">> using file_contexts: $FILE_CONTEXTS"
echo ">> output directory:    $OUTDIR"

python -m span.module_notebook_builder \
    --csv "$CSV" \
    --policy "$POLICY" \
    --file-contexts "$FILE_CONTEXTS" \
    --template "$TEMPLATE" \
    --outdir "$OUTDIR" \
    --keep-going

echo ">> done. See $OUTDIR for the per-module .ipynb and .md files."
