#!/usr/bin/env bash
#
# Copy RPMs from <input-dir> to <output-dir> only when their exact
# version-release-arch is NOT available in any enabled DNF repository.
#
# At startup, lists available repos and prompts for any to exclude from the
# DNF queries (useful for excluding local/internal repos that you know already
# mirror the packages).
#
# Usage:
#   filter_rpms_not_in_repos.sh <input-rpm-dir> <output-dir>

set -euo pipefail
shopt -s nullglob

# ── args ──────────────────────────────────────────────────────────────────────

if (( $# != 2 )); then
    echo "usage: $(basename "$0") <input-rpm-dir> <output-dir>" >&2
    exit 1
fi

INPUT_DIR=$(realpath "$1")
OUTPUT_DIR=$(realpath "$2")

if [[ ! -d "$INPUT_DIR" ]]; then
    echo "error: input directory not found: $INPUT_DIR" >&2
    exit 1
fi

for cmd in dnf rpm; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "error: $cmd not found." >&2
        exit 1
    fi
done

# ── repo exclusion prompt ─────────────────────────────────────────────────────

echo "Enabled DNF repositories:"
dnf repolist --enabled 2>/dev/null | tail -n +2 | awk '{printf "  %s\n", $1}'
echo

read -rp "Repos to exclude from queries (comma-separated, or blank for none): " EXCLUDE_INPUT

DISABLE_REPO_ARGS=()
if [[ -n "$EXCLUDE_INPUT" ]]; then
    IFS=',' read -ra _repos <<< "$EXCLUDE_INPUT"
    for _repo in "${_repos[@]}"; do
        _repo=${_repo// /}   # strip spaces
        [[ -n "$_repo" ]] && DISABLE_REPO_ARGS+=( "--disablerepo=$_repo" )
    done
fi

if (( ${#DISABLE_REPO_ARGS[@]} > 0 )); then
    echo "Excluding: ${DISABLE_REPO_ARGS[*]}"
else
    echo "No repos excluded."
fi
echo

# ── gather RPM metadata ───────────────────────────────────────────────────────

RPMS=( "$INPUT_DIR"/*.rpm )
if (( ${#RPMS[@]} == 0 )); then
    echo "No *.rpm files found in $INPUT_DIR"
    exit 0
fi

echo "Reading metadata for ${#RPMS[@]} RPM(s)..."

# Arrays indexed by position (bash 3-compat; no associative arrays needed)
rpm_files=()
rpm_names=()
rpm_vras=()   # version-release.arch — used for matching dnf repoquery output

for rpm_file in "${RPMS[@]}"; do
    read -r _name _version _release _arch < <(
        rpm -qp --queryformat '%{NAME} %{VERSION} %{RELEASE} %{ARCH}\n' \
            "$rpm_file" 2>/dev/null
    )
    rpm_files+=( "$rpm_file" )
    rpm_names+=( "$_name" )
    rpm_vras+=( "$_version-$_release.$_arch" )
done

# ── bulk DNF query ────────────────────────────────────────────────────────────
# Query every unique package name in one dnf repoquery call to avoid paying
# the metadata-refresh cost once per RPM.

echo "Querying DNF repositories (this may take a moment)..."

# Unique names
declare -A _seen_names=()
unique_names=()
for _n in "${rpm_names[@]}"; do
    if [[ -z "${_seen_names[$_n]+x}" ]]; then
        unique_names+=( "$_n" )
        _seen_names["$_n"]=1
    fi
done

# "name version-release.arch" — one per line, for all packages of interest
available_raw=$(
    dnf repoquery --available \
        --queryformat '%{name} %{version}-%{release}.%{arch}\n' \
        "${DISABLE_REPO_ARGS[@]}" \
        "${unique_names[@]}" 2>/dev/null \
    || true
)

# Build lookup key set:  "name version-release.arch" -> present
declare -A in_repo=()
while IFS= read -r line; do
    [[ -n "$line" ]] && in_repo["$line"]=1
done <<< "$available_raw"

# ── copy missing RPMs ─────────────────────────────────────────────────────────

mkdir -p "$OUTPUT_DIR"
echo
echo "Filtering..."
echo

copied=0
skipped=0

for i in "${!rpm_files[@]}"; do
    rpm_file="${rpm_files[$i]}"
    key="${rpm_names[$i]} ${rpm_vras[$i]}"
    base=$(basename "$rpm_file")

    printf "  %-60s" "$base"

    if [[ -z "${in_repo[$key]+x}" ]]; then
        echo "→ not in repos — copying"
        cp "$rpm_file" "$OUTPUT_DIR/"
        (( ++copied ))
    else
        echo "→ available in repos — skipping"
        (( ++skipped ))
    fi
done

echo
echo "Done.  Copied: $copied  |  Skipped (in repos): $skipped"
echo "Output directory: $OUTPUT_DIR"
