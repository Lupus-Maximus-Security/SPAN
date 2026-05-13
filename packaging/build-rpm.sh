#!/usr/bin/env bash
#
# Build a SPAN RPM from the current working tree.
#
# Produces a versioned source tarball, sets up a private rpmbuild tree,
# and invokes rpmbuild. Resulting RPM and SRPM paths are printed at the
# end so you can copy them to a repo or install with `dnf install`.
#
# Usage:
#   ./packaging/build-rpm.sh              # build src + binary RPM
#   ./packaging/build-rpm.sh --srpm-only  # only the source RPM
#   ./packaging/build-rpm.sh --outdir DIR # copy finished RPMs to DIR
#
# Requirements on the build host:
#   - rpm-build, python3, python3-pip, python3-devel
#   - network access (pip pulls dependency wheels from PyPI during %install)
#   - setools-devel is NOT required at build time; the runtime Requires
#     pulls in the setools system package on the install host

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
PROJECT_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)
SPEC="$SCRIPT_DIR/span.spec"

SRPM_ONLY=0
OUTDIR=""
for arg in "$@"; do
    case "$arg" in
        --srpm-only) SRPM_ONLY=1 ;;
        --outdir=*)  OUTDIR="${arg#--outdir=}" ;;
        --outdir)    : ;;  # handled below
        -h|--help)
            sed -n '2,20p' "$0"
            exit 0
            ;;
        *)
            echo "unknown argument: $arg" >&2
            exit 2
            ;;
    esac
done

# Support `--outdir DIR` (space-separated) too.
while [[ $# -gt 0 ]]; do
    case "$1" in
        --outdir)
            shift
            OUTDIR="${1:-}"
            ;;
    esac
    shift || true
done

NAME=$(rpmspec -q --srpm --qf '%{NAME}\n' "$SPEC")
VERSION=$(rpmspec -q --srpm --qf '%{VERSION}\n' "$SPEC")
TARBALL="${NAME}-${VERSION}.tar.gz"

BUILD_TREE=$(mktemp -d -t span-rpmbuild.XXXXXX)
trap 'rm -rf "$BUILD_TREE"' EXIT

mkdir -p "$BUILD_TREE"/{BUILD,BUILDROOT,RPMS,SRPMS,SOURCES,SPECS}

echo ">> creating source tarball ${TARBALL}"
# `git archive` keeps the tarball reproducible and only includes tracked
# files. Prefix the entries with NAME-VERSION/ so %autosetup finds them.
git -C "$PROJECT_ROOT" archive \
    --format=tar.gz \
    --prefix="${NAME}-${VERSION}/" \
    -o "$BUILD_TREE/SOURCES/${TARBALL}" \
    HEAD

cp "$SPEC" "$BUILD_TREE/SPECS/"

RPMBUILD_ARGS=(
    --define "_topdir $BUILD_TREE"
    "$BUILD_TREE/SPECS/$(basename "$SPEC")"
)

if (( SRPM_ONLY )); then
    echo ">> building source RPM only"
    rpmbuild -bs "${RPMBUILD_ARGS[@]}"
else
    echo ">> building source + binary RPMs"
    rpmbuild -ba "${RPMBUILD_ARGS[@]}"
fi

SRPM_PATH=$(find "$BUILD_TREE/SRPMS" -maxdepth 1 -name '*.src.rpm' | head -n1)
mapfile -t RPM_PATHS < <(find "$BUILD_TREE/RPMS" -name '*.rpm')

DEST="${OUTDIR:-$PROJECT_ROOT/dist-rpm}"
mkdir -p "$DEST"
[[ -n "$SRPM_PATH" ]] && cp "$SRPM_PATH" "$DEST/"
for r in "${RPM_PATHS[@]}"; do
    cp "$r" "$DEST/"
done

echo
echo "Done. Artifacts in $DEST:"
ls -1 "$DEST" | sed 's/^/  /'
