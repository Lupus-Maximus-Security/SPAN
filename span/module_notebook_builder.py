# Copyright 2026 Lupus Maximus Security, LLC
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
#
# * Neither the name of the copyright holder nor the names of its
#   contributors may be used to endorse or promote products derived from
#   this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

"""CLI tool: CSV of (module, rpm) -> per-module executed notebook + Markdown.

See ``specs/module_notebook_builder.md`` for the design.
"""

import argparse
import csv
import os
import re
import shutil
import stat
import subprocess
import sys
from collections import OrderedDict

import nbformat
import papermill
from nbconvert import MarkdownExporter
from nbconvert.preprocessors import TagRemovePreprocessor
from nbconvert.writers import FilesWriter
from traitlets.config import Config

import setools as se

from . import span as _span


# --------------------------------------------------------------------------- #
# CSV parsing
# --------------------------------------------------------------------------- #

_HEADER_KEYWORDS = ("module", "rpm")


def _looks_like_header(row):
    if len(row) < 2:
        return False
    joined = " ".join(c.lower() for c in row[:2])
    return any(k in joined for k in _HEADER_KEYWORDS)


def parse_csv(csv_path):
    """Return an ``OrderedDict[module_name, list[rpm_path]]`` from ``csv_path``.

    Order is preserved both for module names (first occurrence in CSV) and
    for the RPMs within each module. Blank lines and lines starting with
    ``#`` are skipped. A header row is auto-detected and dropped.
    """
    csv_path = os.path.abspath(csv_path)
    base = os.path.dirname(csv_path)

    with open(csv_path, "r", newline="") as fp:
        sample = fp.read(4096)
        fp.seek(0)

        if csv_path.lower().endswith(".tsv"):
            dialect = csv.excel_tab
        else:
            try:
                dialect = csv.Sniffer().sniff(sample, delimiters=",;")
            except csv.Error:
                dialect = csv.excel

        reader = csv.reader(fp, dialect)
        rows = []
        for raw in reader:
            if not raw:
                continue
            first = raw[0].strip()
            if not first or first.startswith("#"):
                continue
            rows.append([c.strip() for c in raw])

    if rows and _looks_like_header(rows[0]):
        rows = rows[1:]

    groups = OrderedDict()
    for row in rows:
        if len(row) < 2:
            raise ValueError("CSV row needs at least 2 columns: %r" % (row,))
        module, rpm_path = row[0], row[1]
        if not module or not rpm_path:
            raise ValueError("CSV row has empty module or rpm: %r" % (row,))
        if not os.path.isabs(rpm_path):
            rpm_path = os.path.normpath(os.path.join(base, rpm_path))
        groups.setdefault(module, []).append(rpm_path)

    return groups


# --------------------------------------------------------------------------- #
# RPM enumeration
# --------------------------------------------------------------------------- #

def _ensure_rpm_available():
    if shutil.which("rpm") is None:
        raise RuntimeError(
            "the 'rpm' command was not found on PATH; install it (or run on "
            "an RPM-based distro) before invoking module_notebook_builder."
        )


def list_rpm_files(rpm_path):
    """Yield ``(path, mode_int)`` for every file inside ``rpm_path``.

    Shells out to ``rpm`` so we don't have to depend on the rpm-python
    bindings.
    """
    if not os.path.exists(rpm_path):
        raise FileNotFoundError(rpm_path)

    proc = subprocess.run(
        [
            "rpm", "-q",
            "--queryformat", "[%{FILEMODES}\t%{FILENAMES}\n]",
            "-p", rpm_path,
        ],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            "rpm failed for %s: %s" % (rpm_path, proc.stderr.strip())
        )

    for line in proc.stdout.splitlines():
        if not line or "\t" not in line:
            continue
        mode_s, path = line.split("\t", 1)
        try:
            mode = int(mode_s)
        except ValueError:
            continue
        yield path, mode


def classify_rpm_contents(rpm_paths):
    """Walk a list of RPMs, returning policy modules and executables.

    Returns ``(policy_modules, executables)`` where:

    - ``policy_modules`` is a sorted list of ``.pp`` paths (deduplicated
      across RPMs).
    - ``executables`` is a list of dicts with ``path``, ``mode`` (octal
      str), ``rpms`` (sorted basenames of RPMs that ship the path).
      Paths are deduplicated across RPMs; mode is taken from the first
      RPM that contributed the path.
    """
    pp_paths = set()
    # path -> {"mode": int, "rpms": set[str]}
    exec_map = {}

    for rpm_path in rpm_paths:
        rpm_base = os.path.basename(rpm_path)
        for path, mode in list_rpm_files(rpm_path):
            if path.endswith(".pp"):
                pp_paths.add(path)
                continue

            is_regular = (mode & 0o170000) == 0o100000
            owner_exec = bool(mode & 0o100)
            if not (is_regular and owner_exec):
                continue

            entry = exec_map.setdefault(path, {"mode": mode, "rpms": set()})
            entry["rpms"].add(rpm_base)

    executables = []
    for path in sorted(exec_map):
        entry = exec_map[path]
        executables.append({
            "path": path,
            "mode": format(entry["mode"], "o"),
            "rpms": sorted(entry["rpms"]),
        })

    return sorted(pp_paths), executables


# --------------------------------------------------------------------------- #
# File contexts resolution
# --------------------------------------------------------------------------- #

_FC_MODE_BY_QUAL = {
    "--": stat.S_IFREG,
    "-d": stat.S_IFDIR,
    "-l": stat.S_IFLNK,
    "-s": stat.S_IFSOCK,
    "-c": stat.S_IFCHR,
    "-b": stat.S_IFBLK,
    "-p": stat.S_IFIFO,
}

# Characters that mark the end of a regex's literal prefix.
_REGEX_META_RE = re.compile(r"[.\\^$|?*+(\[{]")


class _PurePythonFCResolver:
    """Pure-Python file_contexts matcher.

    Approximates libselinux semantics: parses each line, computes a
    "specificity" (length of the literal prefix), sorts most-specific
    first, returns the type of the first regex that fullmatches the
    path. Skips entries whose mode qualifier disagrees with the
    looked-up file's type.
    """

    def __init__(self, fc_path):
        self.entries = []  # list of (specificity, mode_filter, compiled_regex, type, lineno, raw)
        self.errors = []  # list of (lineno, raw, message)

        with open(fc_path, "r") as fp:
            for lineno, raw in enumerate(fp, start=1):
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue

                parts = line.split()
                if len(parts) < 2:
                    self.errors.append((lineno, raw.rstrip("\n"), "too few fields"))
                    continue

                pattern = parts[0]
                mode_qual = None
                ctx_field = None

                if parts[1] in _FC_MODE_BY_QUAL:
                    mode_qual = parts[1]
                    if len(parts) < 3:
                        self.errors.append((lineno, raw.rstrip("\n"), "missing context"))
                        continue
                    ctx_field = parts[2]
                else:
                    ctx_field = parts[1]

                if ctx_field == "<<none>>":
                    se_type = None
                else:
                    ctx_parts = ctx_field.split(":")
                    if len(ctx_parts) < 3:
                        self.errors.append((lineno, raw.rstrip("\n"),
                                            "bad context %r" % ctx_field))
                        continue
                    se_type = ctx_parts[2]

                try:
                    compiled = re.compile(pattern + r"\Z")
                except re.error as e:
                    self.errors.append((lineno, raw.rstrip("\n"),
                                        "regex error: %s" % e))
                    continue

                specificity = _literal_prefix_len(pattern)
                self.entries.append(
                    (specificity, mode_qual, compiled, se_type, lineno, raw.rstrip("\n"))
                )

        # Higher specificity wins; ties: later lines win (more specific by convention).
        self.entries.sort(key=lambda e: (e[0], e[4]), reverse=True)

    def match(self, path, mode_bits=stat.S_IFREG):
        """Return the SELinux type for ``path`` or ``None`` if no match."""
        for _, mode_qual, regex, se_type, _, _ in self.entries:
            if mode_qual is not None:
                if _FC_MODE_BY_QUAL[mode_qual] != mode_bits:
                    continue
            if regex.match(path):
                return se_type
        return None


def _literal_prefix_len(pattern):
    m = _REGEX_META_RE.search(pattern)
    return len(pattern) if m is None else m.start()


class _LibSELinuxFCResolver:
    """File-contexts matcher backed by libselinux's matchpathcon."""

    def __init__(self, fc_path):
        import selinux  # noqa: F401  (proved available before constructing)
        self._selinux = selinux
        self.errors = []
        selinux.matchpathcon_init(fc_path)

    def match(self, path, mode_bits=stat.S_IFREG):
        # Newer libselinux bindings raise FileNotFoundError on no match
        # instead of returning a non-zero rc. Treat both as "no match".
        try:
            rc, ctx = self._selinux.matchpathcon(path, mode_bits)
        except FileNotFoundError:
            return None
        if rc != 0 or not ctx or ctx == "<<none>>":
            return None
        parts = ctx.split(":")
        if len(parts) < 3:
            return None
        return parts[2]


def build_fc_resolver(fc_path):
    """Return a file-contexts resolver, libselinux-backed when possible."""
    try:
        import selinux  # noqa: F401
    except ImportError:
        return _PurePythonFCResolver(fc_path)
    return _LibSELinuxFCResolver(fc_path)


# --------------------------------------------------------------------------- #
# Entrypoint-type filter from policy
# --------------------------------------------------------------------------- #

def load_entrypoint_types(policy_path):
    """Return the set of type names used as ``file:entrypoint`` in policy."""
    policy = _span.load_policy(policy_path)
    rules = policy.terules_query_raw(
        tclass=["file"], perms=["entrypoint"], trusted_domain_types=[],
    )
    return {str(r.target) for r in rules}


# --------------------------------------------------------------------------- #
# Notebook execution + Markdown export
# --------------------------------------------------------------------------- #

_SLUG_BAD = re.compile(r"[^A-Za-z0-9_.-]+")


def slugify(module_name):
    slug = _SLUG_BAD.sub("_", module_name).strip("_")
    return slug or "module"


def execute_template(template_path, output_path, parameters, kernel_name, cwd):
    papermill.execute_notebook(
        input_path=template_path,
        output_path=output_path,
        parameters=parameters,
        kernel_name=kernel_name,
        progress_bar=False,
        log_output=False,
        cwd=cwd,
    )


def _restore_tags_from_template(template_path, executed_path):
    """Copy cell tags from template into the executed notebook.

    Papermill does not reliably preserve ``metadata.tags`` on cells in the
    output notebook.  Match cells by their ``id`` field (which papermill does
    preserve) and write the tags back so that nbconvert preprocessors such as
    ``TagRemovePreprocessor`` work correctly.
    """
    template_nb = nbformat.read(template_path, as_version=4)
    executed_nb = nbformat.read(executed_path, as_version=4)

    id_to_tags = {}
    for cell in template_nb.cells:
        cell_id = cell.get("id")
        tags = cell.get("metadata", {}).get("tags", [])
        if cell_id and tags:
            id_to_tags[cell_id] = tags

    if not id_to_tags:
        return

    changed = False
    for cell in executed_nb.cells:
        cell_id = cell.get("id")
        if cell_id and cell_id in id_to_tags:
            cell.setdefault("metadata", {})["tags"] = id_to_tags[cell_id]
            changed = True

    if changed:
        nbformat.write(executed_nb, executed_path)


def render_markdown(ipynb_path, outdir, slug):
    c = Config()
    c.TagRemovePreprocessor.remove_input_tags = {"hide-input"}
    exporter = MarkdownExporter(config=c)
    exporter.register_preprocessor(TagRemovePreprocessor, enabled=True)
    body, resources = exporter.from_filename(ipynb_path)
    writer = FilesWriter(build_directory=str(outdir))
    writer.write(body, resources, notebook_name=slug)


# --------------------------------------------------------------------------- #
# Per-module driver
# --------------------------------------------------------------------------- #

def build_module(
    *, module_name, rpm_paths, template_path, policy_path,
    fc_resolver, entrypoint_types, outdir, kernel_name,
):
    policy_modules, executables = classify_rpm_contents(rpm_paths)

    for ep in executables:
        se_type = fc_resolver.match(ep["path"], stat.S_IFREG)
        ep["entrypoint_type"] = se_type
        ep["is_entrypoint"] = bool(se_type and se_type in entrypoint_types)

    slug = slugify(module_name)
    ipynb_out = os.path.join(outdir, slug + ".ipynb")

    parameters = {
        "module_name":    module_name,
        "policy_path":    os.path.abspath(policy_path),
        "rpms":           [os.path.abspath(p) for p in rpm_paths],
        "policy_modules": policy_modules,
        "executables":    executables,
    }

    try:
        execute_template(
            template_path=template_path,
            output_path=ipynb_out,
            parameters=parameters,
            kernel_name=kernel_name,
            cwd=outdir,
        )
    except Exception:
        # Keep the partially-executed notebook for inspection.
        failed = ipynb_out + ".failed"
        if os.path.exists(ipynb_out):
            os.replace(ipynb_out, failed)
        raise

    _restore_tags_from_template(template_path, ipynb_out)
    render_markdown(ipynb_out, outdir, slug)
    return ipynb_out, os.path.join(outdir, slug + ".md")


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def _parse_args(argv):
    ap = argparse.ArgumentParser(
        prog="python -m span.module_notebook_builder",
        description="Build per-module review notebooks from a CSV of RPMs.",
    )
    ap.add_argument("--csv", required=True, help="CSV file: module,rpm")
    ap.add_argument("--policy", required=True, help="SELinux binary policy")
    ap.add_argument("--file-contexts", required=True,
                    help="file_contexts file (text form)")
    ap.add_argument("--template", required=True, help="Papermill template .ipynb")
    ap.add_argument("--outdir", required=True, help="Output directory (created if absent)")
    ap.add_argument("--modules", default=None,
                    help="Comma-separated allowlist of module names")
    ap.add_argument("--kernel", default="python3",
                    help="Jupyter kernel name passed to papermill (default: python3)")
    ap.add_argument("--keep-going", action="store_true",
                    help="On per-module failure, log and continue with the next module")
    return ap.parse_args(argv)


def main(argv=None):
    args = _parse_args(argv)

    _ensure_rpm_available()

    if not os.path.exists(args.template):
        print("template not found: %s" % args.template, file=sys.stderr)
        return 2

    os.makedirs(args.outdir, exist_ok=True)

    groups = parse_csv(args.csv)
    if args.modules:
        wanted = {m.strip() for m in args.modules.split(",") if m.strip()}
        groups = OrderedDict(
            (m, rpms) for m, rpms in groups.items() if m in wanted
        )

    fc_resolver = build_fc_resolver(args.file_contexts)
    for lineno, raw, msg in getattr(fc_resolver, "errors", []):
        print("file_contexts line %d skipped (%s): %s"
              % (lineno, msg, raw), file=sys.stderr)

    entrypoint_types = load_entrypoint_types(args.policy)

    seen_slugs = {}
    failures = []
    for module_name, rpm_paths in groups.items():
        slug = slugify(module_name)
        if slug in seen_slugs and seen_slugs[slug] != module_name:
            msg = ("slug collision: %r and %r both slugify to %r"
                   % (seen_slugs[slug], module_name, slug))
            if args.keep_going:
                print(msg, file=sys.stderr)
                failures.append(module_name)
                continue
            print(msg, file=sys.stderr)
            return 1
        seen_slugs[slug] = module_name

        missing = [p for p in rpm_paths if not os.path.exists(p)]
        if missing:
            msg = "module %r references missing RPMs: %s" % (module_name, missing)
            if args.keep_going:
                print(msg, file=sys.stderr)
                failures.append(module_name)
                continue
            print(msg, file=sys.stderr)
            return 1

        try:
            ipynb, md = build_module(
                module_name=module_name,
                rpm_paths=rpm_paths,
                template_path=args.template,
                policy_path=args.policy,
                fc_resolver=fc_resolver,
                entrypoint_types=entrypoint_types,
                outdir=args.outdir,
                kernel_name=args.kernel,
            )
            print("built %s -> %s, %s" % (module_name, ipynb, md))
        except Exception as e:
            failures.append(module_name)
            if args.keep_going:
                print("module %r failed: %s" % (module_name, e), file=sys.stderr)
                continue
            raise

    if failures and not args.keep_going:
        return 1
    if failures:
        print("completed with %d failed module(s): %s"
              % (len(failures), ", ".join(failures)), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
