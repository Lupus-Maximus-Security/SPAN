
# Introduction

SPAN (SELinux Policy Analysis Notebook) is a small library designed to make using SETools 4 simple in a Jupyter notebook.

Using SETools within Jupyter notebook is an amazingly productive way to do policy analysis. It becomes simple to keep
notes alongside any queries you do or, almost more importantly, write simple scripts that allow you to do more powerful
policy analysis.

![SPAN Screenshot](/images/screenshot.png?raw=true "SPAN Screenshot")

Jupyter notebooks are an interactive environment that lets you write text (in Markdown) and code together. What's
powerful is that the code is executable within the document itself. That let's you
write queries and text together at the same time. You can get a feel for what's possible in this awesome notebook on
[Regex Golf from XKCD](http://nbviewer.jupyter.org/url/norvig.com/ipython/xkcd1313.ipynb). There is also the more
official (and boring) [introduction](https://jupyter-notebook-beginner-guide.readthedocs.io/en/latest/).

# Installation

SPAN is typically tested on newer Fedora versions and on RHEL 9 and rebuilds such as Rocky Linux.

SPAN is pure Python and supports Python 3 only.

## SETools Requirement

SPAN requires setools 4 along with the Python bindings. The easiest way to handle this is to install setools from the RPMs and then bring those into a virtual environment. You can do this as follows:

```
$ sudo dnf install setools
$ python -m venv --system-site-packages venv
$ source venv/bin/activate
```

## Installing SPAN

Install SPAN and all its dependencies from the project root:

```
$ pip install .
```

For development, install in editable mode so changes to `span/` take effect
immediately without reinstalling:

```
$ pip install -e .
```

All dependencies are declared in `pyproject.toml`. If you need a pinned lock
file for reproducible dev environments, generate one after installing:

```
$ pip freeze > requirements.txt
```

## MacOS Support

Also note, that this all installs and works on MacOS as well. You will have to install libsepol and SETools from
source, but if you have a working development environment that is not difficult. Just make certain that you
use master from SELinux userspace (https://github.com/SELinuxProject/selinux) and SETools.

1. You must install coreutils and pandoc. We recommend using Home Brew (https://github.com/Homebrew/brew) to install these.
1. You must install userspace SELinux using specific parameters to make so the library ends up in the correct place.

```
brew install coreutils pandoc
# cd you your SELinux checkout
cd libsepol
sudo make DESTDIR=/usr/local PREFIX=/usr/local install
```

After this, you should install setools 4. Then follow the instructions described above in the Installation section.

# Getting Started

Go to examples and start Jupyter notebook: e.g., jupyter-notebook. This will open a browser window listing the
 contents of the directory. From there you can explore the example notebooks (start with SPAN Example).

# Module Notebook Builder

`span.module_notebook_builder` is a CLI tool that turns a CSV of (module, RPM) rows into one executed Jupyter notebook
and one rendered Markdown file per module. It walks each module's RPMs, picks out the executables and policy modules
(`.pp` files), looks up each executable's SELinux entrypoint type from a file_contexts database, and hands the result
to a papermill template that you control.

## Usage

```
python -m span.module_notebook_builder \
    --csv modules.csv \
    --policy /path/to/policy.30 \
    --file-contexts /path/to/file_contexts \
    --template templates/module_review.ipynb \
    --outdir build/module_notebooks
```

Optional flags:

* `--modules httpd,mariadb` — only build the listed modules.
* `--kernel python3` — Jupyter kernel name passed to papermill (default `python3`).
* `--keep-going` — on per-module failure, log and continue with the next module.

## CSV format

Two columns: module name, RPM path. The module name may repeat to group RPMs under one logical module. Blank lines and
`#`-comments are skipped. A header row is auto-detected and dropped. RPM paths may be absolute or relative to the CSV.

```
module_name,rpm_path
httpd,/srv/rpms/httpd-2.4.59-1.x86_64.rpm
httpd,/srv/rpms/mod_ssl-2.4.59-1.x86_64.rpm
mariadb,/srv/rpms/mariadb-server-10.5.21-1.x86_64.rpm
```

## Template contract

The template must declare a parameters cell (tag `parameters`, papermill convention) with these names:

```python
module_name      = ""
policy_path      = ""
rpms             = []
policy_modules   = []
executables      = []   # each: {path, entrypoint_type, is_entrypoint, rpms, mode}
```

Each `executables` entry already includes `is_entrypoint`, set to True only when the resolved type appears as a
`file:entrypoint` target somewhere in the supplied policy. The template author decides what to render from there
(typically `span.load_policy(policy_path)` followed by `domain_summary` calls).

## Outputs

For each module, two files land in `--outdir`:

* `<slug>.ipynb` — the executed notebook.
* `<slug>.md` — the Markdown export of the executed notebook. An accompanying `<slug>_files/` directory appears only
  if the notebook embedded images.

`<slug>` is the module name with characters outside `[A-Za-z0-9_.-]` replaced by `_`.

## Requirements

The tool depends on `papermill` and `nbconvert` (both listed in `requirements.txt`). The `rpm` CLI must be on
PATH. File-contexts resolution prefers libselinux's Python binding (`import selinux`) when available; otherwise it
falls back to a pure-Python parser that approximates libselinux specificity ordering — accurate enough for review
work but consult libselinux on production-critical lookups.
