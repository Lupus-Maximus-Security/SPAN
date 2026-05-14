%global pyproject_name span
%global venv_dir     /opt/%{pyproject_name}/venv

# Skip auto-generated Python provides/requires for the bundled venv —
# its files are an implementation detail of this RPM, not interfaces.
%global __provides_exclude_from ^%{venv_dir}/.*$
%global __requires_exclude_from ^%{venv_dir}/.*$

# Disable byte-compilation of the bundled venv. pip already compiled
# everything inside the venv against the venv's own interpreter.
%global __brp_python_bytecompile %{nil}

# Don't mangle shebangs inside the venv — we want them pointing at the
# venv's Python, not /usr/bin/python3.
%global __brp_mangle_shebangs %{nil}

# Bundled wheels (numpy, pandas, etc.) ship prebuilt .so files without
# the build-ID notes RPM's debuginfo pipeline expects, and eu-strip
# rejects some of them outright. Skip stripping and debug extraction.
%global debug_package %{nil}
%global __brp_strip %{nil}
%global __brp_strip_comment_note %{nil}
%global __brp_strip_static_archive %{nil}
%global __brp_check_rpaths %{nil}
%global _build_id_links none

Name:           %{pyproject_name}
Version:        1.1.0
Release:        1%{?dist}
Summary:        Utilities for SELinux policy analysis in Jupyter Notebook

License:        BSD-3-Clause
URL:            https://github.com/lupusmaximus/SPAN
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  python3
BuildRequires:  python3-devel
BuildRequires:  python3-pip
BuildRequires:  /usr/bin/find
BuildRequires:  /usr/bin/sed

# setools provides the Python bindings the venv picks up via
# --system-site-packages. pandoc and rpm are runtime CLIs used by
# the module notebook builder.
Requires:       python3
Requires:       setools
Requires:       pandoc
Requires:       rpm

%description
SPAN (SELinux Policy Analysis Notebook) is a library designed to make using
SETools 4 simple in a Jupyter notebook.

This package installs SPAN as a self-contained Python virtual environment
under %{venv_dir}, with the setools Python bindings shared from the system
site-packages. Two commands are installed in %{_bindir}: span-notebook
launches Jupyter Notebook inside the venv, and span-module-notebooks runs
the bundled module-notebook builder.

%prep
%autosetup -n %{name}-%{version}

%build
# Nothing to build at this stage; the venv is assembled in %%install.

%install
install -d %{buildroot}/opt/%{pyproject_name}
install -d %{buildroot}%{_bindir}
install -d %{buildroot}%{_datadir}/%{pyproject_name}

# Build the venv at its final on-disk path inside the buildroot so the
# generated console scripts and pyvenv.cfg point at /opt/span/venv/... .
# Anything that ends up referring to %{buildroot} we strip at the end.
python3 -m venv --system-site-packages %{buildroot}%{venv_dir}

PIP="%{buildroot}%{venv_dir}/bin/pip"

# Upgrade pip + install build tooling, then install SPAN with its deps.
# Pulls wheels from PyPI; this requires network access during the build.
"$PIP" install --upgrade pip wheel
"$PIP" install .

# Strip buildroot prefix from every text artifact the venv generated.
VDIR="%{buildroot}%{venv_dir}"
find "$VDIR/bin" -type f -print0 \
    | xargs -0 grep -lI "%{buildroot}" 2>/dev/null \
    | xargs -r sed -i "s|%{buildroot}||g"
sed -i "s|%{buildroot}||g" "$VDIR/pyvenv.cfg"
find "$VDIR" -name "RECORD" -print0 \
    | xargs -0 -r sed -i "s|%{buildroot}||g"
find "$VDIR" -name "direct_url.json" -print0 \
    | xargs -0 -r sed -i "s|%{buildroot}||g"

# Drop bytecode — paths are baked into .pyc files and would be wrong.
# The venv recompiles on first run if needed.
find "$VDIR" -type d -name __pycache__ -exec rm -rf {} +
find "$VDIR" -name '*.pyc' -delete

# /usr/bin wrappers that exec the venv's console scripts.
cat > %{buildroot}%{_bindir}/span-notebook <<EOF
#!/bin/sh
exec %{venv_dir}/bin/jupyter notebook "\$@"
EOF
chmod 0755 %{buildroot}%{_bindir}/span-notebook

cat > %{buildroot}%{_bindir}/span-module-notebooks <<EOF
#!/bin/sh
exec %{venv_dir}/bin/span-module-notebooks "\$@"
EOF
chmod 0755 %{buildroot}%{_bindir}/span-module-notebooks

# Examples ship to /usr/share/span/examples so users can copy and run.
cp -a examples %{buildroot}%{_datadir}/%{pyproject_name}/
[ -d specs ] && cp -a specs %{buildroot}%{_datadir}/%{pyproject_name}/ || :

%files
%license COPYING
%doc README.md
/opt/%{pyproject_name}
%{_bindir}/span-notebook
%{_bindir}/span-module-notebooks
%{_datadir}/%{pyproject_name}

%changelog
* Thu May 14 2026 Karl MacMillan <karl@lupusmaximus.com> - 1.1.0-1
- Update to 1.1.0.

* Wed May 13 2026 Karl MacMillan <karl@lupusmaximus.com> - 1.0.0-1
- Initial RPM packaging with bundled venv under /opt/span.
