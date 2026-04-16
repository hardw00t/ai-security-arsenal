# Python (pip / poetry / pdm / uv) Reference

## Manifest + lockfile files

| File | Purpose |
|------|---------|
| `requirements.txt` | pip (unpinned or pinned; no hash = weak lockfile) |
| `requirements.txt` with `--hash=sha256:...` | pip-tools hashed (strong lockfile) |
| `Pipfile` + `Pipfile.lock` | pipenv |
| `pyproject.toml` + `poetry.lock` | poetry |
| `pyproject.toml` + `pdm.lock` | PDM |
| `pyproject.toml` + `uv.lock` | uv (Astral) |
| `setup.py` / `setup.cfg` | legacy manifest |

## SBOM generation

```bash
# CycloneDX — from the live environment (best fidelity)
pip install cyclonedx-bom
cyclonedx-py environment -o sbom.cdx.json

# From requirements.txt
cyclonedx-py requirements requirements.txt -o sbom.cdx.json

# From poetry
cyclonedx-py poetry -o sbom.cdx.json

# Syft multi-eco
syft dir:. -o cyclonedx-json=sbom.cdx.json
```

## Vulnerability scanning

```bash
# pip-audit (PyPA official)
pip-audit                              # live env
pip-audit -r requirements.txt
pip-audit --fix                        # auto-upgrade
pip-audit -f json -o audit.json
pip-audit --require-hashes             # refuse unhashed deps

# Safety (PyUp)
safety check --json
safety scan --output=json              # newer safety CLI

# OSV-Scanner
osv-scanner --lockfile=requirements.txt
osv-scanner --lockfile=poetry.lock
osv-scanner --lockfile=Pipfile.lock
osv-scanner --lockfile=uv.lock

# Snyk
snyk test --file=requirements.txt
snyk test --file=poetry.lock --package-manager=poetry
```

## Dependency tree inspection

```bash
# Live env
pipdeptree
pipdeptree --packages <pkg> --reverse  # why is this installed?

# poetry
poetry show --tree
poetry show <pkg>  # version + deps
poetry show --outdated

# pdm / uv
pdm list --tree
uv tree
```

## Hash-locked installs (strong supply chain posture)

```bash
# Generate hashed requirements from requirements.in
pip install pip-tools
pip-compile --generate-hashes requirements.in

# Refuse to install unhashed
pip install --require-hashes -r requirements.txt
```

## License extraction

```bash
pip install pip-licenses
pip-licenses --format=json --with-license-file --with-urls > licenses.json
pip-licenses --fail-on "GPL;AGPL"
pip-licenses --allow-only "MIT;Apache-2.0;BSD"
```

## Python-specific supply chain hazards

- **setup.py code execution**: installing an sdist runs `setup.py`. Any package source can run arbitrary code at install. Mitigate with `--only-binary=:all:` where possible.
- **Wheel vs sdist**: prefer wheels; inspect sdist `setup.py` before install.
- **Namespace packages**: `foo-core` and `foo-plugin` may share a namespace — check each.
- **Dependency confusion**: pip by default will pick the highest version across all configured indexes. Pin with `--index-url` + `--no-index` for internal packages, or use `pip install --index-url https://internal/ --extra-index-url https://pypi.org/simple/` with caution.

```bash
# Harden: prefer binary, refuse setup.py execution for untrusted
pip install --only-binary=:all: <pkg>

# Inspect an sdist before installing
pip download --no-deps --no-binary=:all: <pkg>
tar xzf *.tar.gz && cat */setup.py
```

## Attestations / PEP 740 (2025+)

```bash
# PEP 740 provenance is rolling out on PyPI during 2025-2026
pip install --require-hashes -r requirements.txt
# Inspection:
curl -s https://pypi.org/pypi/<pkg>/<ver>/json | jq '.urls[] | {filename, digests, "attestations": .provenance}'
```

## Common vulnerability patterns

| Class | Example | Detection |
|-------|---------|-----------|
| Deserialization (pickle/joblib) | CVE-2022-21797 | pip-audit, OSV |
| Path traversal | CVE-2007-4559 (tarfile) | Safety |
| RCE via YAML | PyYAML < 5.1 non-safe_load | OSV |
| Dependency confusion (internal pkg) | 2021 PayPal PoC | manual + socket.dev |

## Gotchas

- `pip freeze` != lockfile — it's a snapshot, no hashes, not reproducible. Use pip-tools / poetry / pdm / uv for real lockfiles.
- `requirements.txt` without pins means the scan sees whatever is latest, not what was installed. Always scan the **live venv** or a hashed lockfile.
- C-extension packages (numpy, cryptography, lxml) have OS-level CVEs via bundled libs (libxml2, OpenSSL). Trivy/Grype catch these; pip-audit alone does not.

## Tool minimums (2026-04)

- pip >= 24.0
- pip-audit >= 2.7
- poetry >= 1.8
- uv >= 0.4
- cyclonedx-py >= 5.0
