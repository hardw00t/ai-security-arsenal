# SBOM Generation Workflow

Generate a Software Bill of Materials for a repository or container in CycloneDX and SPDX formats. SBOMs are the foundation for downstream vuln correlation, license audit, and supply chain review — generate once, reuse.

## Decision: which tool?

| Source | Preferred tool | Why |
|--------|---------------|-----|
| Repo (any ecosystem) | `syft` | Multi-ecosystem, one binary, both CDX + SPDX |
| Container image | `syft <image>` | Extracts OS packages + app-layer deps |
| npm project only | `@cyclonedx/cyclonedx-npm` | Includes `scope=runtime/dev` distinction |
| Python virtualenv | `cyclonedx-py environment` | Reads the actual installed set, not spec |
| Maven multi-module | `cyclonedx-maven-plugin` | Honors Maven dependency resolution |
| Go | `cyclonedx-gomod mod` | Honors `go.mod` version selection |

## Step 1 — Generate SBOM (Syft, default)

```bash
# Directory scan, CycloneDX JSON
syft dir:. -o cyclonedx-json=sbom.cdx.json

# Same source, SPDX JSON (some tools prefer SPDX)
syft dir:. -o spdx-json=sbom.spdx.json

# Container image
syft registry:ghcr.io/org/app:v1.2.3 -o cyclonedx-json=image.cdx.json

# Include file metadata (checksums) — required for high-assurance SBOMs
syft dir:. --source-name myapp --source-version 1.2.3 \
  -o cyclonedx-json=sbom.cdx.json --file-metadata
```

Parallelism: if repo is polyglot, Syft already walks all ecosystems; one invocation is enough. For per-ecosystem "native" SBOMs (e.g. cyclonedx-npm + cyclonedx-maven), run them in parallel.

## Step 2 — Validate

```bash
# CycloneDX CLI validation
cyclonedx validate --input-file sbom.cdx.json

# SPDX tools validation
pyspdxtools --input-file sbom.spdx.json
```

Reject any SBOM missing: `serialNumber` (CDX) / `documentNamespace` (SPDX), component `purl`, `version`.

## Step 3 — Enrich

```bash
# Add VEX (Vulnerability Exploitability eXchange) stub
cyclonedx-cli merge --input-files sbom.cdx.json vex.cdx.json \
  --output-file sbom-with-vex.cdx.json
```

## Step 4 — Hand off

- Vuln correlation: `grype sbom:sbom.cdx.json` or `trivy sbom sbom.cdx.json` (see `vuln_correlation.md`)
- License audit: jq over `sbom.cdx.json` (see `license_audit.md`)
- Supply chain review: see `supply_chain_review.md`

## Structured output

For each component emit to `schemas/finding.json` only when a risk is found. The SBOM itself is stored as an artifact; the finding schema captures vulns/license issues derived from it.

## Common failure modes

- `syft` missing a dep because lockfile was not committed — fail closed; require lockfiles.
- CDX vs SPDX purl drift — always prefer CDX's `purl` field for tool interop.
- Python SBOMs missing system-installed packages when scanning source dir; use `cyclonedx-py environment` inside the actual runtime venv.

## Minimum tool versions (2026-04)

- syft >= 1.14
- cyclonedx-cli >= 0.27
- cyclonedx-maven-plugin >= 2.8
