# License Audit Workflow

Enumerate licenses for every direct and transitive dependency, map to a policy, and flag violations. Run this in parallel with vuln correlation — they are independent.

## Step 1 — Extract licenses from SBOM

```bash
# CycloneDX SBOM — one row per component
jq -r '.components[] | [.name, .version, (.licenses // [] | map(.license.id // .license.name) | join("|"))] | @tsv' \
  sbom.cdx.json > licenses.tsv

# SPDX SBOM
jq -r '.packages[] | [.name, .versionInfo, .licenseConcluded, .licenseDeclared] | @tsv' \
  sbom.spdx.json > licenses-spdx.tsv
```

## Step 2 — Ecosystem-native fallback

When the SBOM says `NOASSERTION` or `unknown`, fall back to ecosystem tools:

```bash
# npm
npx license-checker --json > npm-licenses.json

# Python
pip-licenses --format=json --with-license-file --with-urls > py-licenses.json

# Java (Maven)
mvn license:aggregate-third-party-report

# Go
go-licenses report ./... --template report.tpl > go-licenses.csv

# Rust
cargo deny check licenses

# Ruby
license_finder report --format=json > rb-licenses.json

# PHP
composer licenses --format=json > php-licenses.json
```

## Step 3 — Classify per policy

Map SPDX identifiers to risk buckets:

| Bucket | Examples | Typical policy |
|--------|----------|----------------|
| `permissive` | MIT, Apache-2.0, BSD-2/3-Clause, ISC, Unlicense, 0BSD | allow |
| `weak_copyleft` | LGPL-2.1, LGPL-3.0, MPL-2.0, EPL-2.0, CDDL-1.0 | allow w/ dynamic linking |
| `strong_copyleft` | GPL-2.0, GPL-3.0, AGPL-3.0 | deny unless exception |
| `commercial` | BUSL-1.1, Elastic-2.0, SSPL-1.0 | review |
| `unknown` | NOASSERTION, custom, dual-license expressions | manual triage |

## Step 4 — Enforce policy

Sample `.licensepolicy.yaml`:

```yaml
allowed: [MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC, MPL-2.0]
denied:  [GPL-2.0, GPL-3.0, AGPL-3.0, SSPL-1.0, BUSL-1.1]
review:  [LGPL-2.1, LGPL-3.0, EPL-2.0, CDDL-1.0]
exceptions:
  - package: some-lgpl-pkg
    license: LGPL-3.0
    reason: "dynamically linked, not redistributed"
    expires: 2026-12-31
```

Enforcement tools:

```bash
# npm
npx license-checker --onlyAllow 'MIT;Apache-2.0;BSD-2-Clause;BSD-3-Clause;ISC'

# Rust
cargo deny check licenses  # reads deny.toml

# Go
go-licenses check ./... --disallowed_types=forbidden,restricted
```

## Step 5 — Emit findings

For every violation or unknown, emit a finding with `finding_type: "license"`, `license`, `license_risk`, `remediation` (e.g. "replace with permissive alt / obtain commercial license / remove").

## SPDX expression gotchas

- `(MIT OR Apache-2.0)` — user's choice; use the more permissive for policy check.
- `(GPL-2.0 AND MIT)` — combined; must satisfy the stricter.
- `GPL-2.0-only` vs `GPL-2.0-or-later` — different obligations. Never silently upgrade.
- Dual-licensed packages may have file-level license headers that override package-level declarations — sample file licenses when the declared license seems anomalous.

## Parallelism / reasoning

- Per-ecosystem license extraction: parallel.
- Policy evaluation: trivial, no reasoning budget.
- Dual-license expression resolution: medium reasoning when ambiguous.
