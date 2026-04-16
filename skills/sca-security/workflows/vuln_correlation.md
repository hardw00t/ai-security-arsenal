# Vulnerability Correlation Workflow

Correlate components (from SBOM or lockfile) against multiple vulnerability databases (OSV, GHSA, NVD, ecosystem-native) and deduplicate. No single database has full coverage — always query at least two.

## Why correlate?

- NVD misses ecosystem-specific advisories (e.g. many GHSA entries never reach NVD).
- OSV aggregates GHSA + PyPA + RustSec + Go Vuln DB but lags NVD by hours.
- Ecosystem-native (`npm audit`, `pip-audit`) often has the fastest signal for its ecosystem.

Rule: run Grype **and** OSV-Scanner **and** the ecosystem-native tool. Merge on `(ecosystem, package, version, cve|ghsa)`.

## Step 1 — Scan with Grype (SBOM-driven)

```bash
grype sbom:sbom.cdx.json -o json > grype.json

# Fail threshold in CI
grype sbom:sbom.cdx.json --fail-on high --only-fixed
```

Grype DB sources: GHSA, NVD, Ubuntu/Debian/RHEL for OS packages.

## Step 2 — Scan with OSV-Scanner (canonical multi-eco)

```bash
osv-scanner --sbom=sbom.cdx.json --format=json > osv.json

# Directly against lockfiles (no SBOM required)
osv-scanner --lockfile=package-lock.json --lockfile=poetry.lock \
  --format=json > osv-locks.json

# Experimental call analysis for Go (used by reachability_analysis.md)
osv-scanner --experimental-call-analysis ./...
```

OSV DB sources: GHSA, PyPA, RustSec, Go Vuln DB, Android, OSS-Fuzz, GSD.

## Step 3 — Ecosystem-native (parallel)

Run in parallel with steps 1+2 — they are independent:

```bash
npm audit --json > npm-audit.json &
pip-audit -f json -o pip-audit.json &
cargo audit --json > cargo-audit.json &
govulncheck -json ./... > govuln.json &
bundle-audit check --format json --output ruby-audit.json &
composer audit --format=json > composer-audit.json &
wait
```

## Step 4 — Merge + dedupe

Join key: prefer `ghsa` > `cve` > `osv_id` > `(package, version, summary)`.

```bash
# Quick jq merge sketch
jq -s '
  [.[0].matches[] | {tool:"grype", pkg:.artifact.name, ver:.artifact.version, cve:.vulnerability.id}]
  + [.[1].results[].packages[].vulnerabilities[] | {tool:"osv", pkg:..., cve:.id}]
  | group_by(.cve + .pkg + .ver)
  | map({cve:.[0].cve, pkg:.[0].pkg, ver:.[0].ver, tools:[.[].tool]})
' grype.json osv.json > merged.json
```

## Step 5 — Enrich with exploitability signals

Per CVE, query:
- CISA KEV: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
- EPSS: `https://api.first.org/data/v1/epss?cve=CVE-...`
- GHSA: includes `references.advisory` and `patched_versions`

Flag any finding with `kev=true` or `epss>=0.5` as critical-by-exploitability regardless of CVSS.

## Step 6 — Emit findings

Populate `schemas/finding.json` with `cve`, `ghsa`, `osv_id`, `cvss`, `epss_score`, `kev`, `installed_version`, `fixed_version`, `vulnerable_range`, `is_transitive`, `dependency_path`, `evidence.scanner`.

Set `is_reachable: "unknown"` by default; run `reachability_analysis.md` for true exploitability triage.

## Parallelism

- Grype, OSV-Scanner, ecosystem-native tools: fully parallel.
- KEV + EPSS enrichment: parallel per CVE (batch the EPSS API).
- Sequential: merge must wait for all scanners.

## Reasoning budget

Low — this is a mechanical orchestration workflow. Escalate to extended thinking only when two scanners disagree on whether a version is affected (often a range-expression bug in one DB).

## Minimum tool versions (2026-04)

- grype >= 0.87
- osv-scanner >= 2.1
- trivy >= 0.58
