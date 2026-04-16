# Software Composition Analysis Report

## Executive Summary

- Project: <name>
- Commit / tag scanned: <sha> / <tag>
- Scan date: YYYY-MM-DD
- SBOM format: CycloneDX 1.6 (attached)
- Total components: X (direct: Y, transitive: Z)
- Findings by severity: Critical (C) / High (H) / Medium (M) / Low (L)
- Findings by reachability: Reachable (R) / Unreachable (U) / Unknown (?)
- License: permissive (P) / copyleft-weak (W) / copyleft-strong (S) / denied (D) / unknown (?)

## Reachable + exploitable (P0)

| # | Pkg | Version | CVE | GHSA | CVSS | EPSS | KEV | Fixed | Reachable symbol | Reason |
|---|-----|---------|-----|------|------|------|-----|-------|------------------|--------|
| 1 | lodash | 4.17.20 | CVE-2021-23337 | GHSA-35jh-r3h4-6jhm | 7.2 | 0.62 | no | 4.17.21 | template() at src/email/renderer.ts:42 | user-controlled subject |

## Reachable (P1/P2)

| # | Pkg | Version | CVE | Severity | Fixed | Call sites |
|---|-----|---------|-----|----------|-------|------------|

## Unreachable (P3 — backlog)

| # | Pkg | Version | CVE | Severity | Fixed | Notes |
|---|-----|---------|-----|----------|-------|-------|

## License violations

| # | Pkg | Version | License | Policy | Action |
|---|-----|---------|---------|--------|--------|

## Supply chain flags

| # | Pkg | Indicator | Confidence | Evidence |
|---|-----|-----------|------------|----------|

## SBOM

- CycloneDX: `sbom.cdx.json` (attached)
- SPDX: `sbom.spdx.json` (attached, optional)

## Remediation plan

| Priority | Action | Owner | Due |
|----------|--------|-------|-----|
| P0 | Upgrade lodash 4.17.20 → 4.17.21 | <team> | immediate |
| P1 | Replace GPL-licensed foo | <team> | 30d |
| P2 | Enforce `--ignore-scripts` in CI | <team> | 60d |

## Methodology

Tools used (with versions): syft 1.14, grype 0.87, osv-scanner 2.1, govulncheck 1.1, codeql <ver>, ...

SBOM generated per `workflows/sbom_generation.md`; vuln correlation per `workflows/vuln_correlation.md`; reachability per `workflows/reachability_analysis.md`.
