# Vulnerability Database Reference

No single database has full coverage. Use multiple. This reference maps databases to ecosystems and highlights known gaps.

## Primary databases

| DB | URL | API | Ecosystem coverage | Latency | Notes |
|----|-----|-----|--------------------|---------|-------|
| NVD | nvd.nist.gov | REST + JSON feeds | CVE universe (hardware+software+OS) | slow (weeks) | Requires API key for sustained use |
| GHSA | github.com/advisories | GraphQL + REST | npm, PyPI, Maven, NuGet, RubyGems, Composer, Go, Rust, Swift, Actions | fast (hours) | First-party for many ecosystems |
| OSV | osv.dev | REST batch | Aggregator — see below | fast | JSON Schema: osv.dev/schema |
| Snyk DB | snyk.io | REST (license gated) | all major + some unique | fastest | Commercial; proprietary IDs |
| OSS Index | ossindex.sonatype.org | REST | Maven, npm, PyPI, etc. | medium | Free with limits |
| CISA KEV | cisa.gov/known-exploited-vulnerabilities | JSON feed | known-exploited only | daily | Binary signal for priority |
| EPSS | first.org/epss | REST | all CVEs | daily | Exploit probability (0-1) |

## OSV aggregation sources

OSV is a meta-database aggregating:
- GHSA (GitHub Advisory)
- PyPA Advisory DB (Python)
- RustSec Advisory DB (Rust)
- Go Vulnerability DB (vuln.go.dev)
- Android Security Bulletin
- OSS-Fuzz
- GSD (Global Security Database)
- Maven ecosystem (via GHSA)
- Packagist (via FriendsOfPHP + GHSA)
- UVI (unreviewed universal)

Query: `https://api.osv.dev/v1/query` with `{"package":{"name":"lodash","ecosystem":"npm"},"version":"4.17.20"}`.

## Ecosystem-specific advisory DBs

| Ecosystem | Canonical DB | Feed |
|-----------|--------------|------|
| npm | GHSA | npm audit uses this + npm registry overlay |
| PyPI | PyPA Advisory DB | github.com/pypa/advisory-database |
| Rust | RustSec | github.com/rustsec/advisory-db |
| Go | Go Vuln DB | vuln.go.dev, github.com/golang/vulndb |
| Ruby | rubysec | github.com/rubysec/ruby-advisory-db |
| PHP | FriendsOfPHP | github.com/FriendsOfPHP/security-advisories |
| Maven | GHSA | often delayed vs upstream project disclosure |
| NuGet | GHSA | |
| Cargo | RustSec | |
| Conda | OSV (PyPI overlap) | partial |

## CVE identifier ecosystem

- **CVE**: MITRE-assigned, canonical ID (`CVE-2024-XXXXX`).
- **GHSA**: GitHub-assigned (`GHSA-xxxx-xxxx-xxxx`) — often issued before CVE.
- **OSV ID**: ecosystem-prefixed (`GO-2024-1234`, `PYSEC-2024-123`, `RUSTSEC-2024-0001`, `GHSA-...`).
- **Snyk ID**: `SNYK-JS-LODASH-567746` — internal only but widely referenced in output.
- **Vendor-specific**: `DSA-xxxx-1` (Debian), `USN-xxxx-1` (Ubuntu), `RHSA-xxxx` (Red Hat).

Always reconcile to CVE + GHSA as joint primary keys.

## Known gaps (2026-04)

- NVD enrichment backlog persists from 2024 disruption — many 2024+ CVEs lack CPE or CVSS. Do not rely on NVD alone for recent vulns.
- GHSA can lag upstream project disclosure by 1-7 days for non-high-profile packages.
- OSV's PyPA coverage is complete for PyPA-tracked advisories but misses PyPI-only advisories (rare).
- Commercial Snyk DB often has exclusive entries not in GHSA/OSV (disclosed privately to Snyk).
- Go Vuln DB only accepts vulns with reviewed symbol-level data — high quality but incomplete breadth.

## Priority signals

| Signal | Source | Weight |
|--------|--------|--------|
| CISA KEV entry | kev.json | **critical** — actively exploited |
| EPSS >= 0.5 | first.org | high — likely to be exploited |
| CVSS-B >= 9.0 | NVD / GHSA | high (but often inflated) |
| Public PoC | GHSA refs, exploit-db.com | high |
| Worm-capable / pre-auth RCE | manual | critical |
| Local-only, privileged | manual | medium |
| Denial-of-service only | manual | low (unless availability-critical) |

## Recommended query order per vuln

1. OSV (fastest, aggregated, batchable)
2. GHSA (richer metadata, better range expressions)
3. Ecosystem-native (`npm audit`, `pip-audit`, etc.) — for ecosystem-only advisories
4. CISA KEV + EPSS for exploitability overlay
5. NVD only when you need CPE or full CVSS vector not present elsewhere
