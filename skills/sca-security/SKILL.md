---
name: sca-security
description: "Software Composition Analysis: find vulnerable dependencies, correlate CVE/GHSA/OSV across ecosystems, generate CycloneDX/SPDX SBOMs, assess license compliance, and run reachability-aware triage to suppress unexploitable findings. Use when scanning package dependencies (npm, PyPI, Maven, Cargo, Go, RubyGems, Composer), reviewing PR lockfile diffs, generating SBOMs, auditing licenses, hunting malicious packages, or auditing the software supply chain. Triggers on requests to scan dependencies, check vulnerable packages, generate SBOM, license compliance, typosquat/dependency-confusion review, or reachability-based vuln triage."
---

# Software Composition Analysis (SCA)

Router skill for dependency security: SBOM generation, multi-source vuln correlation, license compliance, supply chain review, and reachability-driven triage. Optimized for polyglot repositories and PR-time lockfile review. Load the relevant workflow + ecosystem reference on demand — do not read the whole skill up front.

## When to Use

- Scanning project dependencies for known vulnerabilities (CVE / GHSA / OSV)
- Generating an SBOM (CycloneDX or SPDX) for a repo, container, or binary
- Reviewing a PR's lockfile delta for new vulns, license changes, malicious packages
- Reachability analysis to prioritize the 5-15% of findings that are actually exploitable
- License compliance against an allow/deny policy
- Supply chain review: typosquatting, dependency confusion, malicious package triage
- Ecosystem-specific audits: npm, yarn, pnpm, pip, poetry, Maven, Gradle, Go, Cargo, Ruby, Composer
- CI/CD integration for continuous dependency scanning

## Trigger Phrases

- "scan dependencies", "check package vulnerabilities", "run npm audit"
- "generate SBOM", "CycloneDX", "SPDX"
- "license compliance", "audit licenses"
- "supply chain", "typosquat", "dependency confusion", "malicious package"
- "lockfile diff", "dep review", "PR dependency review"
- "is this CVE reachable", "reachability analysis", "filter false positives"

## When NOT to Use This Skill

- **First-party source code vulnerabilities (SQLi, XSS, SSRF, etc.)** → use `sast-orchestration`. SCA looks at third-party deps only.
- **OS-level packages inside container images (apt, apk, rpm)** → use `container-security`. (Overlap: Syft/Grype handle both; choose based on where the bulk of the work is.)
- **Infrastructure-as-Code misconfigurations (Terraform, K8s YAML)** → use `iac-security`.
- **Live web-app runtime testing** → use `dast-automation`.
- **LLM-specific supply chain (model weights, prompts, tool chains)** → use `llm-security`.
- **Mobile app third-party libraries** → this skill works, but `android-pentest` / `ios-pentest` add platform context (cocoapods, SPM, gradle android).

## Decision Tree

```
Start
 ├── Have a PR that touches a lockfile / manifest?
 │    → workflows/lockfile_diff.md
 │
 ├── Need a baseline for a repo or container?
 │    → workflows/sbom_generation.md  → workflows/vuln_correlation.md (parallel: license_audit.md)
 │
 ├── Got 100+ vuln findings and need to prioritize?
 │    → workflows/reachability_analysis.md  (HIGH-VALUE, use extended thinking)
 │
 ├── New or unfamiliar package just showed up in a dep graph?
 │    → workflows/supply_chain_review.md + references/malicious_package_indicators.md
 │
 ├── License audit only?
 │    → workflows/license_audit.md
 │
 └── Ecosystem-specific question?
      → references/{npm_yarn_pnpm,python_pip_poetry,maven_gradle,go_modules,cargo,ruby_gems,php_composer}.md
```

## Parallelism Hints

Run concurrently (independent):
- SBOM generation is independent of vuln scanning — start SBOM, then fan out to Grype + OSV-Scanner + ecosystem-native tools while license + supply chain checks also run.
- Per-ecosystem scans in polyglot repos are fully parallel (npm audit, pip-audit, cargo audit, etc.).
- License audit and vuln correlation are independent — run concurrently.
- OSV batch API: batch all package versions in one HTTP call; do not loop.
- Registry metadata lookups for supply chain triage: parallel, one per package.

Must be sequential:
- Vuln correlation after SBOM (scanner reads the SBOM).
- Reachability analysis after vuln correlation (it refines findings).
- Call-graph construction before reachability queries.
- Lockfile diff classification before per-delta scans.

## Sub-Agent Delegation

- **Polyglot monorepos**: one sub-agent per ecosystem. Each runs the matching reference + native scanner + adds to a shared finding set.
- **PR review**: one sub-agent per changed lockfile. Each applies `workflows/lockfile_diff.md` and reports deltas, then a root agent consolidates.
- **Large finding queue**: shard by ecosystem or by package-prefix for reachability analysis; each sub-agent handles ~50 findings with the same call graph.
- **Supply chain triage at scale**: one sub-agent per batch of ~10 new packages for metadata + tarball inspection.

## Reasoning Budget

| Task | Budget |
|------|--------|
| SBOM generation | minimal — mechanical orchestration |
| Vuln correlation / dedup | minimal — unless scanners disagree on version ranges |
| License classification | low — policy lookup |
| Lockfile diff classification | medium — distinguish regression vs pre-existing |
| **Reachability analysis** | **extended thinking** — combines call graph + vuln metadata + taint + framework semantics |
| **Malicious package triage** | **extended thinking** — weighing many weak signals; high cost of FP/FN |
| Integrity hash mismatch (no version change) | extended thinking — possible registry compromise |
| License expression parsing (dual-license, SPDX exprs) | medium |

## Multimodal Hooks

- Dependency graph visualizations: `syft dir:. -o cyclonedx-json | cyclonedx-cli graph` produces a graph you can screenshot into a PR comment for humans.
- `cargo tree -d`, `npm ls --all`, `mvn dependency:tree -Dverbose` are better consumed as text — do not screenshot.
- For reachability results, CodeQL's query result JSON is preferred over SARIF HTML render.

## Structured Output

All findings MUST conform to `schemas/finding.json`. Key fields:
- `ecosystem`, `package_name`, `installed_version`
- `vulnerable_range`, `fixed_version`
- `cve`, `ghsa`, `osv_id`
- `is_transitive`, `dependency_path[]`
- `is_reachable` (`reachable` / `unreachable` / `unknown`), `reachability_evidence`
- `exploitability_notes`
- `license`, `license_risk`
- `malicious_indicators[]`, `finding_type`
- `epss_score`, `kev`

Priority rule (applies after correlation + reachability):

| Reachable | KEV | EPSS | CVSS | Priority | SLA |
|-----------|-----|------|------|----------|-----|
| yes | yes | any | any | P0 | 24h |
| yes | no | >=0.5 | any | P1 | 7d |
| yes | no | any | >=7 | P1 | 7d |
| yes | no | <0.5 | <7 | P2 | 30d |
| unknown | yes | any | any | P1 | investigate first |
| unknown | no | any | >=9 | P2 | investigate first |
| no (unreachable) | any | any | any | P3 | next dep-upgrade cycle |

## CI/CD Integration

Run at three gates:
- **Pre-commit** — lightweight ecosystem-native (`npm audit --audit-level=high`, `pip-audit`). Fast local feedback.
- **PR** — `workflows/lockfile_diff.md` as a required check. Block on new high/critical vulns; comment on license / supply-chain flags.
- **Main / nightly** — full `workflows/sbom_generation.md` → `vuln_correlation.md` → `reachability_analysis.md`. Publish SBOM as build artifact. Update Dependency-Track / CycloneDX server.

Use `--exit-code 1` on the relevant scanner with `--severity HIGH,CRITICAL` (Trivy) or `--fail-on high --only-fixed` (Grype) to gate builds. Keep suppressions in tool-native config (`.trivyignore`, `.snyk`, `deny.toml`, `suppressions.xml`) with `reason` + `expires` fields — never suppress silently.

## Remediation Strategy

Upgrade paths (see per-ecosystem reference for commands):
1. Patch-level bump if fix is in a patch release → low risk.
2. Minor bump if patch unavailable → test + ship.
3. Major bump or fork → extended thinking; coordinate with owning team.
4. Virtual patch / WAF rule if upgrade blocked → record in finding's `exploitability_notes` + set an expiry.
5. Accept risk → only for `is_reachable: "unreachable"` + `kev: false` + `epss < 0.2`; document + set review date.

## Workflow Index

| Workflow | Purpose |
|----------|---------|
| [sbom_generation.md](workflows/sbom_generation.md) | Syft + CycloneDX + SPDX generation + validation |
| [vuln_correlation.md](workflows/vuln_correlation.md) | Grype + OSV + ecosystem-native merge + KEV/EPSS enrichment |
| [license_audit.md](workflows/license_audit.md) | SBOM-driven license extraction + policy enforcement |
| [lockfile_diff.md](workflows/lockfile_diff.md) | PR-time delta review across lockfiles (frontier-model favored) |
| [reachability_analysis.md](workflows/reachability_analysis.md) | Call-graph-aware filtering — **key workflow** for triage |
| [supply_chain_review.md](workflows/supply_chain_review.md) | Typosquatting, dependency confusion, malicious-package detection |

## References Index

| Reference | Content |
|-----------|---------|
| [npm_yarn_pnpm.md](references/npm_yarn_pnpm.md) | Node.js ecosystem: manifests, scanners, install-script hardening |
| [python_pip_poetry.md](references/python_pip_poetry.md) | Python: pip/poetry/pdm/uv + hashed lockfiles + sdist risks |
| [maven_gradle.md](references/maven_gradle.md) | Java: Maven + Gradle + Log4Shell-class patterns |
| [go_modules.md](references/go_modules.md) | Go: govulncheck (built-in reachability), MVS, binary scanning |
| [cargo.md](references/cargo.md) | Rust: cargo-audit + cargo-deny + geiger |
| [ruby_gems.md](references/ruby_gems.md) | Ruby: bundler-audit + RubySec |
| [php_composer.md](references/php_composer.md) | PHP: composer audit + FriendsOfPHP |
| [sbom_formats.md](references/sbom_formats.md) | CycloneDX 1.6 vs SPDX 2.3 field-by-field |
| [vuln_databases.md](references/vuln_databases.md) | NVD, OSV, GHSA, ecosystem DBs — coverage + gaps |
| [malicious_package_indicators.md](references/malicious_package_indicators.md) | Signal catalog + triage matrix |

## Templates Index

| Template | Purpose |
|----------|---------|
| [sca_report.md](templates/sca_report.md) | Final report format |

## Tools

| Tool | Purpose | Install |
|------|---------|---------|
| syft | Multi-eco SBOM generator | `brew install syft` |
| grype | SBOM + dir vuln scanner | `brew install grype` |
| trivy | Multi-eco scanner (also containers/IaC) | `brew install trivy` |
| osv-scanner | OSV-backed multi-eco, call analysis | `go install github.com/google/osv-scanner/cmd/osv-scanner@latest` |
| govulncheck | Go official, reachability-aware | `go install golang.org/x/vuln/cmd/govulncheck@latest` |
| pip-audit | Python, PyPA official | `pipx install pip-audit` |
| cargo-audit | Rust, RustSec | `cargo install cargo-audit` |
| cargo-deny | Rust, unified advisories + licenses + sources | `cargo install cargo-deny` |
| cyclonedx-cli | SBOM convert / merge / validate | `brew install cyclonedx-cli` |
| snyk | Commercial, multi-eco | `npm install -g snyk` |
| socket | Supply chain risk scoring (npm/PyPI/Go/Rust) | `npm install -g @socketsecurity/cli` |
| OWASP Dependency-Check | Java-focused, NVD-backed | https://github.com/jeremylong/DependencyCheck |
| license-checker | npm license scan | `npm install -g license-checker` |
| pip-licenses | Python license scan | `pipx install pip-licenses` |
| go-licenses | Go license scan | `go install github.com/google/go-licenses@latest` |

## Last Validated

2026-04. Tool minimum versions per ecosystem are listed at the bottom of each `references/*.md`. Advisory DBs (OSV, GHSA) are rolling — re-check coverage notes in `references/vuln_databases.md` for NVD backlog status.
