---
name: sast-orchestration
description: "Static Application Security Testing orchestration — run and compose Semgrep, CodeQL, Bandit, gosec, Brakeman, SpotBugs, ESLint; author custom rules; ingest SARIF; triage and rank findings by exploitability. Use this skill when asked to scan code for vulnerabilities, write Semgrep/CodeQL rules, triage SAST output, reduce false positives, or integrate SAST into CI/CD. Triggers on phrases like 'scan this code', 'write a Semgrep rule', 'triage these findings', 'SARIF', 'SAST in CI', or when a repo is handed over for a security review."
---

# SAST Orchestration

This skill runs multiple static-analysis tools against a codebase, authors custom detection rules, ingests SARIF, and performs high-signal triage. The headline capability is **triage**: converting raw, noisy SAST output into a ranked list of exploitable findings — where frontier reasoning models outperform traditional tools.

## When to Use

- Scan a codebase for security vulnerabilities (first-party or third-party).
- Write a custom Semgrep rule or CodeQL query from a CVE advisory, patch diff, or sink spec.
- Triage and rank a pile of SAST findings (SARIF or tool-native JSON) by exploitability.
- Reduce false-positive noise from existing scans.
- Integrate SAST into GitHub Actions / GitLab CI / Bitbucket Pipelines / Jenkins.
- Aggregate and deduplicate findings across multiple SAST tools.
- Decide which SAST tool(s) fit a given language/framework.

## Trigger Phrases

- "scan this code for vulnerabilities"
- "write a Semgrep rule to detect ..."
- "write a CodeQL query for ..."
- "triage these SAST findings" / "rank these by exploitability"
- "convert this CVE into a detection rule"
- "set up SAST in CI" / "add security scanning to our pipeline"
- "reduce false positives in this scan"
- "aggregate SARIF from multiple tools"

## When NOT to Use This Skill

- **Dependency/package CVEs** (SBOM, transitive vulns, license) → use `sca-security`.
- **Runtime/dynamic testing** (HTTP fuzzing, auth bypass, DAST) → use `dast-automation`.
- **Container image scanning** (OS packages, base image CVEs) → use `container-security`.
- **IaC misconfiguration** (Terraform, CloudFormation, Kubernetes YAML) → use `iac-security`.
- **Mobile app binary scanning** (APK, IPA) → use `android-pentest` / `ios-pentest`.
- **LLM/prompt-injection scanning** → use `llm-security`.
- **Threat modeling** (architecture-level risk analysis) → use `threat-modeling`.

SAST = source code static analysis. If the artifact is not source, check a sibling skill first.

## Decision Tree

```
Incoming request
│
├── "write a rule"         → workflows/custom_semgrep_from_cve.md  (from CVE/advisory)
│                            workflows/custom_codeql_from_sink.md  (from sink spec)
│
├── "triage these findings"→ workflows/triage.md                   [MAX THINKING]
│
├── "scan this codebase"   → workflows/multi_tool_scan.md          (parallel fan-out)
│                            then workflows/triage.md
│
├── "too much noise"       → workflows/false_positive_reduction.md
│
├── "SAST in CI"           → workflows/cicd_integration.md
│
└── "which tool for X?"    → references/<tool>.md (selection matrix below)
```

Tool-picking rules of thumb:

| Codebase characteristic | First choice | Second |
|-------------------------|-------------|--------|
| Polyglot / unfamiliar | Semgrep (auto) | CodeQL (security-extended per lang) |
| Python mono-repo | Semgrep + Bandit | CodeQL python-security-extended |
| Go services | gosec + Semgrep | CodeQL go-security-extended |
| Rails app | Brakeman | Semgrep `p/ruby` |
| Java / Spring | SpotBugs+FSB | CodeQL java-security-extended |
| JS/TS + Node | Semgrep `p/javascript p/nodejs` | ESLint security plugins |
| Need inter-procedural taint | CodeQL | Semgrep Pro |
| Fast PR gating | Semgrep `ci` mode | ESLint for JS |

## Parallelism Hints

**Independent (run concurrently):**
- Semgrep, Bandit, gosec, Brakeman, ESLint-security, Gitleaks — all source-only, read-only; fan out fully.
- CodeQL `database create` across distinct languages — independent.
- CodeQL `database analyze` across distinct language databases — independent.
- Per-tool sub-agents scanning the same codebase — each writes to a distinct SARIF path.

**Sequential (hard dependency):**
- CodeQL `database create` → `database analyze` for the same language.
- SpotBugs requires `mvn compile` / `gradle build` to have produced classes first.
- Aggregation and triage wait for all per-tool scans to complete — do NOT start triage with partial SARIF.

See `workflows/multi_tool_scan.md` for the reference orchestration.

## Sub-Agent Delegation

Pattern: **one sub-agent per tool for scanning; one aggregator/triage agent downstream.**

- Per-tool scan agent: context-minimal, just runs `<tool>` and reports SARIF path + count. Minimal thinking.
- Aggregator agent: reads all SARIF, normalizes to `schemas/finding.json`, deduplicates by `(cwe, file, ±3 lines)`.
- Triage agent: consumes deduped findings, annotates with reachability, exploitability rank, and fix suggestions. **Maximum thinking.**

Do not pool tool-specific expertise into one mega-agent — it collapses parallelism and exhausts context.

## Reasoning Budget

Allocate extended thinking deliberately — not uniformly.

| Activity | Budget | Rationale |
|----------|--------|-----------|
| Running a scan (`semgrep --config=auto .`) | **None** | Mechanical; just invoke |
| Pack selection / tool selection | Low | Matrix lookup in `references/<tool>.md` |
| SARIF aggregation + dedup | Low | Deterministic key-based merge |
| Triage (`workflows/triage.md`) | **MAXIMUM** | Reachability, taint, impact, FP classification — where Opus-4.7-class models dominate |
| Custom Semgrep rule from CVE | High | Generalizing patch diff → AST pattern |
| Custom CodeQL query from sink | High | Source/sink/barrier modeling |
| FP reduction (rule tuning) | Medium | Pattern recognition across findings |
| CI/CD config | Low | Template instantiation |

**Headline: extended thinking pays off most on triage. This is the single biggest win over traditional SAST tools. Do not rush per-finding analysis.**

## Structured Output

All findings — regardless of source tool — conform to `schemas/finding.json`. Key fields include `tool`, `rule_id`, `cwe`, `file_path`, `line`, `column`, `snippet`, `confidence`, `exploitability_rank` (1-5), `is_reachable`, `taint_source`, `taint_sink`, `taint_flow`, `is_false_positive`, `fp_reason`, `remediation`, `fix_suggestion`.

Use SARIF 2.1.0 for tool-native emission; convert to the finding schema during aggregation. See `references/sarif_format.md`.

## Workflow Index

| Workflow | Purpose | Thinking |
|----------|---------|----------|
| [workflows/multi_tool_scan.md](workflows/multi_tool_scan.md) | Run Semgrep + CodeQL + language tools in parallel; dedup SARIF | Low |
| [workflows/triage.md](workflows/triage.md) | **HEADLINE** — ingest SARIF, rank exploitability, identify FPs, emit fix suggestions | **MAX** |
| [workflows/custom_semgrep_from_cve.md](workflows/custom_semgrep_from_cve.md) | CVE advisory + patch → Semgrep rule + tests | High |
| [workflows/custom_codeql_from_sink.md](workflows/custom_codeql_from_sink.md) | Sink API → taint-tracking query with sources/sanitizers | High |
| [workflows/false_positive_reduction.md](workflows/false_positive_reduction.md) | Systematic rule-level FP triage + suppression loop | Medium |
| [workflows/cicd_integration.md](workflows/cicd_integration.md) | GitHub Actions / GitLab CI / Bitbucket / Jenkins / pre-commit templates | Low |

## References Index

| Reference | Covers |
|-----------|--------|
| [references/semgrep.md](references/semgrep.md) | Install, pack selection, rule authoring, taint mode, autofix |
| [references/codeql.md](references/codeql.md) | DB creation, suite names, modern `DataFlow::ConfigSig` taint template |
| [references/bandit.md](references/bandit.md) | Python AST scanner: test IDs, known FPs |
| [references/gosec.md](references/gosec.md) | Go scanner: G-rule table, suppressions |
| [references/brakeman.md](references/brakeman.md) | Rails-aware scanner: check list, config |
| [references/spotbugs.md](references/spotbugs.md) | Java bytecode + Find Security Bugs: Maven/Gradle setup, FSB detectors |
| [references/eslint_security.md](references/eslint_security.md) | JS/TS security plugins: flat-config + legacy |
| [references/sarif_format.md](references/sarif_format.md) | SARIF 2.1.0 schema, codeFlows, fingerprinting, emission flags |
| [references/bounty_patterns_2024_2026.md](references/bounty_patterns_2024_2026.md) | Post-2023 bounty TTPs as SAST rule ideas (prototype-pollution, ORM JOIN leakage, AI-tool-call injection in repo/config strings) |

## Examples Index

| Path | Purpose |
|------|---------|
| [examples/semgrep_rules/sql_injection.yaml](examples/semgrep_rules/sql_injection.yaml) | Multi-language SQL injection rules (textual + taint) |
| [examples/semgrep_rules/ssrf.yaml](examples/semgrep_rules/ssrf.yaml) | SSRF rules — Python/JS/Go with taint + fallback |
| [examples/semgrep_rules/hardcoded_secret.yaml](examples/semgrep_rules/hardcoded_secret.yaml) | Secret-pattern regex rules: AWS, GitHub, Slack, Stripe, keys |
| [examples/codeql_queries/taint_template.ql](examples/codeql_queries/taint_template.ql) | Starter taint-tracking query (Python, modern API) |
| [examples/codeql_queries/sql_injection_taint.ql](examples/codeql_queries/sql_injection_taint.ql) | Full SQLi taint query: multi-framework sources + sanitizers |
| [examples/codeql_queries/hardcoded_credential.ql](examples/codeql_queries/hardcoded_credential.ql) | Single-location `@kind problem` query |

## Scripts

| Script | Purpose |
|--------|---------|
| [scripts/sast_scan.sh](scripts/sast_scan.sh) | Parallel multi-tool orchestration; emits SARIF per tool |
| [scripts/aggregate_results.py](scripts/aggregate_results.py) | SARIF → `schemas/finding.json` with dedup |

## Tools

| Tool | Purpose | Install |
|------|---------|---------|
| Semgrep | Multi-language pattern + taint SAST | `pip install semgrep` / `brew install semgrep` |
| CodeQL | Deep taint SAST, GitHub-native | Download CLI from github/codeql-cli-binaries |
| Bandit | Python AST scanner | `pip install 'bandit[sarif]'` |
| gosec | Go scanner | `go install github.com/securego/gosec/v2/cmd/gosec@latest` |
| Brakeman | Rails scanner | `gem install brakeman` |
| SpotBugs + FSB | Java bytecode scanner | Maven/Gradle plugin |
| ESLint + security plugins | JS/TS linter-scanner | `npm i -D eslint eslint-plugin-security eslint-plugin-no-unsanitized` |
| Gitleaks | Secret scanner | `brew install gitleaks` |

## Last Validated

2026-04. Minimum versions tested: Semgrep 1.60, CodeQL CLI 2.17, Bandit 1.8, gosec 2.20, Brakeman 6.2, SpotBugs 4.8 + FSB 1.13, ESLint 9.
