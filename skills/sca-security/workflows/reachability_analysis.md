# Reachability Analysis Workflow — KEY WORKFLOW

**This is the SCA killer feature for frontier models.** Most SCA findings are noise because the vulnerable function is never called from application code. Reachability analysis filters the triage queue from hundreds of findings to the handful that actually matter.

## Why reachability?

A CVE on `lodash.template()` is irrelevant if your app only uses `lodash.cloneDeep()`. Classic SCA tools alert on both. Reachability analysis answers: "is the vulnerable symbol transitively called from any application entry point?"

Signal: typical enterprise repos see 70-95% false positive reduction with reachability filtering.

## Decision tree

```
Finding has a known vulnerable symbol (function/class/method)?
 yes → proceed to Step 1
 no  → mark is_reachable=unknown, do NOT suppress; rely on other signals
        (e.g. entire package is malicious → always reachable-by-existence)
```

## Step 1 — Identify the vulnerable symbol

Per CVE/GHSA, extract the "sink":
- GHSA advisories often include patch diffs — the patched function is the sink.
- Snyk Vuln DB provides `vulnerableFunctions` field.
- OSV does not standardize this; fall back to the patch commit.

Example (CVE-2021-23337 lodash):
```
vulnerable_symbol: "lodash.template"
  (also: "template" when imported as named export)
```

## Step 2 — Build the call graph

Pick a tool per ecosystem:

| Ecosystem | Tool | Command |
|-----------|------|---------|
| Go | OSV-Scanner call analysis | `osv-scanner --experimental-call-analysis ./...` |
| Python | Semgrep + custom rules | `semgrep --config p/security-audit --metavariable-pattern '$F($...)'` |
| JavaScript/TypeScript | Socket CLI / CodeQL | `codeql database analyze --format=sarif` |
| Java | CodeQL / Snyk Code | `codeql database analyze --format=sarif` |
| Rust | cargo-geiger (unsafe reachability proxy) | `cargo geiger` |
| Multi-language | CodeQL | Language-specific packs |

## Step 3 — Query reachability

### 3a. OSV-Scanner (Go, preferred when available)

```bash
osv-scanner --experimental-call-analysis=go -r . --format=json > reach.json
# Each vuln in output has:
#   groupInfo.experimentalAnalysis.<CVE>.called: true/false
```

### 3b. Semgrep taint mode (Python/JS)

```yaml
# .semgrep/lodash-template.yml
rules:
  - id: lodash-template-reachable
    mode: taint
    pattern-sources:
      - pattern-either:
          - pattern: |
              import { template } from "lodash"
          - pattern: |
              require("lodash").template
    pattern-sinks:
      - pattern: $T(...)
    message: Reachable call to vulnerable lodash.template (CVE-2021-23337)
    severity: ERROR
    languages: [javascript, typescript]
```

### 3c. CodeQL (Java / TS / Python / C/C++)

```bash
codeql database create db --language=javascript --source-root=.
codeql query run --database=db \
  queries/reachable-lodash-template.ql > reachable.bqrs
codeql bqrs decode reachable.bqrs --format=json > reachable.json
```

Query sketch (pseudo-CodeQL):
```
from FunctionCall c, Import i
where i.getImportedPath() = "lodash"
  and c.getTarget().getName() = "template"
  and reachableFromEntryPoint(c)
select c
```

## Step 4 — Cross-reference vuln → symbol → call sites

For each vuln finding:

```
vuln: CVE-2021-23337 (lodash < 4.17.21)
  package: lodash@4.17.20 present? yes
  vulnerable_symbol: lodash.template
  call_sites in app code: [src/email/renderer.ts:42, src/admin/template.ts:18]
  → is_reachable = "reachable"
```

vs:

```
vuln: CVE-2020-8203 (lodash < 4.17.19, zipObjectDeep)
  package: lodash@4.17.20 present? yes (already patched via 4.17.20)
  → not applicable
```

vs:

```
vuln: CVE-2022-21797 (joblib Python)
  package: joblib@1.1.0 present? yes (transitive via scikit-learn)
  vulnerable_symbol: joblib.load
  call_sites in app code: none
  call_sites in transitive deps: scikit-learn's model loader (not on hot path)
  → is_reachable = "unreachable" (with caveat: user-controlled model files would change this)
```

## Step 5 — Populate finding

Update `schemas/finding.json` instance:

```json
{
  "is_reachable": "reachable",
  "reachability_evidence": {
    "vulnerable_symbol": "lodash.template",
    "call_sites": ["src/email/renderer.ts:42", "src/admin/template.ts:18"],
    "call_graph_depth": 2,
    "tool": "codeql"
  },
  "exploitability_notes": "template() is called with user-supplied subject line from /admin/send-email; confirmed reachable from HTTP edge."
}
```

## Step 6 — Prioritize

Re-rank the triage queue:

| is_reachable | kev | epss | action |
|--------------|-----|------|--------|
| reachable | true | any | P0 — fix within 24h |
| reachable | false | >=0.5 | P1 — fix within 7d |
| reachable | false | <0.5 | P2 — fix within 30d |
| unknown | true | any | P1 — investigate reachability first |
| unreachable | any | any | P3 — document + update deps on next cycle |

## Integration with sast-orchestration

SAST tools produce call graphs as a byproduct. If sast-orchestration has already run and produced a CodeQL DB or Semgrep dataflow output, **reuse it** — don't rebuild. See `sast-orchestration` skill for call graph artifacts.

## Parallelism hint

- Call graph build: one per ecosystem, in parallel (each independent).
- Per-vuln reachability queries against the same graph: parallel.
- Sequential: graph must be built before queries.

## Reasoning budget

**High — use extended thinking.** This workflow requires combining:
- CVE advisory metadata (which function is vulnerable)
- Call graph structure (can we reach it?)
- Taint propagation (does user input flow to the call?)
- Ecosystem-specific import semantics (re-exports, dynamic requires, reflection)

The model must reason about transitive call chains and potentially mismatched symbol names (minification, re-exports, monkey-patching). Do not shortcut.

## Common pitfalls

- Dynamic dispatch / reflection hides calls from static graphs → assume reachable when the language supports it (Python `getattr`, Java reflection, JS dynamic `require`).
- Tree-shaking/bundler dead-code-elimination can remove vulnerable code at build time — check the shipped bundle, not source.
- Framework magic (Django signals, Spring autowiring, Next.js routing) — entry points are not `main()`; enumerate framework routes.
- Test-only reachability doesn't count — exclude `test/`, `spec/`, `__tests__/` from entry points.
