# Bug Bounty Patterns 2024-2026 — sast-orchestration

## Overview

Rules and detection strategies for post-2023 patterns, targeted at static analysis
orchestrators (Semgrep, CodeQL, Bandit, gosec, Brakeman, ESLint). Adds:
- prototype-pollution (DOMPurify / deep-merge) detection,
- ORM JOIN-leakage detection,
- source-side AI-tool-call-injection detection (MCP manifests, agent configs).
Sources: PortSwigger Top 10 2024/2025, CVE-2024-45801, CVE-2025-53773, HackerOne SCA.
Last validated: 2026-04. Emit findings via `../schemas/finding.json`.

## Pattern Index

| #   | Pattern                                                  | Severity | Primary Source                        |
|-----|----------------------------------------------------------|----------|---------------------------------------|
| PA  | Prototype Pollution via deep-merge / Object.assign       | High     | PortSwigger 2024 · CVE-2024-45801     |
| PB  | ORM Data Leakage via relational filter DSL               | High     | PortSwigger 2025                      |
| P8  | AI-Tool-Call Injection embedded in repo/config strings   | Critical | CVE-2025-53773 (Copilot)              |

---

## Patterns

### PA. Prototype Pollution via deep-merge / Object.assign

- **CVE / Source:** PortSwigger "Top 10 2024"; CVE-2024-45801 (DOMPurify < 3.0.8).
- **Summary:** Deep-merge / recursive-assign helpers that copy `__proto__`, `constructor`, or `prototype` keys from untrusted input into host objects pollute `Object.prototype` globally, enabling XSS / RCE downstream.
- **Affected surface:** `lodash.merge`, `_.defaultsDeep`, hand-rolled `function deepMerge(a,b)`, query-string parsers (`qs` with `allowPrototypes: true`), config loaders (`rc`, `yargs`, `minimist` < 1.2.6).
- **Detection (Semgrep rule idea):**
  ```yaml
  rules:
    - id: js.prototype-pollution.unsafe-merge
      languages: [javascript, typescript]
      message: Untrusted data flows into a prototype-reachable deep-merge.
      severity: ERROR
      pattern-either:
        - pattern: $MERGE(..., $UNTRUSTED, ...)
        - patterns:
            - pattern: |
                for ($K in $SRC) { $DST[$K] = ... }
            - metavariable-regex: { metavariable: $K, regex: "^(?!.*(Object|hasOwn))" }
      metavariable-pattern:
        metavariable: $MERGE
        patterns:
          - pattern-regex: "(_|lodash)\\.(merge|defaultsDeep|mergeWith)|Object\\.assign"
      metavariable-pattern:
        metavariable: $UNTRUSTED
        patterns:
          - pattern-either:
              - pattern: req.body
              - pattern: req.query
              - pattern: req.params
              - pattern: JSON.parse($X)
  ```
- **Exploitation / PoC (to validate rule):**
  ```js
  const _ = require('lodash');
  _.merge({}, JSON.parse('{"__proto__":{"polluted":1}}'));
  console.log(({}).polluted); // 1
  ```
- **Indicators:** Rule hits; runtime: `Object.prototype` has unexpected keys.
- **Mitigation:** Upgrade libs; `Object.freeze(Object.prototype)`; explicit allow-list merge; CodeQL pack `javascript/prototype-pollution`.
- **Cross-refs:** CWE-1321; DAST chain → `../../dast-automation/references/bounty_patterns_2024_2026.md` (PA).

### PB. ORM Data Leakage via Relational Filter DSL

- **CVE / Source:** PortSwigger "Top 10 2025".
- **Summary:** API handlers that pass request-supplied filter strings into an ORM / ORM-like DSL (`findWhere`, `PostgREST` style, Prisma `where`, Hasura `where`) allow queries across relations the user should not traverse. Static analysis can flag the sink.
- **Affected surface:** Node / TS Prisma; Python SQLAlchemy with `filter_by(**request.args)`; Ruby ActiveRecord `where(params[:filter])`; Java Hibernate Query-by-Example; GraphQL without permission middleware.
- **Detection (Semgrep rule idea):**
  ```yaml
  rules:
    - id: orm.untrusted-filter-dsl
      languages: [python, javascript, typescript, ruby]
      message: Untrusted input passed directly to ORM where/filter builder.
      severity: ERROR
      pattern-either:
        - pattern: $MODEL.objects.filter(**$UNTRUSTED)
        - pattern: prisma.$M.findMany({ where: $UNTRUSTED })
        - pattern: $REPO.where($UNTRUSTED)
        - pattern: $QB.where($KEY, $OP, $UNTRUSTED)
      metavariable-pattern:
        metavariable: $UNTRUSTED
        patterns:
          - pattern-either:
              - pattern: request.args
              - pattern: req.query
              - pattern: params[:filter]
              - pattern: input.where
  ```
- **Exploitation / PoC:**
  ```http
  GET /api/notes?filter[author.email][starts_with]=admin@ HTTP/1.1
  ```
- **Indicators:** Production log shows filter path spanning `*.email`, `*.password_hash`, `*.org_id` from non-privileged users.
- **Mitigation:** Whitelist filterable fields per endpoint; apply row-level auth middleware; GraphQL: `@auth` directive on every field.
- **Cross-refs:** CWE-200, CWE-639; related → API P6, DAST PB.

### P8. AI-Tool-Call Injection Embedded in Repo / Config Strings

- **CVE / Source:** CVE-2025-53773 (GitHub Copilot); LLM skill P8.
- **Summary:** Source-side counterpart of LLM P8 — detect *at SAST time* the presence of agent-targeting instructions in repository content. These smuggle tool-call directives into repos, MCP manifests, GitHub-Action descriptions, and CI config.
- **Affected surface:** Any repo feeding an AI coding assistant, an MCP server registry, or an LLM doc-search index.
- **Detection (Semgrep rule idea):**
  ```yaml
  rules:
    - id: ai.tool-call-injection.in-string
      languages: [generic]
      paths:
        include: ["*.md", "*.mdx", "*.rst", "*.txt", "*.yml", "*.yaml", "*.json", "*.jsonc", "*.ipynb", "*.mdc"]
      message: Potential LLM instruction injection embedded in content.
      severity: WARNING
      pattern-regex: >-
        (?i)(ignore\s+previous|disregard\s+prior|you\s+are\s+now|<\|im_start\|>|
        \bSYSTEM\s*[:>]|\bASSISTANT\s*[:>]|\bdeveloper\s*[:>]|
        run\s+the\s+following\s+command|curl\s+[^\s`]+\|\s*sh|
        execute\s+.*\s+in\s+the\s+shell|tool:\w+\(|<tool_call>)
  ```
  Secondary Unicode detection (`generic` path, hex-regex):
  ```yaml
    - id: ai.tool-call-injection.invisible
      languages: [generic]
      paths: { include: ["*.md", "*.mdx", "*.rst", "*.txt", "*.json", "*.yaml"] }
      message: File contains invisible Unicode tag / bidi / ZW chars (prompt injection carrier).
      severity: WARNING
      pattern-regex: "[\\x{E0000}-\\x{E007F}\\x{202A}-\\x{202E}\\x{2066}-\\x{2069}\\x{200B}-\\x{200F}]"
  ```
- **Exploitation / PoC (validation):** See LLM skill P8 PoC samples; pipe through Semgrep to confirm rule fires.
- **Indicators:** Rule hits in PRs touching docs / config / MCP manifests.
- **Mitigation:** CI gate on the rule; strip / sanitize tool-description strings before registering with an agent; sign MCP manifests.
- **Cross-refs:** CWE-77, CWE-94; related → LLM P7/P8, SCA P30/P31.

---

## Output plumbing
All three rules should output SARIF and feed into the skill's existing triage flow
(`../workflows/*` — prioritize by reachability, then by DAST-confirmed exploitability).

## Cross-skill links
- LLM: runtime counterparts — `../../llm-security/references/bounty_patterns_2024_2026.md`.
- DAST: dynamic confirmation — `../../dast-automation/references/bounty_patterns_2024_2026.md`.
- SCA: package-level AI-manifest triage — `../../sca-security/references/bounty_patterns_2024_2026.md`.
