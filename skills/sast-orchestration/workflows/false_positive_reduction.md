# Workflow: Systematic False-Positive Reduction

SAST tools generate noise. A noisy tool that developers ignore is worse than a tuned tool that teams act on. This workflow converts raw output into a low-noise stream.

## Reasoning budget: MEDIUM

FP reduction is mostly pattern recognition at the rule level. Per-finding deep reasoning is the triage workflow's job; THIS workflow works at the rule / codebase level.

## Inputs

- Historical findings (ideally at least one prior scan)
- Current scan SARIF outputs
- Optional: prior triage annotations (TP/FP labels)

## Loop

```
┌────────────────────────────────────────────────────────────────┐
│  1. Run scans → collect SARIF                                  │
│  2. Group findings by rule_id                                  │
│  3. Sample 10-20 findings per high-volume rule                 │
│  4. Triage sample: TP or FP? Record fp_reason                  │
│  5. If FP rate >30% on sample:                                 │
│     - Is there a codebase-specific FP pattern? → ignore rule   │
│     - Is it a noisy default rule? → downgrade / suppress       │
│     - Is there a known-safe wrapper? → add sanitizer model     │
│  6. Re-run, measure: target <10% FP on remaining findings      │
└────────────────────────────────────────────────────────────────┘
```

## Common FP classes and fixes

### SQL injection FPs

| Pattern | Fix |
|---------|-----|
| ORM methods (SQLAlchemy `.filter()`, Django `.filter()`) | Add `pattern-not-inside:` ORM chain |
| Parameterized via 2-arg form: `execute(sql, params)` | Ensure rule requires single-arg execute |
| Hardcoded string literal | `metavariable-pattern: pattern-not-regex: '^".*"$'` |
| Query builder (sqlalchemy.text, knex.raw without interp) | Whitelist specific API shape |

### XSS FPs

| Pattern | Fix |
|---------|-----|
| Auto-escaping template (Jinja2 autoescape=True, React JSX) | Exclude render paths or downgrade rule |
| Server-only internal tools (no browser render) | Scope via `paths.include` for public endpoints |
| Sanitization with `bleach.clean`, `DOMPurify.sanitize` | Add as `pattern-sanitizers` / `isBarrier` |

### Command injection FPs

| Pattern | Fix |
|---------|-----|
| Hardcoded argv (`exec.Command("ls", "-l")`) | Rule should require variable arg |
| Validated allowlist (`if cmd in ALLOWED:`) | Add `pattern-not-inside` for allowlist check |
| `shlex.quote` / `shellescape` wrapper | Add as sanitizer |

### Crypto FPs

| Pattern | Fix |
|---------|-----|
| MD5/SHA1 for non-security hashing (ETags, cache keys) | Scope by call site / suppress per-file |
| Test/dev environments | `paths.exclude: ["tests/**", "**/dev/**"]` |
| Legacy migration (marked by comment) | `pattern-not-inside` comment block, or `# nosec` |

### Secrets FPs

| Pattern | Fix |
|---------|-----|
| Test fixtures / example configs | `paths.exclude: ["tests/fixtures/**", "**/*.example.*"]` |
| Placeholder strings (`xxxxxxxx`, `CHANGEME`) | Entropy floor + regex negatives |
| Public keys (by design) | Whitelist key-format prefixes (`ssh-rsa AAAA`, not secret) |

## Triage annotations — make them durable

For every confirmed FP, record in a persistent format so future scans don't re-triage:

```yaml
# .sast-triage.yaml
findings:
  - fingerprint: abc123def456
    tool: semgrep
    rule_id: python.lang.security.audit.dangerous-system-call
    file_path: src/ops/deploy.py
    line_range: [45, 50]
    status: accepted
    reason: "sanitized via shlex.quote on line 44; rule misses wrapper function"
    reviewed_by: alice
    reviewed_date: 2026-04-15
    expires: 2026-10-15
```

Tools that honor per-finding suppressions:
- Semgrep: `# nosemgrep: <rule-id>` inline; `.semgrepignore` for paths.
- CodeQL: `// lgtm[<rule-id>]` inline (legacy); query-suite filters.
- Bandit: `# nosec <B###>` inline.
- gosec: `// #nosec G###` inline.
- Brakeman: `config/brakeman.ignore` (generated JSON).
- SpotBugs: `@SuppressFBWarnings`.
- ESLint: `// eslint-disable-next-line <rule>`.

## Rule tuning levers

Ranked from cheapest to most-expensive:

1. **Path exclusion** — `paths.exclude` / `.semgrepignore` / `exclude_dirs`. Start here.
2. **Severity / confidence floor** — raise `--severity ERROR` or `bandit -ll -ii`.
3. **Rule exclusion** — drop specific noisy rule IDs.
4. **Metavariable constraints** — add `metavariable-regex` / `-pattern` to narrow match.
5. **Sanitizer modeling** — add `pattern-sanitizers` / `isBarrier` predicate.
6. **Custom rule replacement** — rewrite the rule with more precision.

Do NOT disable entire security categories (e.g., "all SQL injection rules"). Prefer surgical suppressions with justification.

## Metrics

Track per scan:
- Total findings (raw).
- Findings after FP suppression (effective).
- FP rate on a labeled sample (target <10%).
- Mean-time-to-triage per finding (target <5 min for frontier-model triage).
- Rule-level FP distribution (rules in the top decile by FP rate → tune first).

## Anti-patterns

- Suppressing findings without written reason → re-emerges next scan, team ignores it.
- Global rule disables → lose coverage on unrelated codebases.
- Tuning to zero findings → tool is broken; real bugs hide in the noise that was deleted.
- Trusting the tool's own `confidence` field → verify against code.
