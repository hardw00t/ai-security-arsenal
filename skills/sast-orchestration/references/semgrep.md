# Semgrep Reference

Fast, multi-language pattern-based SAST with a simple YAML rule DSL. Best for custom patterns, secrets, framework-specific rules, and quick scans.

## Install

```bash
pip install semgrep
# or
brew install semgrep
# Verify: semgrep --version (target >= 1.60)
```

## Invocation

```bash
# Default auto-config
semgrep --config=auto .

# Curated rule packs
semgrep --config=p/security-audit \
        --config=p/secrets \
        --config=p/supply-chain \
        --config=p/owasp-top-ten \
        --config=p/cwe-top-25 .

# Language packs: p/python p/javascript p/java p/golang p/ruby p/php
# Framework packs: p/django p/flask p/react p/nodejs p/express p/spring

# Custom rules directory
semgrep --config=./rules/ .

# Output (SARIF is preferred for triage interop)
semgrep --config=auto --sarif -o results.sarif .
semgrep --config=auto --json -o results.json .

# CI mode (non-zero exit on findings, honors .semgrepignore)
semgrep ci
```

## Rule pack selection matrix

| Goal | Config |
|------|--------|
| Quick audit | `--config=auto` |
| OWASP coverage | `p/owasp-top-ten p/cwe-top-25` |
| Secret detection | `p/secrets p/gitleaks` |
| Supply chain | `p/supply-chain` |
| Python web | `p/python p/django p/flask` |
| JS/TS web | `p/javascript p/react p/nodejs p/express` |
| Java web | `p/java p/spring` |
| Dockerfile | `p/dockerfile` |

## Rule authoring essentials

Minimal rule skeleton:

```yaml
rules:
  - id: <kebab-case-id>
    message: <one-line finding text>
    languages: [python]  # or generic, javascript, java, go, ruby, php, etc.
    severity: ERROR      # ERROR | WARNING | INFO
    metadata:
      cwe: "CWE-89"
      owasp: "A03:2021 - Injection"
      confidence: HIGH
    pattern: <code pattern>
```

### Pattern operators

- `pattern`: single pattern match
- `patterns`: AND of conditions
- `pattern-either`: OR of conditions
- `pattern-inside` / `pattern-not-inside`: contextual scoping
- `pattern-not`: negation
- `metavariable-pattern`: nested match on a metavariable
- `metavariable-regex`: regex filter on metavariable text
- `metavariable-comparison`: numeric/string comparison

Metavariables: `$X` matches one AST node; `$...X` matches a sequence; `...` matches any code.

### Taint mode (preferred for injection classes)

```yaml
rules:
  - id: xss-taint
    mode: taint
    languages: [python]
    severity: ERROR
    pattern-sources:
      - pattern: request.args.get(...)
      - pattern: request.form.get(...)
    pattern-sanitizers:
      - pattern: markupsafe.escape(...)
    pattern-sinks:
      - pattern: render_template_string(...)
      - pattern: Markup(...)
    message: Untrusted input reaches HTML sink
```

### Autofix

Add `fix:` with a replacement template that can reference metavariables:

```yaml
fix: hmac.compare_digest($SECRET, $USER_INPUT)
```

### Path filters

```yaml
paths:
  include: ["src/**", "**/*prod*.py"]
  exclude: ["tests/**", "vendor/**"]
```

## Starter rules (see examples/semgrep_rules/)

- `sql_injection.yaml`
- `ssrf.yaml`
- `hardcoded_secret.yaml`

## Tuning and FP reduction

- Prefer `mode: taint` over textual patterns for injection, SSRF, path traversal, XXE.
- Add `pattern-not-inside` for safe wrappers in the codebase (ORMs, sanitizers).
- Use `paths.exclude` for test fixtures and vendored code.
- Set `metadata.confidence` for downstream triage ranking.
- `semgrep --severity ERROR` to fail CI only on high-signal findings.

## Known limits

- Inter-procedural taint requires Semgrep Pro (`--pro`) for deep flow.
- No call-graph outside a single file without Pro.
- Regex rules (`pattern-regex`) scan byte-wise and miss AST structure.

## Troubleshooting

- `--verbose` prints rule compile errors.
- `semgrep --test` runs rule unit tests (adjacent `*.yaml` + target file).
- Cache: `~/.semgrep/` — delete if rules feel stale.
