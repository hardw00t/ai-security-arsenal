# Phase 3: Output Artifacts

Every DAST result written to disk follows `schemas/finding.json`. Human-readable outputs are generated from the JSON set, not hand-written.

## Output hierarchy

```
results/<target>/
├── output.json             # array of finding objects (schemas/finding.json)
├── output.html             # rendered for humans
├── output.md               # for issue trackers
├── output.pdf              # executive handout (optional)
├── crawl/                  # raw crawl artifacts
├── evidence/               # per-entry request/response bodies
└── screenshots/            # per-entry Playwright screenshots
```

## Entry skeleton

Driven by `schemas/finding.json`. Required per entry:

- `id` — deterministic (`<target>-<cwe>-<hash(url+param+payload)>`)
- `title` — less than 80 chars
- `severity` — one of `critical|high|medium|low|info`
- `confidence` — `confirmed|likely|suspected`
- `affected.url`, `affected.http_method`, `affected.parameter`
- `evidence.request` (curl command)
- `evidence.response` (truncated to 1 KB)
- `evidence.playwright_screenshot_path` (when available)
- `reproduction` — ordered step array
- `remediation` — concise, actionable

## Severity rubric (calibrate with CVSS)

| Severity | Criteria |
|----------|----------|
| Critical | RCE, SQLi-to-DB dump, IDOR exposing PII of other tenants, auth bypass, SSRF-to-cloud-creds |
| High     | Stored XSS w/ session context, privilege escalation, SSRF-to-internal-no-creds, SSO replay |
| Medium   | Reflected XSS, CSRF on non-critical action, info leak (versions, stacktraces), open redirect |
| Low      | Missing cookie flags, verbose errors, unsanitized headers, weak TLS config |
| Info     | Tech fingerprint, defense-in-depth suggestions |

## Executive summary template

```markdown
# DAST Assessment — <target> — <date>

**Scope:** <hosts>
**Mode:** blackbox|greybox
**Duration:** <hh:mm>

| Severity | Count |
|----------|-------|
| Critical | N     |
| High     | N     |
| Medium   | N     |
| Low      | N     |

**Top 3 risks:**
1. ...
2. ...
3. ...

**Recommended immediate actions:** ...
```

## Validation gate

Before delivery:

- Every Critical/High re-verified manually (one operator, fresh session).
- All screenshots redact PII.
- Credentials scrubbed from logs (`grep -r <password> results/` returns empty).
- JSON validates against `schemas/finding.json`.

## CI/CD integration

See `examples/github_actions_dast.yml` — fail the pipeline on new Critical/High vs baseline.

## Do not share

- Raw cookies, full JWTs, or customer PII.
- Sample payloads with working exploit code for unpatched Critical issues on public trackers.
