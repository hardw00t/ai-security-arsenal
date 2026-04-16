# Workflow: SAST Finding Triage (HEADLINE WORKFLOW)

This is where frontier-model reasoning adds the most value over raw SAST output. SAST tools are great at generating candidates; they are poor at distinguishing exploitable bugs from noise. Your job is the latter.

## Reasoning budget: MAXIMUM

Use extended thinking aggressively in this workflow. Per finding, you're performing:
1. Reachability analysis (can user input reach this sink?)
2. Sanitizer recognition (is the data validated on the path?)
3. Trust-boundary reasoning (is the source actually untrusted?)
4. Impact modeling (RCE vs. info-disc vs. DoS vs. theoretical)
5. Cross-tool corroboration (do multiple tools flag the same root cause?)

Each of these benefits from chain-of-thought. Do NOT rush. This is where Opus-4.7-class models dominate traditional SAST triage tools — lean into it.

## Inputs

- Normalized findings array conforming to `schemas/finding.json`
- Read access to the target repository
- Optional: prior triage history, threat model, architecture notes

## Output

Same findings array, annotated in-place with:
- `exploitability_rank` (1 = trivial exploit, 5 = theoretical)
- `is_reachable` (bool)
- `taint_source`, `taint_sink`, `taint_flow` (filled in when you trace)
- `is_false_positive` + `fp_reason` (when applicable)
- `confidence` (confirmed / likely / suspected)
- `fix_suggestion` (concrete patch or replacement code)

## SARIF ingestion

```python
import json
def load_sarif(path):
    with open(path) as f: s = json.load(f)
    for run in s["runs"]:
        tool = run["tool"]["driver"]["name"].lower()
        rules = {r["id"]: r for r in run["tool"]["driver"].get("rules", [])}
        for r in run["results"]:
            loc = r["locations"][0]["physicalLocation"]
            yield {
                "tool": tool,
                "rule_id": r["ruleId"],
                "file_path": loc["artifactLocation"]["uri"],
                "line": loc["region"]["startLine"],
                "column": loc["region"].get("startColumn"),
                "message": r["message"]["text"],
                "level": r.get("level", "warning"),
                "cwe": _extract_cwe(rules.get(r["ruleId"], {})),
                "code_flows": r.get("codeFlows", []),
                "fingerprint": r.get("partialFingerprints", {}).get("primaryLocationLineHash"),
            }
```

See `references/sarif_format.md` for full schema.

## The triage loop (per finding)

Think carefully through each step. Do not skip.

### Step 1 — Classify the bug class

From `rule_id` + `cwe`, identify the class: injection / XSS / SSRF / path traversal / crypto / auth / deserialization / secret / ReDoS / race / other.

### Step 2 — Read the code

Open `file_path` and at minimum read ±30 lines around `line`. For taint bugs, follow `taint_flow` / `codeFlows` if present. If the tool did NOT provide a flow, construct one mentally: where does the variable at `line` come from?

### Step 3 — Reachability

Ask: "If I were an attacker, what HTTP request / CLI invocation / message reaches this line?"

- If there is no plausible entry point → `is_reachable=false`, `is_false_positive=true`, `fp_reason=dead_code`.
- If the only entry is test fixtures → `fp_reason=test_only`.
- If reached only via an authenticated admin role → note in remediation, lower rank by 1.

### Step 4 — Sanitizers on the path

Walk from the source toward the sink. List every transformation:
- Type coercion (`int(x)`, `parseInt(x)`) — often sufficient for SQLi/path traversal, not for XSS.
- Allowlist check (`if x in ALLOWED:`) — effective if allowlist is complete.
- Escape function (`markupsafe.escape`, `shlex.quote`, `html.escape`) — bug-class-specific.
- ORM / parameterized API — usually safe unless raw-string escape hatch used.
- Regex validation — frequently insufficient (bypass surfaces).

If a recognized sanitizer covers the bug class → `is_false_positive=true`, `fp_reason=sanitized`.

### Step 5 — Trust boundary

Is the source actually attacker-controlled?
- HTTP request params, headers, body → YES
- Env vars set by operator → NO for external attacker, YES for insider
- File system reads → depends on who writes the file
- DB reads → only if the DB is writable by an attacker (stored injection)

If source is not attacker-controlled → downgrade or mark FP (`fp_reason=not_user_controlled`).

### Step 6 — Impact

- RCE (command injection, deserialization, template injection) → rank 1-2, severity critical
- SQLi with DB that contains sensitive data → rank 1-2, severity critical
- SSRF with cloud metadata reachable → rank 1, severity critical
- SSRF blind → rank 2-3, severity high
- Stored XSS in authenticated context → rank 2, severity high
- Reflected XSS with no sensitive context → rank 3, severity medium
- DoS-only (ReDoS, algorithmic) → rank 3-4, severity medium
- Info disclosure (stack trace, version) → rank 4, severity low
- Defense-in-depth / best-practice → rank 5, severity info

### Step 7 — Cross-tool corroboration

If multiple tools flagged the same root cause (check `duplicate_of[]`), raise confidence to `confirmed`. If only one tool with a low-precision rule — `suspected`.

### Step 8 — Fix suggestion

Write the patch you would apply. Concrete code, not advice. Examples:

```python
# BEFORE
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
# AFTER
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
```

```go
// BEFORE
exec.Command("sh", "-c", "ls "+userDir)
// AFTER  — do not use shell; pass args directly
exec.Command("ls", userDir)     // still validate userDir against allowlist
```

## Batch triage strategy for large finding sets

If you have >100 findings:
1. Group by `(rule_id, file_path)` — one root cause often produces many findings.
2. Triage one representative per group with full thinking; apply conclusion to the group.
3. Sample 10% of each group to verify no drift from representative.
4. Focus full-thinking budget on: critical severity, RCE-class, cross-tool duplicates.

## Exploitability rank rubric

| Rank | Meaning |
|------|---------|
| 1 | Trivial: direct attacker input to dangerous sink, no auth, no sanitizer |
| 2 | Straightforward: requires minor precondition (auth as normal user, specific header) |
| 3 | Feasible: requires chaining, specific state, or partial control |
| 4 | Difficult: requires rare precondition, privileged position, or protocol quirk |
| 5 | Theoretical: defense-in-depth; requires breaking a separate security control first |

## Deliverables

1. Annotated findings array (schemas/finding.json conformant).
2. Top-N report: findings where `rank <= 2` and `is_false_positive = false`, sorted by severity.
3. FP report: findings marked FP with `fp_reason` — useful for tuning rules.
4. Rule-tuning recommendations: rule IDs with FP rate >30% → candidates for `semgrep:ignore` / suppression config.

## Common pitfalls

- Marking something FP because "the framework handles it" without verifying the framework version enables that protection.
- Trusting `metadata.confidence` from the tool as ground truth — always verify against the code.
- Skipping step 5 (trust boundary) — internal tools still have insider threats.
- Letting tool noise set the ceiling: if every `eval()` is flagged, the FP rate is fine if every true positive is caught.
