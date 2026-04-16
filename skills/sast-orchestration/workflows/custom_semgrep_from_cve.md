# Workflow: Semgrep Rule from a CVE Advisory

Given a CVE advisory (CVE-ID, affected package, description, patch diff), produce a Semgrep rule that detects the vulnerable pattern in first- or third-party code.

## Reasoning budget: HIGH

Rule authoring benefits strongly from extended thinking. You must:
- Identify the minimal AST shape of the bug from patch diffs.
- Generalize without over-matching (avoid broad `pattern: $X(...)`).
- Choose between `pattern`, `patterns` (AND), `pattern-either` (OR), and `mode: taint`.
- Name metavariables and add `metavariable-regex` / `metavariable-pattern` to keep precision.

Budget: per rule, ~3-5 iterations against the PoC + negative test cases before committing.

## Inputs

- CVE identifier and advisory text
- Affected package name + version range
- Patch diff (from GitHub security advisory, upstream commit, or vendor bulletin)
- Optional: public PoC

## Process

### 1. Extract the bug shape from the patch

Read the patch. Identify exactly what the fix changed. Common patterns:

| Patch pattern | Rule template |
|---------------|---------------|
| Added escape/sanitize call before sink | `pattern: $SINK(..., $INPUT, ...)` with `pattern-not-inside: $SANITIZE($INPUT)` |
| Added validation branch | `pattern: $SINK(...)` with `pattern-not-inside: if $VALIDATE(...): ...` |
| Replaced concatenation with parameterization | `pattern-either:` covering string-concat, f-string, %-fmt |
| Replaced weak primitive (md5 → sha256) | `pattern-either:` listing weak primitives |
| Changed default flag (secure=True) | `pattern: $CALL(..., secure=False, ...)` or `pattern-not: $CALL(..., secure=True, ...)` |

### 2. Minimal pattern

Start with the smallest pattern that matches the vulnerable call. Example — a hypothetical CVE where `render_to_string(template=user_input)` is vulnerable when `template` is tainted:

```yaml
rules:
  - id: cve-YYYY-NNNN-ssti-myframework
    message: |
      CVE-YYYY-NNNN: server-side template injection when user input
      flows to render_to_string(template=...) in myframework < 2.5.3
    languages: [python]
    severity: ERROR
    metadata:
      cve: "CVE-YYYY-NNNN"
      cwe: "CWE-94"
      confidence: HIGH
      references:
        - https://github.com/acme/myframework/security/advisories/GHSA-xxxx
    pattern: render_to_string(template=$TEMPLATE, ...)
```

### 3. Scope it correctly

Two choices:

**(a) Textual pattern** — fast, any codebase. Add path filters and metavariable constraints:

```yaml
    patterns:
      - pattern: render_to_string(template=$TEMPLATE, ...)
      - metavariable-pattern:
          metavariable: $TEMPLATE
          patterns:
            - pattern-not-regex: '^".*"$'   # exclude string literals
            - pattern-not-regex: "^'.*'$"
```

**(b) Taint mode** — higher fidelity, requires a source model:

```yaml
    mode: taint
    pattern-sources:
      - pattern: request.args.get(...)
      - pattern: request.form.get(...)
      - pattern: request.json.get(...)
    pattern-sinks:
      - pattern: render_to_string(template=$X, ...)
    pattern-sanitizers:
      - pattern: html.escape(...)
```

Prefer taint mode for injection-class CVEs; prefer textual for API-misuse or config CVEs.

### 4. Import-scoping (optional, precision boost)

If the rule applies only when the vulnerable library is imported:

```yaml
    patterns:
      - pattern-inside: |
          import myframework
          ...
      - pattern: myframework.render_to_string(template=$TEMPLATE, ...)
```

Or with `from` imports:

```yaml
    pattern-either:
      - patterns:
          - pattern-inside: |
              from myframework import render_to_string
              ...
          - pattern: render_to_string(template=$TEMPLATE, ...)
      - patterns:
          - pattern-inside: |
              import myframework
              ...
          - pattern: myframework.render_to_string(template=$TEMPLATE, ...)
```

### 5. Version-gating metadata

Semgrep does not natively gate by package version, but record it for triage:

```yaml
    metadata:
      cve: CVE-YYYY-NNNN
      vulnerable-versions: "<2.5.3"
      fixed-version: "2.5.3"
      package: "myframework"
```

Pair with SCA (see sca-security skill) to confirm the installed version is vulnerable.

### 6. Test matrix

Every rule needs BOTH a positive and negative test file:

```
rules/
  cve-YYYY-NNNN.yaml
  cve-YYYY-NNNN.py         # contains vulnerable code (comment: # ruleid: cve-YYYY-NNNN)
```

Vulnerable-code file:
```python
# ruleid: cve-YYYY-NNNN-ssti-myframework
render_to_string(template=request.args.get("tmpl"))

# ok: cve-YYYY-NNNN-ssti-myframework
render_to_string(template="fixed_template.html")
```

Run `semgrep --test rules/` to verify pass/fail markers match.

### 7. FP sanity check

Run the rule against a corpus of clean code (e.g., the fixed version of the affected library, or unrelated projects). Target: <5% FP rate on 10k+ LoC.

### 8. Publish / commit

File under `rules/cve/cve-YYYY-NNNN.yaml` with the test alongside. Add to your org's custom rule pack.

## Example CVE → rule conversions

### Example A: deserialization CVE

Advisory: `pickle.loads()` on user-controlled session data.

Patch: added HMAC verification before `pickle.loads`.

Rule:
```yaml
rules:
  - id: cve-YYYY-NNNN-unsafe-pickle
    patterns:
      - pattern: pickle.loads($DATA)
      - pattern-not-inside: |
          if hmac.compare_digest(...):
              ...
    message: "CVE-YYYY-NNNN: pickle.loads without signature verification"
    languages: [python]
    severity: ERROR
    metadata:
      cve: CVE-YYYY-NNNN
      cwe: CWE-502
```

### Example B: SSRF CVE via URL parsing

Advisory: `requests.get(url)` where `url` comes from user input without allowlist.

See `examples/semgrep_rules/ssrf.yaml` for a full template.

### Example C: algorithm-confusion CVE

Advisory: `jwt.decode(token, algorithms=["none"])` disables signature verification.

Rule:
```yaml
rules:
  - id: cve-YYYY-NNNN-jwt-none
    pattern-either:
      - pattern: jwt.decode($T, ..., algorithms=["none"], ...)
      - pattern: jwt.decode($T, ..., options={"verify_signature": False}, ...)
    message: "CVE-YYYY-NNNN: JWT signature verification disabled"
    languages: [python]
    severity: ERROR
    metadata:
      cve: CVE-YYYY-NNNN
      cwe: CWE-347
```

## Common mistakes

- Using `pattern: $FUNC(...)` with no constraints → matches every call.
- Forgetting that f-strings in Python are their own AST node — use `pattern: $CURSOR.execute(f"...{$X}...")`, not a regex.
- Writing a taint rule without `pattern-sanitizers` — floods findings.
- Omitting `metadata.cve` and `metadata.references` — destroys traceability.
