# Workflow: Multi-Tool SAST Scan

Run Semgrep + CodeQL + language-specific tools against one codebase concurrently, then aggregate and deduplicate.

## When to run this

- Initial audit of an unfamiliar codebase.
- Periodic security gate (weekly / release-gate).
- Whenever a single tool's coverage is known-incomplete.

## Parallelism map

```
          ┌────────────────────────────────────────────────┐
START ──► │  launch in parallel (independent) :            │
          │    - Semgrep       (source only)               │
          │    - Bandit        (Python, source)            │
          │    - gosec         (Go, source)                │
          │    - Brakeman      (Rails, source)             │
          │    - ESLint-sec    (JS/TS, source)             │
          │    - Gitleaks      (secrets, source)           │
          │    - CodeQL DB create per language (parallel)  │
          └────────────────────────────────────────────────┘
                          │
                          ▼  (DB-create finishes, THEN analyze)
          ┌────────────────────────────────────────────────┐
          │  CodeQL analyze per DB (parallel across langs) │
          └────────────────────────────────────────────────┘
                          │
                          ▼  (all SARIF collected)
          ┌────────────────────────────────────────────────┐
          │  Aggregate + dedup + rank (single triage agent)│
          └────────────────────────────────────────────────┘
```

Hard sequencing rules:
1. CodeQL `database create` MUST complete before `database analyze` for that language.
2. SpotBugs requires the project to be compiled first (`mvn compile`).
3. Aggregation must wait for all tools — do NOT start triage with partial data.

## Sub-agent delegation pattern

Spawn one sub-agent per tool for scanning; each returns a SARIF path + summary stats. Spawn a single aggregator/triage agent that consumes all SARIF outputs. This keeps each sub-agent's context small and lets them run wall-clock concurrent.

Minimal delegation template (per tool):
```
Task: Run <TOOL> against <REPO_PATH> and emit SARIF to <OUTPUT_DIR>/<tool>.sarif.
Report: output path, finding count by severity, any tool errors.
Do NOT triage; do NOT read results in detail.
```

Aggregator template:
```
Task: Read all SARIF files in <OUTPUT_DIR>/*.sarif, normalize to schemas/finding.json,
deduplicate by (cwe, file_path, line±3), then hand off to triage.md.
```

## Reasoning budget

- Per-tool scan sub-agents: MINIMAL thinking. These are mechanical.
- Aggregation: LOW thinking (dedup keys are well-defined).
- Triage (separate workflow): MAXIMUM thinking — see `triage.md`.

## Runbook

### 1. Detect languages

```bash
# Quick language census
(cd "$REPO" && {
  find . -type f -name '*.py'   | head -1 && echo "-> python"
  find . -type f -name '*.go'   | head -1 && echo "-> go"
  find . -type f -name '*.rb'   | head -1 && echo "-> ruby"
  find . -type f -name '*.java' | head -1 && echo "-> java"
  find . -type f \( -name '*.js' -o -name '*.ts' \) | head -1 && echo "-> javascript"
  find . -type f -name '*.php'  | head -1 && echo "-> php"
})
```

### 2. Launch scans in parallel

Use `scripts/sast_scan.sh` as the reference implementation. Per-tool invocations:

```bash
# always-on (language-agnostic)
semgrep --config=auto --config=p/security-audit --config=p/secrets \
        --sarif -o "$OUT/semgrep.sarif" "$REPO" &

gitleaks detect --source="$REPO" --report-path="$OUT/gitleaks.sarif" \
        --report-format=sarif &

# per detected language
bandit -r "$REPO" -f sarif -o "$OUT/bandit.sarif" -ll -ii &
gosec -fmt=sarif -out="$OUT/gosec.sarif" "$REPO/..." &
brakeman "$REPO" -f sarif -o "$OUT/brakeman.sarif" &
npx eslint --format @microsoft/eslint-formatter-sarif \
           --output-file "$OUT/eslint.sarif" "$REPO/src" &

# CodeQL: create + analyze per language (sequenced per-lang, parallel across langs)
for lang in python javascript java go ruby; do
  (
    codeql database create "$OUT/codeql-$lang" --language=$lang --source-root="$REPO" &&
    codeql database analyze "$OUT/codeql-$lang" \
      "codeql/${lang}-queries:codeql-suites/${lang}-security-extended.qls" \
      --format=sarif-latest --output="$OUT/codeql-$lang.sarif"
  ) &
done

wait
```

### 3. Aggregate

Use `scripts/aggregate_results.py` (bundled). Output is a normalized JSON array matching `schemas/finding.json`.

Dedup key: `(normalized_cwe, file_path, line ± 3)`. Record duplicates in `duplicate_of[]` rather than discarding — multiple tool confirmation raises confidence.

### 4. Hand off to triage

Pass the normalized findings list to the triage workflow (`triage.md`). Do NOT attempt severity ranking during aggregation — that requires reachability analysis.

## Output contract

- `$OUT/*.sarif` — raw per-tool outputs
- `$OUT/findings.json` — normalized array (schemas/finding.json)
- `$OUT/summary.md` — counts by tool, severity, CWE
