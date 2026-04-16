# Workflow: Terraform Scan (Checkov + tfsec + Terrascan)

Orchestrate three scanners concurrently, then aggregate and dedup.

## When
- Any `.tf` / `.tf.json` change
- Pre-merge PR gate on a Terraform repo
- Full audit of an existing Terraform codebase

## Prerequisites
```bash
pip install checkov        # >= 3.0
brew install tfsec         # >= 1.28
brew install terrascan     # >= 1.19
```

## Steps

### 1. Establish scan target
```bash
TF_DIR="${1:-.}"
OUT=/tmp/iac-scan-$(date +%s)
mkdir -p "$OUT"
```

### 2. Run all three in parallel
Spawn each as a background job (or delegate one sub-agent per scanner — see `Sub-Agent Delegation` in SKILL.md).

```bash
checkov -d "$TF_DIR" --framework terraform -o json > "$OUT/checkov.json" 2>"$OUT/checkov.err" &
PID_CK=$!

tfsec "$TF_DIR" --format json > "$OUT/tfsec.json" 2>"$OUT/tfsec.err" &
PID_TS=$!

terrascan scan -t terraform -d "$TF_DIR" -o json > "$OUT/terrascan.json" 2>"$OUT/terrascan.err" &
PID_TR=$!

wait $PID_CK $PID_TS $PID_TR
```

Guardrails:
- Non-zero exit from a scanner when findings exist is NORMAL — don't abort aggregation.
- If stderr contains "plugin not found" or "version mismatch" → stop and fix tooling before trusting results.

### 3. Optional: plan-based scan for higher fidelity
```bash
terraform -chdir="$TF_DIR" init -backend=false
terraform -chdir="$TF_DIR" plan -out=tfplan.binary
terraform -chdir="$TF_DIR" show -json tfplan.binary > "$OUT/tfplan.json"
checkov -f "$OUT/tfplan.json" -o json > "$OUT/checkov-plan.json"
```
Plan-based scans resolve dynamic values (count/for_each, variable defaults) that static HCL scans miss.

### 4. Normalize + dedup
For each scanner output, map to `schemas/finding.json`:
- `tool` ← scanner name
- `rule_id` ← `check_id` (Checkov) / `rule_id` (tfsec) / `rule_id` (Terrascan)
- `iac_type` ← `terraform`
- `resource_type`, `resource_name` ← extracted per scanner's JSON shape
- `normalized_severity` ← apply table in `references/severity_mapping.md`

Dedup key: `(iac_file, resource_type, resource_name, category)` — keep highest severity, retain all `rule_id`s.

### 5. Emit report
- SARIF: aggregate into one `findings.sarif` for PR annotations.
- Markdown: group by category (encryption / iam / network / logging / …) with severity counts.

### 6. Validate fixes
Re-run the three scanners after each remediation commit. If a remediation fixes the resource but a scanner still reports: check for an outdated `--skip-check` or a misparsed multi-file module.

## Exit criteria
- Zero `critical` findings (hard gate)
- Zero `high` findings without documented suppressions (soft gate — configurable)
- All suppressions have a justification comment

## Parallel structure
```
        ┌─> checkov  ──┐
scan ──>├─> tfsec    ──┼─> aggregate ─> dedup ─> report
        └─> terrascan ─┘
```
Scanners are read-only and have no ordering dependency; always run concurrently.
