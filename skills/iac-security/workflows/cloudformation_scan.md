# Workflow: CloudFormation Scan (cfn-lint + cfn-nag + Checkov)

Lint first, then security-scan. cfn-lint catches syntax/schema issues that produce noise in downstream security tools.

## When
- `.yaml` / `.json` / `.template` under a CFN-structured path
- PR gate on `cloudformation/**`
- Pre-deploy audit

## Prerequisites
```bash
pip install cfn-lint       # >= 1.0
gem install cfn-nag        # >= 0.8
pip install checkov        # >= 3.0
```

## Steps

### 1. Enumerate templates
```bash
CFN_DIR="${1:-.}"
mapfile -t TEMPLATES < <(find "$CFN_DIR" -type f \( -name "*.yaml" -o -name "*.yml" -o -name "*.template" -o -name "*.json" \))
OUT=/tmp/cfn-scan-$(date +%s); mkdir -p "$OUT"
```

### 2. Lint gate (sequential — must pass before security scans)
```bash
cfn-lint "${TEMPLATES[@]}" > "$OUT/cfn-lint.txt" 2>&1 || true
```
- If lint emits `E` errors: STOP. Fix schema/intrinsic issues first; security scanners will produce false negatives / crashes on malformed templates.
- `W` warnings are fine to carry into the security pass.

### 3. Security scanners (parallel)
```bash
(for T in "${TEMPLATES[@]}"; do
  cfn_nag_scan --input-path "$T" --output-format json
done) > "$OUT/cfn-nag.json" &

checkov -d "$CFN_DIR" --framework cloudformation -o json > "$OUT/checkov.json" &

wait
```

### 4. Optional: KICS for provider-specific depth
```bash
docker run --rm -v "$CFN_DIR":/path checkmarx/kics scan \
  -p /path -t CloudFormation -o /path --report-formats json > "$OUT/kics.json"
```

### 5. Parameter-aware re-scan
If the repo ships `parameters.json` per env, re-scan with each to catch env-specific exposures:
```bash
for P in parameters/*.json; do
  checkov -f template.yaml --var-file "$P" -o json \
    > "$OUT/checkov-$(basename "$P" .json).json"
done
```

### 6. Normalize + dedup
Map all findings to `schemas/finding.json` with `iac_type: cloudformation`. cfn-nag uses `FAIL`/`WARN` — see `references/severity_mapping.md`.

### 7. Report + fix loop
- Group findings by logical resource (`Resources.<LogicalId>`).
- For each `FAIL`/`CRITICAL`: produce a remediation snippet with the specific property (e.g. `BucketEncryption`, `PubliclyAccessible`).
- Re-run Steps 2–4 after each commit.

## Exit criteria
- cfn-lint: no `E` errors
- cfn-nag: zero `FAIL`
- Checkov: zero `CRITICAL`, no undocumented `HIGH`
