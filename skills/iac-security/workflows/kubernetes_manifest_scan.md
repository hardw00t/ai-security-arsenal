# Workflow: Kubernetes Manifest Scan (kubesec + kube-linter + Polaris)

Three scanners with different strengths: kubesec = scoring, kube-linter = deep rule library, Polaris = opinionated workload checks.

## When
- Raw K8s manifests (`Deployment`, `StatefulSet`, `DaemonSet`, `Pod`, etc.)
- kustomize overlays (render first)
- Helm charts (render first — see `workflows/terraform_scan.md` pattern, use `helm template`)

For runtime cluster scans or image CVEs, use the `container-security` skill.

## Prerequisites
```bash
brew install kubesec                                      # >= 2.14
go install golang.stackrox.io/kube-linter/cmd/kube-linter@latest
brew install fairwinds/tap/polaris                        # >= 9.0
pip install checkov                                       # optional 4th scanner
```

## Steps

### 1. Materialize manifests
```bash
MANIFEST_DIR="${1:-./k8s}"
OUT=/tmp/k8s-scan-$(date +%s); mkdir -p "$OUT"

# If kustomize
kustomize build overlays/prod > "$OUT/rendered.yaml"

# If Helm
helm template myrel ./chart -f values-prod.yaml > "$OUT/rendered.yaml"

# Otherwise just point at the directory
```

### 2. Run scanners in parallel
```bash
# kubesec — per-file because it wants a single doc at a time
(find "$MANIFEST_DIR" -name '*.yaml' -print0 \
  | xargs -0 -P4 -I{} kubesec scan {} -o json) > "$OUT/kubesec.json" &

kube-linter lint "$MANIFEST_DIR" --format json > "$OUT/kube-linter.json" 2>"$OUT/kube-linter.err" &

polaris audit --audit-path "$MANIFEST_DIR" --format json --only-show-failed-tests \
  > "$OUT/polaris.json" 2>"$OUT/polaris.err" &

checkov -d "$MANIFEST_DIR" --framework kubernetes -o json > "$OUT/checkov.json" 2>&1 &

wait
```

### 3. Normalize findings
Map to `schemas/finding.json` with `iac_type: kubernetes`:
- `resource_type`: `kind` from the manifest (`Deployment`, `Service`, …)
- `resource_name`: `metadata.namespace` + `metadata.name`
- `rule_id`: per-scanner (`CKV_K8S_*`, kube-linter check name, Polaris check name)
- `normalized_severity`: apply `references/severity_mapping.md`

Dedup key: `(manifest_path, kind, namespace/name, category)`.

### 4. Opinion merging
When kubesec says `passed` but kube-linter flags the same pod as `privileged-containers`, kube-linter wins — kubesec is intentionally lenient on some rules. Document per-team overrides in a `.iac-policy.yaml` consumed by the aggregator.

### 5. Policy gate with Conftest (optional)
Apply team-authored Rego on top:
```bash
conftest test "$MANIFEST_DIR" -p policy/
```
See `workflows/policy_as_code_loop.md` for rule authoring.

### 6. Report
- Group by namespace + workload.
- Highlight pod security context failures (runAsNonRoot, readOnlyRootFilesystem, capabilities.drop) first — these have highest blast radius.

## Exit criteria
- kube-linter: zero HIGH-severity checks firing
- Polaris: zero `danger`
- Checkov: zero `CRITICAL`
- Conftest: all policies pass
