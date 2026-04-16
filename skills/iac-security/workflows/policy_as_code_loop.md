# Workflow: Policy-as-Code Development Loop (OPA / Conftest / Rego)

Iterative loop for writing and validating custom Rego policies against IaC fixtures. This is the HIGH-VALUE workflow for frontier coding agents: with 2-3 examples, modern models reliably author valid Rego.

## When
- Org-specific compliance rule not covered by Checkov/tfsec/Terrascan defaults
- Converting a written control ("all S3 buckets must have `DataClassification` tag") into automation
- Migrating legacy security reviews into CI gates

## Prerequisites
```bash
brew install conftest                                      # >= 0.50
brew install opa                                           # >= 0.62
# Optional: regal for Rego linting
brew install regal
```

## Loop (repeat per rule)

### 1. Draft rule from natural-language control
Capture the control. Example: *"Kubernetes Deployments must not mount the service account token unless annotated with `needs-sa-token: true`."*

Produce `policy/k8s/sa_token.rego`:
```rego
package main

deny[msg] {
  input.kind == "Deployment"
  input.spec.template.spec.automountServiceAccountToken != false
  annotations := object.get(input.spec.template.metadata, "annotations", {})
  annotations["needs-sa-token"] != "true"
  msg := sprintf(
    "Deployment %s mounts SA token without 'needs-sa-token=true' annotation",
    [input.metadata.name]
  )
}
```

Key Rego idioms to include in prompts:
- `package main` + `deny[msg]` is the Conftest convention.
- `object.get(obj, "key", default)` avoids undefined-value traps.
- `some x in coll` (Rego v1) or `coll[_]` (older) for iteration.
- Rules are ANDs of the body conditions; OR = multiple rules with the same head.

### 2. Build a fixture pair
Create PASS and FAIL fixtures side-by-side:

```yaml
# fixtures/pass.yaml  — should NOT produce deny
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
spec:
  template:
    metadata:
      annotations:
        needs-sa-token: "true"
    spec:
      containers: [{name: api, image: api:1}]
```

```yaml
# fixtures/fail.yaml  — should produce deny
apiVersion: apps/v1
kind: Deployment
metadata: {name: api}
spec:
  template:
    metadata: {}
    spec:
      containers: [{name: api, image: api:1}]
```

### 3. Test the rule
```bash
conftest test fixtures/pass.yaml -p policy/     # exit 0 expected
conftest test fixtures/fail.yaml -p policy/     # exit 1 expected, denial msg shown
```

If the outcome is wrong, go to step 4. Otherwise → step 5.

### 4. Debug with trace + opa eval
```bash
# Full trace
conftest test fixtures/fail.yaml -p policy/ --trace

# Ad-hoc query
opa eval --data policy/ --input fixtures/fail.yaml 'data.main.deny'

# Interactive REPL
opa run policy/
> data.main.deny with input as <paste>
```

Common Rego bugs frontier models still make:
1. `!= false` vs `not ... == false` — Rego falsy rules are subtle; prefer explicit equality.
2. Undefined is NOT false. `input.x.y` where `x` absent → undefined, not false; the whole rule body fails silently.
3. Using `==` in iteration where `=` (unification) is needed.
4. Forgetting `import future.keywords.in` in pre-v1 deployments.

### 5. Add unit tests
Rego natively supports tests. Create `policy/k8s/sa_token_test.rego`:
```rego
package main

test_deny_when_annotation_missing {
  deny[_] with input as {"kind": "Deployment",
                         "metadata": {"name": "x"},
                         "spec": {"template": {"metadata": {},
                                               "spec": {"containers": [{"name": "c"}]}}}}
}

test_allow_when_annotation_true {
  count(deny) == 0 with input as {"kind": "Deployment",
                                  "metadata": {"name": "x"},
                                  "spec": {"template": {"metadata": {"annotations": {"needs-sa-token": "true"}},
                                                        "spec": {"containers": [{"name": "c"}]}}}}
}
```

Run:
```bash
opa test policy/ -v
```

### 6. Lint
```bash
regal lint policy/
```
Regal catches style/perf issues and common semantic bugs.

### 7. Integrate into CI
Add to the relevant scan workflow (`workflows/terraform_scan.md`, `workflows/kubernetes_manifest_scan.md`):
```bash
conftest test <target> -p policy/
```

Fail-closed: any `deny[_]` → PR blocked.

## Rule catalog skeleton

Organize by IaC type:
```
policy/
  terraform/
    s3_encryption.rego
    s3_encryption_test.rego
  k8s/
    sa_token.rego
    sa_token_test.rego
  cloudformation/
    iam_wildcard.rego
    ...
```

Starter snippets for common controls live in `examples/opa_rego_templates.md`.

## Reasoning budget guidance

- **Extended thinking ON** for: authoring the rule from a written control; interpreting multi-rule interactions; debugging unexpected `undefined`.
- **Extended thinking OFF** for: running `conftest test`, running `opa test`, assembling fixtures from existing examples.
