---
name: iac-security
description: "Infrastructure-as-Code security scanning router for Terraform, CloudFormation, Kubernetes manifests, Helm, ARM/Bicep. Orchestrates Checkov, tfsec, Terrascan, KICS, kubesec, kube-linter, Polaris, cfn-lint/cfn-nag, and OPA/Conftest. Use when auditing IaC for misconfigurations, scanning Terraform plans, validating K8s security policies, checking cloud infrastructure compliance, or authoring custom policy-as-code (Rego)."
---

# Infrastructure as Code Security

Thin router for IaC static analysis. Pick the right workflow, run scanners in parallel, aggregate findings into `schemas/finding.json`, and (where org controls demand it) author Rego policies via the policy-as-code loop. Detailed per-stack commands and rule references live under `references/`; multi-step runbooks live under `workflows/`.

## When to Use
- Scan Terraform `.tf` / plan JSON for misconfigurations
- Audit CloudFormation YAML/JSON templates
- Validate Kubernetes manifests (incl. rendered Helm / kustomize)
- Validate Helm charts pre- and post-render
- Scan ARM / Bicep templates for Azure misconfigurations
- Verify CIS benchmark compliance across AWS / Azure / GCP / K8s
- Integrate IaC scanning into PR gates or pre-commit hooks
- Author custom OPA/Rego policies for org-specific controls

## Trigger Phrases
- "scan this Terraform / audit my CloudFormation / check Kubernetes manifests"
- "validate Helm chart security" · "IaC security scan" · "infrastructure compliance"
- "write a Rego policy for X" · "add Conftest rule for Y"

## When NOT to Use This Skill
- **Runtime cloud assessment** (live AWS/Azure/GCP accounts, IAM policies in force, runtime resource state) → use `cloud-security`.
- **Container image CVE scanning, admission control at runtime, cluster live scans** → use `container-security`.
- **Secrets discovery in a codebase** → use `secrets-scanning` (pair with this skill for IaC files that contain secrets).
- **Application source-code SAST** → use `code-security` / `sast`.
- **Pure drift detection vs deployed state** — not in scope; use Terraform Cloud / Driftctl / AWS Config.

## Decision Tree
```
What file(s)?
├── .tf / .tf.json / tfplan.json   → workflows/terraform_scan.md
├── CFN .yaml/.json/.template      → workflows/cloudformation_scan.md
├── K8s manifests (Deployment/etc) → workflows/kubernetes_manifest_scan.md
├── Helm chart (Chart.yaml)        → references/helm.md  (render → K8s workflow)
├── ARM / .bicep                   → references/arm_bicep.md
└── Need a custom org rule?        → workflows/policy_as_code_loop.md
```

If the target mixes types (monorepo), fan out: run every applicable workflow in parallel, then merge findings with `iac_type` as the disambiguator.

## Parallelism Hints
Run concurrently (no shared state, all read-only):
- Checkov + tfsec + Terrascan on the same Terraform dir
- cfn-lint (first, as a gate) → then cfn-nag + Checkov + KICS in parallel
- kubesec + kube-linter + Polaris + Checkov on K8s manifests
- One sub-agent per IaC type when a monorepo contains multiple

Must be sequential:
- `terraform init && terraform plan && terraform show -json` BEFORE plan-based Checkov scan
- `helm template` / `kustomize build` BEFORE manifest scanners
- `cfn-lint` error gate BEFORE CFN security scanners (malformed templates poison the rest)
- Findings aggregation + dedup AFTER all scanners complete

## Sub-Agent Delegation
Spawn sub-agents for:
- **One per scanner** (Checkov / tfsec / Terrascan / KICS) in large Terraform repos — each owns its own output file, main agent aggregates.
- **One per IaC type** in monorepos (TF sub-agent, K8s sub-agent, CFN sub-agent).
- **Dedicated policy-author sub-agent** for `workflows/policy_as_code_loop.md` — it carries full context on Rego idioms and the PASS/FAIL fixture discipline.
- **Dedicated aggregator sub-agent** to read all scanner JSON outputs, apply `references/severity_mapping.md`, and emit the unified report.

Do NOT parallelize across sub-agents when one workflow must gate another (e.g. cfn-lint → cfn-nag).

## Reasoning Budget
- **Extended thinking ON**: writing custom Rego, interpreting cross-tool disagreements (e.g. Checkov CRITICAL + tfsec MEDIUM on the same resource), deciding whether a suppression is legitimate, designing fixture pairs.
- **Extended thinking OFF**: running scanners, parsing their JSON, applying the severity mapping table, formatting the report, file-system operations.

## Multimodal Hooks
- Accept architecture diagrams (PNG / PDF) as context when reasoning about network boundaries and expected exposure — useful to decide whether a `0.0.0.0/0` SG rule is actually the desired public edge.
- If the user pastes a screenshot of a scanner UI / dashboard finding, read the rule ID and resource from the image and route to the matching reference.

## Structured Output
All findings MUST conform to `schemas/finding.json`. Key IaC-specific fields: `iac_file`, `iac_type`, `resource_type`, `resource_name`, `tool`, `rule_id`, `cis_benchmark_id`, `normalized_severity`. Dedup on `(iac_file, resource_type, resource_name, category)` keeping highest normalized severity.

## Quick-Start Commands
Minimal first pass per stack — use as a smoke test before invoking a full workflow:
```bash
# Terraform
checkov -d . --framework terraform -o json > /tmp/ckv.json
tfsec . --format json                     > /tmp/tfs.json

# CloudFormation (lint gate → security)
cfn-lint templates/*.yaml && checkov -d templates/ --framework cloudformation

# Kubernetes manifests
kube-linter lint ./k8s --format json > /tmp/kl.json
checkov -d ./k8s --framework kubernetes

# Helm — render first
helm template myrel ./chart -f values-prod.yaml | checkov -f - --framework kubernetes

# ARM / Bicep
checkov -d ./arm --framework arm

# Conftest (custom org rules)
conftest test <target> -p policy/
```

## Triage Cheatsheet
Highest-impact finding families — fix these before anything else:
1. **Public network ingress** on admin ports (SSH/RDP/DB) — security groups, NSGs, NACLs with `0.0.0.0/0` or `::/0` → sev=`critical`.
2. **Public data stores** — S3 public-read, Azure storage `allowBlobPublicAccess`, RDS/CosmosDB `publicly_accessible` → sev=`critical`.
3. **Wildcard IAM** — `Action: "*"` with `Resource: "*"` in AWS IAM / Azure role / GCP IAM binding → sev=`critical`.
4. **Unencrypted at-rest** — S3/EBS/RDS/Azure Storage without SSE or CMK; KMS without rotation → sev=`high`.
5. **Privileged / hostPath / hostNetwork pods** — container escape / node-level blast radius → sev=`high`.
6. **Missing audit trails** — CloudTrail disabled, Azure Activity Log export off, VPC flow logs missing → sev=`high`.
7. **Hardcoded secrets** in IaC — re-route to `secrets-scanning` skill, keep a breadcrumb in this report.

Everything else (tagging, versioning, lifecycle, resource hygiene) queues behind the above.

## Workflow Index
| Workflow | File | Use when |
|----------|------|----------|
| Terraform scan | `workflows/terraform_scan.md` | Any `.tf` change or TF repo audit |
| CloudFormation scan | `workflows/cloudformation_scan.md` | CFN templates (lint → security) |
| Kubernetes manifest scan | `workflows/kubernetes_manifest_scan.md` | Raw K8s / rendered Helm / kustomize |
| Policy-as-code loop | `workflows/policy_as_code_loop.md` | Authoring custom OPA/Rego rules |

## Examples Index
| File | Purpose |
|------|---------|
| `examples/opa_rego_templates.md` | Starter Rego for common org controls (K8s, TF, CFN) |
| `examples/vulnerable_terraform.tf` | Intentionally-misconfigured fixture for scanner / Rego regression tests |

## References Index
| File | Contents |
|------|----------|
| `references/terraform.md` | Checkov / tfsec / Terrascan commands, misconfig catalog, custom checks |
| `references/cloudformation.md` | Checkov / cfn-lint / cfn-nag / KICS commands + CFN checklist |
| `references/kubernetes_manifests.md` | kubesec / Checkov / Trivy / kube-linter / Polaris + K8s checklist |
| `references/helm.md` | Render-vs-direct scanning, Chart.yaml hygiene, pluto for deprecated APIs |
| `references/arm_bicep.md` | Checkov / KICS / PSRule for Azure + ARM/Bicep checklist |
| `references/severity_mapping.md` | Per-tool → normalized severity table, dedup key, category buckets |
| `references/ci_cd_integration.md` | GitHub Actions / GitLab CI / pre-commit wiring, gate policy guidance |
| `references/bounty_patterns_2024_2026.md` | Post-2023 bounty TTPs (Terraform OIDC AWS trust misconfig, Helm dev/prod parity drift, unauth kube-apiserver exposure, shift-left maturity gaps) |

## Tools
| Tool | Purpose | Install |
|------|---------|---------|
| Checkov | Multi-framework IaC scanner | `pip install checkov` |
| tfsec | Terraform security scanner | `brew install tfsec` |
| Terrascan | Multi-cloud IaC scanner | `brew install terrascan` |
| KICS | Keeping IaC Secure (Checkmarx) | `docker pull checkmarx/kics` |
| kubesec | K8s manifest scoring | `brew install kubesec` |
| kube-linter | K8s rule library | `go install golang.stackrox.io/kube-linter/cmd/kube-linter@latest` |
| Polaris | Opinionated K8s workload checks | `brew install fairwinds/tap/polaris` |
| cfn-lint | CFN schema/intrinsic lint | `pip install cfn-lint` |
| cfn-nag | CFN security scanner | `gem install cfn-nag` |
| Trivy | Config scanning (IaC mode) | `brew install trivy` |
| OPA / Conftest | Policy-as-code | `brew install opa conftest` |
| Regal | Rego linter | `brew install regal` |
| pluto | Deprecated K8s API detection | `brew install FairwindsOps/tap/pluto` |

## Last Validated
2026-04. Minimum versions: Checkov ≥ 3.0, tfsec ≥ 1.28, Terrascan ≥ 1.19, Conftest ≥ 0.50, OPA ≥ 0.62, kube-linter ≥ 0.6, Polaris ≥ 9.0, cfn-lint ≥ 1.0, Trivy ≥ 0.50.
