# Bug Bounty Patterns 2024-2026 — iac-security

## Overview

Post-2023 IaC misconfiguration patterns from HackingTheCloud, real-world healthcare incidents,
Helm chart audits, Terraform Cloud OIDC research, and industry forecasts (75% of security
failures projected to stem from IaC by end of 2025). Last validated: 2026-04.
Emit findings via `../schemas/finding.json`.

## Pattern Index

| #   | Pattern                                                   | Severity | Primary Source                              |
|-----|-----------------------------------------------------------|----------|---------------------------------------------|
| P26 | Terraform Cloud OIDC → arbitrary AWS IAM role assumption  | Critical | HackingTheCloud 2024-2025                   |
| P27 | Helm chart dev/prod securityContext parity drift          | High     | Dev.to / Helm best-practice 2026            |
| P28 | Unauthenticated Kubernetes API-server exposure            | Critical | Healthcare incident 2024                    |
| P29 | IaC shift-left correlation controls                       | Critical | Industry forecasts 2025                     |

---

## Patterns

### P26. Terraform Cloud OIDC → Arbitrary AWS IAM Role Assumption

- **CVE / Source:** HackingTheCloud "Exploiting Misconfigured Terraform Cloud OIDC AWS IAM Roles".
- **Summary:** Trust policies that bind to Terraform Cloud's OIDC issuer (`https://app.terraform.io`) often forget to constrain the `sub` claim (`organization:workspace:run_phase`), letting *any* Terraform Cloud workspace (including attacker-owned free-tier orgs) assume the AWS role.
- **Affected surface:** AWS IAM roles with `Principal.Federated: arn:aws:iam::…:oidc-provider/app.terraform.io`; GitHub Actions OIDC roles with similarly loose subject conditions; GitLab CI OIDC.
- **Detection (automated):**
  ```bash
  aws iam list-open-id-connect-providers
  aws iam list-roles --query 'Roles[?AssumeRolePolicyDocument!=`null`]' \
    --output json | jq -r '.[] | select(
      .AssumeRolePolicyDocument.Statement[]?.Principal.Federated // empty
      | tostring | test("terraform.io|token.actions.githubusercontent.com|gitlab"))
    | .RoleName'
  # For each, verify Condition.StringEquals/Like on token.actions.githubusercontent.com:sub
  # (or equivalent TFC claim)
  ```
- **Exploitation / PoC:**
  ```hcl
  # attacker TFC workspace in their org
  provider "aws" {
    assume_role_with_web_identity {
      role_arn                = "arn:aws:iam::VICTIM:role/TerraformAdmin"
      session_name            = "pwn"
      web_identity_token_file = "/dev/stdin"
    }
  }
  ```
- **Indicators:** CloudTrail `AssumeRoleWithWebIdentity` events from unrecognized workspace names; role assumption from org not matching internal TFC tenant.
- **Mitigation:** Constrain `sub` to specific `organization:foo:workspace:bar` + `run_phase:apply`; add `aud` check; pin role per workspace.
- **Cross-refs:** CWE-284, CWE-862; AWS IAM Best Practices; related → P14.

### P27. Helm Chart Dev/Prod securityContext Parity Drift

- **CVE / Source:** Helm security best-practices guidance 2025-2026; Checkov/KICS community rules.
- **Summary:** Teams ship a single Helm chart with permissive defaults (`privileged: true`, `allowPrivilegeEscalation: true`, `capabilities.add: [NET_ADMIN]`) for dev clusters, then apply the same values in production via hasty `helm upgrade`, inheriting all the escalation primitives.
- **Affected surface:** Helm charts with `values.yaml` defaults that are not locked down in `values-prod.yaml`; GitOps pipelines where `helm template` is not linted; multi-environment ArgoCD applications sharing base chart without overlays.
- **Detection (automated):**
  ```bash
  helm template . -f values-prod.yaml | checkov -d - --framework kubernetes \
    --check CKV_K8S_16,CKV_K8S_19,CKV_K8S_23,CKV_K8S_37
  # Compare dev vs prod rendered output:
  diff <(helm template . -f values-dev.yaml) <(helm template . -f values-prod.yaml) \
    | grep -E 'privileged|allowPrivilege|capabilities|hostPath|hostNetwork'
  ```
- **Exploitation / PoC:** A developer-friendly pod with `hostPath: /` and `privileged: true` lands in prod → attacker who reaches any exec on that pod escapes to node.
- **Indicators:** `kubectl get psa` / PodSecurity admission logs: prod namespace falling back to `privileged` profile; Checkov/KICS report delta dev ↔ prod.
- **Mitigation:** Enforce `PodSecurity` admission `restricted` per prod namespace; fail-closed admission webhook (Kyverno/OPA) on privileged specs; CI gate on rendered-chart linting.
- **Cross-refs:** CWE-732, CWE-250; related → P17, P20, P28.

### P28. Unauthenticated Kubernetes API-Server Exposure

- **CVE / Source:** Healthcare industry incident 2024; repeated HackerOne / shodan-sourced reports.
- **Summary:** Self-hosted clusters exposing `kube-apiserver` on `0.0.0.0:6443` without TLS-client-cert enforcement (anonymous auth enabled or webhook mis-fail-open) allow direct cluster control via a public endpoint — catastrophic data exposure.
- **Affected surface:** Bare-metal / on-prem K8s, kubeadm defaults with `--anonymous-auth=true`; dev clusters lifted into prod; cloud-managed clusters with public endpoint enabled and no CIDR allow-list.
- **Detection (automated):**
  ```bash
  # Anonymous read-only probe (never destructive)
  curl -sk https://target:6443/version
  curl -sk https://target:6443/api/v1/namespaces
  # If 200 without client cert → anonymous enabled.
  # IaC audit:
  grep -R '\-\-anonymous-auth=true\|authorization-mode=AlwaysAllow' .
  checkov -d . --framework terraform --check CKV_AWS_58,CKV_AWS_38,CKV_GCP_20
  ```
- **Exploitation / PoC:** Public disclosure shows listing of Pods, Secrets, and even patient PII via direct API calls — illustrative only; do not target unowned clusters.
- **Indicators:** Non-localhost hits on `/api`, `/apis`, `/openapi/v2` without `Authorization: Bearer`; API-server logs at `--v=4` showing anonymous group usage.
- **Mitigation:** `--anonymous-auth=false`; enforce mTLS; restrict control-plane endpoint to bastion/jumpbox CIDR; cloud providers: private endpoint + authorized networks.
- **Cross-refs:** CWE-306, CWE-287; CIS Kubernetes Benchmark §1.2.1; related → P20.

### P29. IaC Shift-Left Correlation Controls

- **CVE / Source:** Industry analyst forecasts 2025 — 75% of security failures linked to IaC misconfiguration by year-end.
- **Summary:** Not a single bug but a class of blind spots: same misconfiguration discovered in CI post-merge rather than pre-commit, or drifted at runtime, accounts for the lion's share of 2024-2025 cloud bounties. The pattern is "missing layered IaC scanning" itself.
- **Affected surface:** Teams that run `terraform validate` but no policy scan; teams without GitOps drift detection; teams that allow `terraform apply` without a PR gate.
- **Detection (automated):**
  - Enumerate the IaC-scan maturity per repo: pre-commit hook? CI job? PR gate? Runtime drift? Use the matrix below:
  ```text
  [ ] pre-commit: tflint / kics / checkov
  [ ] CI gate on PR: checkov --soft-fail false, tfsec --exit-code 1
  [ ] policy-as-code: OPA/Rego/Sentinel integrated with plan output
  [ ] runtime drift: cloudquery / driftctl daily; alert on delta
  [ ] post-apply attestation: SLSA-style provenance for IaC runs
  ```
  Gap in any row = concrete bounty-eligible finding in maturity-assessment scope.
- **Exploitation / PoC:** Not exploitation — control-maturity finding. Recommend missing layer + show before/after scan output.
- **Indicators:** Repo shows a misconfig introduced in commit N that a pre-commit hook would have blocked.
- **Mitigation:** Implement the five-row matrix; integrate Checkov / Terrascan / KICS / Kyverno; require signed-off policy exceptions.
- **Cross-refs:** NIST 800-53 CM-2, CM-6; related → P26, P27, P28.

---

## Cross-skill links
- Cloud: IAM privesc chains that IaC controls should prevent — `../../cloud-security/references/bounty_patterns_2024_2026.md`.
- Container: PSA / admission policies land as IaC — `../../container-security/references/bounty_patterns_2024_2026.md`.
- SCA: supply-chain Terraform modules — `../../sca-security/references/bounty_patterns_2024_2026.md`.
