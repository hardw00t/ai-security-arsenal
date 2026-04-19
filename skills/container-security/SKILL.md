---
name: container-security
description: "Container and Kubernetes security assessment — image vulnerability scanning, SBOM diff analysis, K8s cluster auditing, RBAC privilege mapping, NetworkPolicy review, container escape testing, and runtime monitoring (Falco/Tetragon). Use when scanning Docker/OCI images, auditing K8s clusters, reviewing Dockerfiles, diffing SBOMs across releases, analyzing RBAC, or assessing container runtime posture. Triggers on requests involving Trivy, Grype, Syft, Kubescape, kube-bench, Falco, container escapes, or CIS Docker/K8s benchmarks."
---

# Container Security

Thin router for container and Kubernetes security assessments. Load the
reference, workflow, or payload file you need — do not read all of them.

## When to Use

- Scanning Docker/OCI images for CVEs (single image or pipeline)
- Generating or attesting SBOMs (Syft / CycloneDX / SPDX)
- **Diffing SBOMs across releases to flag newly-introduced CVEs**
- Auditing a live Kubernetes cluster (CIS / NSA / MITRE)
- Mapping K8s RBAC and finding privilege-escalation paths
- Reviewing NetworkPolicy coverage
- Authoring Falco / Tetragon runtime rules
- Analyzing or testing container escape vectors (authorized only)
- Docker daemon / host hardening review

## Trigger Phrases

"scan this image", "trivy / grype / syft", "audit k8s cluster",
"kube-bench", "kubescape", "run CIS benchmark", "check RBAC",
"networkpolicy coverage", "falco rule", "container escape",
"SBOM diff", "new CVEs since last release".

## When NOT to Use This Skill

| Request                                                         | Use instead       |
|-----------------------------------------------------------------|-------------------|
| Static scan of K8s YAML / Helm / Kustomize **before deploy**    | `iac-security`    |
| Terraform / CloudFormation / Pulumi misconfig                   | `iac-security`    |
| EKS / GKE / AKS control-plane or managed-service misconfig      | `cloud-security`  |
| Cloud IAM misconfiguration (beyond K8s RBAC)                    | `cloud-security`  |
| Application-code vulns inside the container                     | `sast-orchestration` |
| Third-party library CVEs at source-code level                   | `sca-security`    |
| API endpoints exposed by containerized services                 | `api-security`    |

Rule of thumb: **pre-deployment YAML → iac-security; running cluster or
built image → this skill.**

## Decision Tree

```
Target?
|
|-- Built/registry image ----------> workflows/image_scan.md
|     \-- two images to compare? --> workflows/sbom_diff.md    (FLAGSHIP)
|
|-- Dockerfile source -------------> examples/vulnerable_dockerfile.md
|                                    + hadolint (references/image_scanning.md)
|
|-- Live K8s cluster --------------> workflows/cluster_audit.md
|     |-- RBAC deep-dive ----------> workflows/rbac_analysis.md
|     |-- Network policy gap ------> workflows/network_policy_review.md
|     \-- CIS benchmark only ------> references/kubernetes_hardening.md
|
|-- Runtime monitoring ------------> references/runtime_security.md
|                                    + examples/falco_custom_rule.yaml
|
\-- Escape testing (authorized) --> references/container_escape.md
                                     + payloads/container_escape_poc.md
```

## Parallelism Hints

Run concurrently (no shared state, no rate conflicts):

- **Trivy + Grype + Syft + Hadolint on the same image** — always parallel
- **Scanners across multiple image tags** — one sub-agent per tag
- **kube-bench across nodes** — deploy as DaemonSet, collect in parallel
- **Kubescape frameworks** (nsa, mitre, cis) — parallel invocations
- **RBAC object fetches** (`clusterroles`, `roles`, bindings) — parallel
- **SBOM diff Grype scans** (prior vs current) — parallel
- **Per-principal RBAC graph expansion** — parallel (stateless)

Sequential only:

- Cosign attestation (needs SBOM first)
- Cross-scanner CVE consensus merge (needs all scanner outputs)
- Finding emission (needs evaluated data)

## Sub-Agent Delegation

- **Multi-image pipeline**: spawn one sub-agent per image; each runs
  `workflows/image_scan.md` and returns finding records. Parent merges.
- **Multi-cluster environment**: one sub-agent per cluster; each runs
  `workflows/cluster_audit.md` with its own kubecontext.
- **Cluster audit fan-out**: parent runs inventory, then spawns sub-agents
  for `rbac_analysis`, `network_policy_review`, and runtime log triage in
  parallel.
- **SBOM diff per service**: one sub-agent per service in a monorepo
  release; parent aggregates the "newly-introduced CVEs" roll-up.

## Reasoning Budget

| Task                                                    | Budget              |
|---------------------------------------------------------|---------------------|
| Running a scanner and capturing output                  | Minimal             |
| Applying CIS checks, filling checklists                 | Minimal             |
| SBOM canonicalization and package diff                  | Minimal             |
| Cross-scanner CVE consensus                             | Moderate            |
| RBAC privilege-graph traversal (principal -> cluster-admin) | **Extended**    |
| Container escape chain composition                      | **Extended**        |
| SBOM diff CVE exposure scoring + waiver decision        | **Extended**        |
| Runtime alert triage (chaining Falco events to intent)  | Moderate            |

Extended thinking pays off where the answer requires composing many small
facts into an attack path or risk decision; it does not help when running
a scanner and reporting output verbatim.

## Multimodal Hooks

- **Image layer histograms** — attach Syft/Dive output screenshots to
  evidence for bloat/secret-layer findings.
- **RBAC graphs** — `rbac-tool viz` produces graphviz; render as PNG and
  embed in report for stakeholder clarity.
- **Falco/Tetragon alert screenshots** — useful for runtime-detection
  evidence bundles.

## Structured Output

All findings MUST conform to [`schemas/finding.json`](schemas/finding.json).

Container-security-specific fields: `affected.image_digest`,
`affected.image_tag`, `affected.cluster_name`, `affected.namespace`,
`affected.resource_kind`, `affected.service_account`, `cve`, `cvss`,
`fixed_version`, `cis_control`, and the `sbom_diff` block for diff
findings.

## Workflow Index

| Workflow                                                   | Purpose |
|------------------------------------------------------------|---------|
| [`workflows/image_scan.md`](workflows/image_scan.md)       | Build-time / registry image vuln scan with consensus merge |
| [`workflows/sbom_diff.md`](workflows/sbom_diff.md)         | **Flagship.** Compare prior vs current SBOM; flag new CVEs |
| [`workflows/cluster_audit.md`](workflows/cluster_audit.md) | Live K8s cluster assessment (CIS / NSA / MITRE)             |
| [`workflows/rbac_analysis.md`](workflows/rbac_analysis.md) | RBAC privilege mapping and attack-path search               |
| [`workflows/network_policy_review.md`](workflows/network_policy_review.md) | NetworkPolicy coverage + enforcement validation |

## Payloads Index

| Payload                                                                   | Purpose |
|---------------------------------------------------------------------------|---------|
| [`payloads/container_escape_poc.md`](payloads/container_escape_poc.md)    | Documented escape PoCs (authorized testing only) |

## References Index

| Reference                                                                     | Purpose |
|-------------------------------------------------------------------------------|---------|
| [`references/image_scanning.md`](references/image_scanning.md)                | Trivy, Grype, Syft, Clair, Snyk, Hadolint commands |
| [`references/kubernetes_hardening.md`](references/kubernetes_hardening.md)    | kube-bench, Kubescape, CIS K8s mapping, PSS        |
| [`references/container_escape.md`](references/container_escape.md)            | Escape vectors, capabilities, runtime CVEs         |
| [`references/runtime_security.md`](references/runtime_security.md)            | Falco, Tetragon, eBPF, rule authoring              |
| [`references/bounty_patterns_2024_2026.md`](references/bounty_patterns_2024_2026.md) | Post-2023 bounty TTPs (CVE-2024-21626 runC, CVE-2025-23266 NVIDIA, SA token theft, RoleBinding privesc) |

## Examples Index

| Example                                                                          | Purpose |
|----------------------------------------------------------------------------------|---------|
| [`examples/falco_custom_rule.yaml`](examples/falco_custom_rule.yaml)             | Ready-to-load Falco rule pack |
| [`examples/vulnerable_dockerfile.md`](examples/vulnerable_dockerfile.md)         | Common Dockerfile anti-patterns + fixes |

## Templates Index

| Template                                                                                                   | Purpose |
|------------------------------------------------------------------------------------------------------------|---------|
| [`templates/assessment_report_template.md`](templates/assessment_report_template.md) | End-of-engagement deliverable skeleton |

## Tools

| Tool         | Purpose                       | Install                                       |
|--------------|-------------------------------|-----------------------------------------------|
| Trivy        | Image / FS vuln + SBOM + IaC  | `brew install trivy`                          |
| Grype        | Image / SBOM vuln             | `brew install grype`                          |
| Syft         | SBOM generator                | `brew install syft`                           |
| Hadolint     | Dockerfile lint               | `brew install hadolint`                       |
| Kubescape    | K8s security platform         | `curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh \| /bin/bash` |
| kube-bench   | CIS K8s benchmark             | `brew install kube-bench`                     |
| kube-hunter  | K8s pentest recon             | `pip install kube-hunter`                     |
| Falco        | Runtime security (eBPF)       | Helm chart `falcosecurity/falco`              |
| Tetragon     | eBPF detection + enforcement  | Helm chart `cilium/tetragon`                  |
| Docker Bench | Docker CIS benchmark          | `git clone https://github.com/docker/docker-bench-security.git` |
| Cosign       | Sign / attest images + SBOMs  | `brew install cosign`                         |
| Crane        | Registry ops (resolve digest) | `brew install crane`                          |
| rbac-tool    | RBAC graph visualization      | `brew install insights-engineering/tap/rbac-tool` |

## Last Validated

2026-04. Minimum tool versions: Trivy 0.59, Grype 0.87, Syft 1.18,
Kubescape 3.0, kube-bench 0.10 (CIS K8s v1.9), Falco 0.38, Tetragon 1.2,
Hadolint 2.12, Cosign 2.4.
