---
name: cloud-security
description: "Multi-cloud security assessment skill for AWS, Azure, and GCP. Use when performing cloud security audits, scanning for misconfigurations, testing IAM policies, auditing storage permissions, and identifying privilege escalation paths. Triggers on requests to audit cloud security, scan AWS/Azure/GCP, check cloud misconfigurations, or perform cloud penetration testing. Covers CIS benchmarks, CSPM, and cross-cloud identity federation."
---

# Cloud Security Assessment

Thin router for security assessment of AWS, GCP, and Azure environments. The body of knowledge lives in per-cloud `references/`, per-domain `methodology/`, and per-scope `workflows/`. Load only what the current task needs.

## When to Use

- Multi-cloud or single-cloud security audit (read-only CSPM-style).
- IAM privilege-escalation path discovery.
- Storage (S3 / GCS / Azure Blob) exposure review.
- Network posture and metadata-service checks.
- Secrets-store audit (Secrets Manager / Secret Manager / Key Vault).
- CIS / SOC2 / PCI-DSS benchmark assessment against a live account.
- Cross-cloud identity federation / trust-graph review.

## Trigger Phrases

`audit AWS security`, `scan Azure for misconfigurations`, `check GCP security`, `test cloud IAM`, `find S3 bucket issues`, `cloud penetration test`, `CIS benchmark audit`, `cloud privilege escalation`, `multi-cloud assessment`.

## When NOT to Use This Skill

| If the task is… | Use instead |
|---|---|
| Scanning Terraform / CloudFormation / ARM / Bicep / Pulumi files pre-deploy | `iac-security` |
| Container image CVEs or scanning running workloads on EKS / GKE / AKS | `container-security` |
| Testing an application hosted in the cloud (OWASP, BOLA, XSS, SQLi) | `api-security` or `dast-automation` |
| Source-code SAST of cloud-deployed apps | `sast-orchestration` |
| LLM-specific attacks against a cloud-hosted model | `llm-security` |

This skill assumes you have credentials against a live cloud account. If you only have source artifacts, route to the sibling skills above.

## Decision Tree

```
Target scope?
├─ Single cloud (AWS only)    → workflows/aws_full_assessment.md
├─ Single cloud (GCP only)    → workflows/gcp_full_assessment.md
├─ Single cloud (Azure only)  → workflows/azure_full_assessment.md
└─ 2+ clouds / federated      → workflows/cross_cloud_comparison.md  (fan out per-cloud)

Within a cloud, narrow by domain:
├─ IAM / identity / privesc         → methodology/iam_privilege_escalation.md
├─ Storage exposure (S3/GCS/Blob)   → methodology/storage_misconfig.md
├─ Networking / firewall / IMDS     → methodology/network_security.md
├─ Secrets / KMS / Key Vault        → methodology/secrets_management.md
└─ CIS/compliance full sweep        → the workflow for that cloud (runs scanners)

Need specific commands or tool invocations?
├─ AWS        → references/aws.md
├─ GCP        → references/gcp.md
├─ Azure      → references/azure.md
├─ Tooling    → references/cloud_tools.md
└─ SQL        → references/steampipe_queries.sql
```

## Parallelism Hints

Parallelize freely:
- **Per-cloud audits** across AWS / GCP / Azure are fully independent — run three concurrent sub-agents.
- **Per-service audits** within a cloud (IAM, storage, compute, network, secrets, logging) are independent after Phase 0 context gathering.
- **Per-region iteration** (AWS regions, GCP zones, Azure locations) is independent — fan out.
- **Scanner sweep** (Prowler + ScoutSuite + Steampipe) runs concurrently — same target, different lenses.

Must be sequential:
- Phase 0 (context / identity / scope) → everything else (enumeration depends on knowing who you are and what you can see).
- IAM enumeration → privesc graph analysis (graph needs the nodes first).
- All per-cloud results → cross-cloud rollup (synchronization point).

## Sub-Agent Delegation

Spawn sub-agents when:
- **Multi-cloud account**: one sub-agent per cloud provider. Each runs its own `workflows/<cloud>_full_assessment.md`.
- **Many subscriptions / projects / accounts in one cloud**: one sub-agent per subscription/project.
- **Service deep-dives**: if an audit surfaces 20+ S3 buckets or 50+ VMs, spawn a dedicated sub-agent for that service.

Coordinator responsibilities: scope enforcement, credential distribution, finding deduplication, cross-cloud correlation.

## Reasoning Budget

- **Extended thinking** for:
  - IAM privilege-escalation path analysis (graph traversal, multi-hop chains, cross-layer — ARM ↔ Entra, AWS IAM → Lambda → DynamoDB).
  - Trust-graph analysis in `workflows/cross_cloud_comparison.md` Phase F-1.
  - Blast-radius determination for a compromised principal.
  - Effective network reachability through layered NACL + SG + peering + TGW.
- **Minimal / no extended thinking** for:
  - Misconfiguration enumeration (script-driven, tool output).
  - Scanner orchestration (Prowler / ScoutSuite / Steampipe invocations).
  - Per-bucket / per-resource attribute checks.
  - CIS benchmark cross-referencing.

## Multimodal Hooks

- Cloud console screenshots (AWS Console / Azure Portal / GCP Console) are often the clearest evidence for policy findings — capture when proving exploitability.
- ScoutSuite produces an HTML dashboard; screenshots of red "Danger" cards communicate severity well to executives.
- PMapper / ROADrecon visualizations of privesc graphs are worth including as diagrams.

Attach to `evidence.screenshot` in the finding schema.

## Structured Output

All findings conform to `schemas/finding.json`. Key cloud-specific fields:
`cloud_provider`, `account_id`, `region`, `service`, `resource_arn`, `cis_benchmark_id`, `compliance` (array of `CIS` / `SOC2` / `PCI-DSS` / `HIPAA` / `GDPR` / `NIST-800-53` / `ISO-27001`), `privilege_escalation_path`, `detection`.

## Workflow Index

| Workflow | Use for |
|---|---|
| `workflows/aws_full_assessment.md` | End-to-end AWS account or org audit |
| `workflows/gcp_full_assessment.md` | End-to-end GCP project / folder / org audit |
| `workflows/azure_full_assessment.md` | End-to-end Azure subscription + Entra ID audit |
| `workflows/cross_cloud_comparison.md` | 2+ clouds, federated identity, unified rollup |

## Methodology Index

| Methodology | Scope |
|---|---|
| `methodology/iam_privilege_escalation.md` | Known privesc vectors across AWS / GCP / Azure; extended-thinking heavy |
| `methodology/storage_misconfig.md` | S3 / GCS / Azure Blob exposure and encryption checks |
| `methodology/network_security.md` | Firewall / NSG / SG audit, IMDS posture, SSRF chains |
| `methodology/secrets_management.md` | Secret stores, rotation, env-var exfil surfaces |

## References Index

| Reference | Content |
|---|---|
| `references/aws.md` | AWS CLI commands, Prowler invocations, S3/IAM/EC2/RDS checks, misconfig catalog |
| `references/gcp.md` | gcloud commands, GCS/IAM/Compute checks, org policy quick-list |
| `references/azure.md` | az CLI commands, ARM + Entra ID enumeration, Key Vault/Storage/NSG checks |
| `references/cloud_tools.md` | ScoutSuite / Prowler / CloudSploit / Steampipe / Pacu / ROADtools comparison + invocation |
| `references/steampipe_queries.sql` | Ready-to-run Steampipe SQL covering public storage, permissive IAM, exposed network, encryption gaps — cross-cloud patterns |
| `references/bounty_patterns_2024_2026.md` | Post-2023 bounty TTPs (ConfusedFunction, Cloud Run bypass, Compute IAM + tag chain, AWSMarketplaceFullAccess → admin, SSRF DNS rebinding, CVE-2025-61882 Oracle EBS, blind-SSRF redirect loop) |

## Tools

| Tool | Purpose | Install |
|---|---|---|
| ScoutSuite | Multi-cloud audit with HTML dashboard | `pip install scoutsuite` |
| Prowler | Deep AWS/Azure/GCP CIS + compliance | `pip install prowler` |
| CloudSploit | Fast triage CSPM | `npm install -g cloudsploit` |
| Steampipe | Declarative SQL over cloud APIs | `brew install turbot/tap/steampipe` |
| Pacu | AWS offense / privesc modules | `pip install pacu` |
| PMapper | AWS IAM privesc graph | `pip install principalmapper` |
| ROADtools | Entra ID enumeration + offline analysis | `pip install roadrecon` |
| enumerate-iam | Blind AWS IAM enumeration | `pip install enumerate-iam` |
| s3scanner | External S3 bucket discovery | `pip install s3scanner` |

## Last Validated

- 2026-04
- AWS CLI v2.15+, gcloud 465+, Azure CLI 2.60+
- Prowler v4.0+, ScoutSuite 5.14+, Steampipe 0.22+, Pacu 1.5+
- CIS Benchmarks: AWS v3.0, Azure v2.1, GCP v3.0
