# Workflow: Full AWS Security Assessment

End-to-end assessment runbook for a single AWS account (or organization). Target runtime: 1-4 hours for a mid-sized account.

## Preconditions

- `aws sts get-caller-identity` succeeds with authorized credentials.
- `SecurityAudit` + `ViewOnlyAccess` minimum; `ReadOnlyAccess` preferred.
- Scope confirmed: which account(s), which regions, exclusions (e.g. don't touch production Lambdas).

## Phase 0: Context & scope (5 min)

```bash
aws sts get-caller-identity > ctx-identity.json
aws organizations describe-organization 2>/dev/null > ctx-org.json
aws ec2 describe-regions --query "Regions[].RegionName" --output text > ctx-regions.txt
```

Record account ID(s), the effective principal, and whether this is org-wide.

## Phase 1: Broad scanner sweep (parallel, 30-90 min)

Run scanners in parallel — they're independent:

```bash
prowler aws --compliance cis_3.0_aws -M json-ocsf -o prowler-out/ &
scout aws --profile default --report-dir scout-out &
steampipe query references/steampipe_queries.sql --output json > steampipe-aws.json &
wait
```

Triage by severity: start with Critical + High from Prowler OCSF output.

## Phase 2: IAM deep dive (parallel per region is N/A — IAM is global)

```bash
aws iam get-account-authorization-details > iam-full.json
aws iam generate-credential-report
aws iam get-credential-report --query Content --output text | base64 -d > creds-report.csv
```

Then run privilege escalation scanning — see `methodology/iam_privilege_escalation.md`:

```bash
pacu
> new_session aws-assessment-$(date +%F)
> run iam__enum_permissions
> run iam__privesc_scan

# Or graph-based with PMapper
pmapper graph create
pmapper query "preset privesc *"
```

**Reasoning budget**: engage extended thinking here. Privesc path discovery needs graph traversal.

## Phase 3: Per-service audits (parallelize across services)

These are fully independent — delegate to sub-agents:

| Sub-agent | Scope | Primary inputs |
|-----------|-------|----------------|
| storage   | S3 + Glacier | `methodology/storage_misconfig.md` |
| compute   | EC2 + Lambda + ECS + EKS-control-plane | `references/aws.md` |
| data      | RDS + DynamoDB + Redshift + ElastiCache | `references/aws.md` |
| network   | VPC + SG + NACL + TGW + Route53 | `methodology/network_security.md` |
| secrets   | Secrets Manager + SSM PS + KMS | `methodology/secrets_management.md` |
| logging   | CloudTrail + Config + GuardDuty + Security Hub | `references/aws.md` |

Iterate each sub-agent over all in-scope regions in parallel.

## Phase 4: Targeted deep-dive (extended thinking)

For each Critical/High candidate, confirm exploitability:

1. Reproduce with minimal tooling (CLI commands only — avoid destructive ops).
2. Identify detection gap: would CloudTrail / GuardDuty fire?
3. Trace blast radius: what does this principal/resource grant access to?
4. Produce a finding conforming to `schemas/finding.json`.

## Phase 5: Consolidation & reporting

- Normalize all findings into `schemas/finding.json` structures.
- Deduplicate across Prowler / ScoutSuite / Steampipe / manual sources.
- Map each to `cis_benchmark_id` and `compliance` list.
- Rank by severity × exposure (public-facing > internal).

## Output artifacts

```
aws-assessment-YYYY-MM-DD/
├── ctx-identity.json
├── ctx-regions.txt
├── iam-full.json
├── creds-report.csv
├── prowler-out/
├── scout-out/
├── steampipe-aws.json
├── findings/
│   ├── CS-AWS-IAM-001.json
│   ├── CS-AWS-S3-001.json
│   └── ...
└── report.md
```

## Parallelism summary

- Phase 1 scanners: fully parallel.
- Phase 3 services: fully parallel across services AND regions.
- Phase 4 deep-dives: parallel per finding.

## Reasoning budget summary

- Phases 0, 1, 3: minimal thinking — mostly tool orchestration.
- Phase 2 privesc, Phase 4 blast radius: extended thinking.
