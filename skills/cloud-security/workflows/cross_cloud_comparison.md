# Workflow: Cross-Cloud Comparative Assessment

Use when the target environment spans two or three of AWS / GCP / Azure and the caller wants a single unified view, or when benchmarking relative posture across clouds.

## When to use this workflow

- Multi-cloud account (common for M&A integrations, hybrid deployments).
- CISO-level posture comparison ("which cloud is weakest?").
- Federated identity between clouds (AWS IAM → Azure AD trust, GCP Workload Identity Federation, etc.).

## Principle: maximum parallelism

Per-cloud audits are fully independent. Spawn one sub-agent per cloud, each running the cloud-specific workflow (`workflows/aws_full_assessment.md`, `workflows/gcp_full_assessment.md`, `workflows/azure_full_assessment.md`) concurrently.

```
 coordinator
 ├─ sub-agent: AWS  → aws_full_assessment
 ├─ sub-agent: GCP  → gcp_full_assessment
 └─ sub-agent: Azure → azure_full_assessment
```

When all three complete, the coordinator runs cross-cloud analysis (Phase F below).

## Phase F-1: Identity federation & trust graph

Identify cross-cloud trust. These links make a finding in one cloud exploitable from another:

| Link | Find it via |
|------|-------------|
| AWS IAM role with `AssumeRoleWithWebIdentity` trusting Azure AD / GCP OIDC issuer | `iam:ListRoles` + inspect `AssumeRolePolicyDocument` for `token.actions.githubusercontent.com`, `accounts.google.com`, `sts.windows.net/TENANT_ID` |
| GCP Workload Identity Federation pools trusting AWS / Azure | `gcloud iam workload-identity-pools list` |
| Azure federated identity credentials on SP | `az ad app federated-credential list --id APP_ID` |
| Cross-cloud S3/GCS/Blob replication | Bucket replication configs on each side |

```bash
# AWS roles trusting external OIDC
aws iam list-roles --query "Roles[?AssumeRolePolicyDocument.Statement[?contains(Principal.Federated || '', 'oidc') || contains(Principal.Federated || '', 'token.actions') || contains(Principal.Federated || '', 'sts.windows.net')]]"

# GCP Workload Identity Federation
for p in $(gcloud projects list --format="value(projectId)"); do
  gcloud iam workload-identity-pools list --project=$p --location=global 2>/dev/null
done

# Azure federated credentials on apps
az ad app list --all --query "[?length(federatedIdentityCredentials) > \`0\`].{Name:displayName,AppId:appId}"
```

## Phase F-2: Unified finding normalization

Each cloud sub-agent emits findings conforming to `schemas/finding.json`. The `cloud_provider` field makes grouping trivial:

```bash
# After all three sub-agents finish:
cat findings/*.json | jq -s 'group_by(.cloud_provider) | map({cloud: .[0].cloud_provider, count: length})'

# Severity rollup per cloud
cat findings/*.json | jq -s '
  group_by(.cloud_provider) | map({
    cloud: .[0].cloud_provider,
    critical: [.[] | select(.severity=="critical")] | length,
    high:     [.[] | select(.severity=="high")]     | length,
    medium:   [.[] | select(.severity=="medium")]   | length
  })'
```

## Phase F-3: Common misconfiguration mapping

Same category, different cloud — map them onto a shared lens so the report reads consistently:

| Category | AWS | GCP | Azure |
|----------|-----|-----|-------|
| Public object storage | S3 public bucket | GCS allUsers/allAuthenticatedUsers | Storage account allowBlobPublicAccess |
| Admin to all | `*:*` policy | `roles/owner` / `roles/editor` | Owner at subscription/root mgmt group |
| Exposed management ports | SG 0.0.0.0/0:22/3389 | FW 0.0.0.0/0:22/3389 | NSG Internet:22/3389 |
| Weak IMDS | IMDSv1 | Default SA on VM | Public MI on VM |
| Key rotation | IAM key > 90d | SA user-managed key | SP secret > 90d |
| Audit logging off | CloudTrail disabled/region-only | Cloud Audit Logs disabled | Activity Log not exported |
| Root/top-level MFA | Root no MFA | Org admin no MFA | Global Admin no MFA |

Use this table to produce a "multi-cloud posture scorecard."

## Phase F-4: Steampipe cross-cloud summary

```sql
-- Requires aws, azure, gcp plugins all installed & authenticated
SELECT 'aws'   AS cloud, count(*) AS public_storage FROM aws_s3_bucket WHERE bucket_policy_is_public
UNION ALL
SELECT 'azure', count(*) FROM azure_storage_account WHERE allow_blob_public_access
UNION ALL
SELECT 'gcp',   count(*) FROM gcp_storage_bucket b
WHERE EXISTS (SELECT 1 FROM jsonb_to_recordset(b.iam_policy->'bindings') AS bind(role text, members jsonb),
                            jsonb_array_elements_text(bind.members) m
              WHERE m IN ('allUsers','allAuthenticatedUsers'));
```

See `references/steampipe_queries.sql` for more cross-cloud patterns.

## Phase F-5: Executive rollup

Produce a single `report.md` with:

1. **Scorecard** — counts by severity × cloud.
2. **Top 10 findings** — highest severity × exposure, irrespective of cloud.
3. **Cross-cloud attack chains** — e.g., AWS role → GitHub OIDC → code repo → GCP SA key → GCS public bucket with secrets.
4. **Common themes** — if the same misconfig appears across all three clouds, it's an org-wide gap (policy, training, tooling).

## Parallelism summary

- Three sub-agents, one per cloud, fully parallel.
- Phase F runs only after all three complete (synchronization point).

## Reasoning budget summary

- Per-cloud sub-agents: follow the per-cloud workflow budget guidance.
- Phase F-1 trust graph: **extended thinking** — this is where the highest-impact findings hide.
- Phase F-5 rollup: moderate thinking.
