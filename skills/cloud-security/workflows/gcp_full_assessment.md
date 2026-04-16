# Workflow: Full GCP Security Assessment

End-to-end assessment for a single project, folder, or organization.

## Preconditions

- `gcloud auth list` shows authorized identity.
- Minimum: `roles/viewer` + `roles/iam.securityReviewer` + `roles/logging.viewer` at the target scope.
- For org-wide: `roles/cloudasset.viewer` at the org level is extremely valuable.
- Scope confirmed (project IDs, exclusions).

## Phase 0: Context & scope

```bash
gcloud auth list              > ctx-identity.txt
gcloud config list            > ctx-config.txt
gcloud projects list          > ctx-projects.txt
gcloud organizations list     > ctx-orgs.txt
```

For each in-scope project, verify reachability: `gcloud config set project PROJECT_ID && gcloud projects describe PROJECT_ID`.

## Phase 1: Broad scanner sweep (parallel)

```bash
scout gcp --project-id PROJECT_ID --report-dir scout-gcp/ &
prowler gcp --project-ids PROJECT_ID --compliance cis_3.0_gcp -M json-ocsf -o prowler-gcp/ &
steampipe query references/steampipe_queries.sql --output json > steampipe-gcp.json &
wait
```

## Phase 2: IAM deep dive

```bash
# Project-wide IAM
gcloud projects get-iam-policy PROJECT_ID \
  --flatten="bindings[].members" \
  --format=json > iam-policy.json

# Service accounts + user-managed keys
gcloud iam service-accounts list --format=json > service-accounts.json
for sa in $(gcloud iam service-accounts list --format="value(email)"); do
  gcloud iam service-accounts keys list --iam-account=$sa --format=json
done > sa-keys.json

# Public / anyone bindings (any resource in project)
gcloud asset search-all-iam-policies \
  --scope=projects/PROJECT_ID \
  --query="policy:allUsers OR policy:allAuthenticatedUsers" \
  --format=json > public-iam-bindings.json

# Custom roles
gcloud iam roles list --project=PROJECT_ID > custom-roles.json
```

Use `gcloud iam test-iam-permissions` to verify specific privesc permissions against your identity (see `methodology/iam_privilege_escalation.md`).

**Extended thinking**: escalation chain discovery (SA impersonation graphs can be multi-hop).

## Phase 3: Per-service audits (parallel)

| Sub-agent | Scope |
|-----------|-------|
| storage   | GCS buckets |
| compute   | GCE + GAE + Cloud Run + Cloud Functions |
| gke       | GKE clusters (control-plane only; workload → container-security skill) |
| data      | Cloud SQL, BigQuery, Spanner, Firestore, Memorystore |
| network   | VPC, firewall rules, Cloud Armor, LBs |
| secrets   | Secret Manager + KMS |
| logging   | Cloud Audit Logs, VPC Flow Logs, Cloud Monitoring |

Iterate across regions per service. Cross-project parallelism encouraged for folder/org assessments.

## Phase 4: Org-policy review (if scope ≥ folder)

```bash
gcloud resource-manager org-policies list --organization=ORG_ID > org-policies.json

# Expected enforced constraints for a mature org:
# - constraints/iam.disableServiceAccountKeyCreation
# - constraints/storage.uniformBucketLevelAccess
# - constraints/storage.publicAccessPrevention
# - constraints/compute.requireOsLogin
# - constraints/compute.vmExternalIpAccess
# - constraints/sql.restrictPublicIp
# - constraints/iam.allowedPolicyMemberDomains
```

Flag any expected constraint that is missing.

## Phase 5: Deep-dive & reporting

Same pattern as AWS:
1. Reproduce each candidate with read-only CLI.
2. Confirm detection gap (Cloud Audit Log MethodName).
3. Map to CIS-GCP-x.y and relevant compliance.
4. Emit findings conforming to `schemas/finding.json`.

## Output artifacts

```
gcp-assessment-YYYY-MM-DD/
├── ctx-*
├── iam-policy.json
├── service-accounts.json
├── sa-keys.json
├── public-iam-bindings.json
├── org-policies.json
├── scout-gcp/
├── prowler-gcp/
├── steampipe-gcp.json
├── findings/
└── report.md
```

## Parallelism summary

- Scanner sweep: parallel.
- Per-service: parallel.
- Multi-project / multi-folder: parallel — one sub-agent per project.

## Reasoning budget summary

- Enumeration + scanner orchestration: minimal.
- SA impersonation graph, org policy gap analysis: extended.
