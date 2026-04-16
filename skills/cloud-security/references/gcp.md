# GCP Security Reference

Command reference and pitfall catalog for Google Cloud. Load when `cloud_provider == gcp`.

## Authentication Setup

```bash
# Application default credentials
gcloud auth application-default login

# Service account key
export GOOGLE_APPLICATION_CREDENTIALS="/path/to/sa-key.json"
gcloud auth activate-service-account --key-file=$GOOGLE_APPLICATION_CREDENTIALS

# Set active project / verify identity
gcloud config set project PROJECT_ID
gcloud config list
gcloud auth list

# Enumerate projects the identity can see
gcloud projects list
gcloud organizations list
gcloud resource-manager folders list --organization=ORG_ID
```

Minimum read roles: `roles/viewer` + `roles/iam.securityReviewer` + `roles/logging.viewer`. For deeper compute/storage inspection, add `roles/cloudasset.viewer` for Cloud Asset Inventory.

## ScoutSuite / Prowler

```bash
scout gcp --project-id PROJECT_ID --report-dir ./scout-gcp

# ScoutSuite org-wide (all projects)
scout gcp --folder-id FOLDER_ID --all-projects

# Prowler (v4+ supports GCP)
prowler gcp --project-ids PROJECT_ID --compliance cis_3.0_gcp
prowler gcp --project-ids PROJECT_ID --services iam gcs compute
```

## IAM Analysis

```bash
# Project-level policy (human-readable flatten)
gcloud projects get-iam-policy PROJECT_ID \
  --flatten="bindings[].members" \
  --format="table(bindings.role, bindings.members)"

# Org-level
gcloud organizations get-iam-policy ORG_ID

# Service accounts + their keys (user-managed keys = long-lived credential risk)
gcloud iam service-accounts list
gcloud iam service-accounts get-iam-policy SA_EMAIL
gcloud iam service-accounts keys list --iam-account=SA_EMAIL

# Identify overly permissive bindings via Cloud Asset Inventory
gcloud asset search-all-iam-policies \
  --scope=projects/PROJECT_ID \
  --query="policy:roles/owner OR policy:roles/editor"

# Find public-bound resources
gcloud asset search-all-iam-policies \
  --scope=projects/PROJECT_ID \
  --query="policy:allUsers OR policy:allAuthenticatedUsers"

# Custom roles (often over-scoped on purpose)
gcloud iam roles list --project=PROJECT_ID

# Recommender: surface over-privileged principals
gcloud recommender recommendations list \
  --project=PROJECT_ID \
  --recommender=google.iam.policy.Recommender \
  --location=global
```

See `methodology/iam_privilege_escalation.md` for GCP-specific impersonation/key-creation chains.

## Cloud Storage (GCS)

```bash
# Enumerate buckets
gcloud storage buckets list
# or legacy: gsutil ls

# Bucket IAM
gcloud storage buckets get-iam-policy gs://BUCKET
gsutil iam get gs://BUCKET

# Bucket config (uniform access, logging, versioning, retention)
gcloud storage buckets describe gs://BUCKET --format=json

# Public bucket probes
gsutil ls gs://BUCKET                    # authenticated
curl https://storage.googleapis.com/BUCKET/   # anonymous list
curl https://storage.googleapis.com/BUCKET/OBJECT  # anonymous fetch

# Check uniform bucket-level access (disables legacy ACLs)
gcloud storage buckets describe gs://BUCKET \
  --format="value(iamConfiguration.uniformBucketLevelAccess.enabled)"
```

Pitfall: `allUsers` or `allAuthenticatedUsers` bound to `roles/storage.objectViewer` on a bucket == world-readable. `allAuthenticatedUsers` means ANY Google account, not just yours.

## Compute Engine

```bash
# Public IPs
gcloud compute instances list \
  --format="table(name,zone,networkInterfaces[0].accessConfigs[0].natIP)" \
  --filter="networkInterfaces[0].accessConfigs[0].natIP:*"

# SSH keys in project metadata (stale keys = persistent access)
gcloud compute project-info describe --format="value(commonInstanceMetadata.items.ssh-keys)"

# OS Login enforcement
gcloud compute project-info describe --format="value(commonInstanceMetadata.items.enable-oslogin)"

# Firewall rules allowing 0.0.0.0/0
gcloud compute firewall-rules list \
  --filter="sourceRanges:0.0.0.0/0" \
  --format="table(name,network,sourceRanges,allowed)"

# Default service account usage (BAD — has Editor by default)
gcloud compute instances list \
  --format="table(name,serviceAccounts[0].email)"

# Shielded VM + Confidential VM
gcloud compute instances describe INSTANCE \
  --format="value(shieldedInstanceConfig)"
```

## GKE

```bash
gcloud container clusters list
gcloud container clusters describe CLUSTER --zone ZONE

# Check for legacy auth / ABAC / public control plane
gcloud container clusters describe CLUSTER --zone ZONE \
  --format="yaml(masterAuth,legacyAbac,privateClusterConfig,networkPolicy)"

# Workload Identity enabled?
gcloud container clusters describe CLUSTER --zone ZONE \
  --format="value(workloadIdentityConfig.workloadPool)"
```

For deep workload scanning, see `container-security` skill.

## Common GCP Misconfigurations

### Critical
- [ ] Public Cloud Storage buckets (allUsers / allAuthenticatedUsers)
- [ ] Service accounts with `roles/owner` or `roles/editor`
- [ ] Default Compute Engine service account in use
- [ ] Public GCE instances without Identity-Aware Proxy
- [ ] No organization policies enforcing resource constraints
- [ ] User-managed SA keys that are old (>90d) or never rotated

### High
- [ ] Firewall rules with `0.0.0.0/0` on 22/3389/3306/5432
- [ ] Cloud Audit Logging disabled for Data Access logs
- [ ] No VPC Service Controls around sensitive projects
- [ ] Compute Engine default encryption only (no CMEK)
- [ ] IAM binding with `allUsers` / `allAuthenticatedUsers` anywhere

### Medium
- [ ] Uniform bucket-level access not enforced
- [ ] Cloud Armor not configured for internet-facing LBs
- [ ] Binary Authorization disabled on GKE
- [ ] Artifact Registry / Container Registry public
- [ ] Access Transparency not enabled
- [ ] OS Login not enforced

## Metadata Server

```bash
# GCP metadata (Metadata-Flavor: Google required)
curl -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/

# Default SA token (useful post-SSRF)
curl -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# All SAs attached to this VM
curl -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/

# SSH keys in metadata
curl -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/project/attributes/ssh-keys
```

## Organization Policy Quick Checks

```bash
# List enforced policies
gcloud resource-manager org-policies list --organization=ORG_ID

# Common policies that SHOULD be set:
# - constraints/iam.disableServiceAccountKeyCreation
# - constraints/storage.uniformBucketLevelAccess
# - constraints/compute.requireOsLogin
# - constraints/compute.vmExternalIpAccess
# - constraints/sql.restrictPublicIp
```

## Last validated: 2026-04

- gcloud CLI 465+
- ScoutSuite 5.14+
- Prowler v4.0+ (GCP support)
