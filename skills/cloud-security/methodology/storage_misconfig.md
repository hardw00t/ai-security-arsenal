# Storage Misconfiguration Methodology

Audit object storage (S3 / GCS / Azure Blob) systematically. Enumeration is independent per bucket — parallelize.

## Universal checklist

For every bucket/container:

1. **Access model**: what authentication model is in use (IAM-only, ACL, SAS, anonymous)?
2. **Public exposure**: is it reachable from the internet without credentials?
3. **Encryption**: at-rest (CMK vs provider-managed) and in-transit (HTTPS-only).
4. **Logging**: is object-level access logged? Are logs sent off-account?
5. **Versioning / immutability**: can an attacker delete or overwrite evidence?
6. **Lifecycle**: short TTL logs / legal hold on compliance buckets.
7. **Replication**: replicating to accounts not controlled by the owner?

## AWS S3

### Controls that must align

Public access depends on **all four** layers — any one can make a bucket public:

1. **Account-level Block Public Access** (`s3control get-public-access-block`)
2. **Bucket-level Block Public Access** (`s3api get-public-access-block --bucket`)
3. **Bucket policy** (`s3api get-bucket-policy --bucket`) — check for `Principal: "*"` or `AWS: "*"` without a Condition narrowing it
4. **Bucket ACL** (`s3api get-bucket-acl --bucket`) — check for grants to `AllUsers` or `AuthenticatedUsers` URIs

### High-value checks

```bash
# Per bucket (loop across list-buckets)
B=my-bucket
aws s3api get-public-access-block --bucket $B 2>&1
aws s3api get-bucket-policy --bucket $B --query Policy --output text 2>&1 | jq .
aws s3api get-bucket-policy-status --bucket $B
aws s3api get-bucket-acl --bucket $B
aws s3api get-bucket-encryption --bucket $B
aws s3api get-bucket-versioning --bucket $B
aws s3api get-bucket-logging --bucket $B
aws s3api get-bucket-ownership-controls --bucket $B
aws s3api get-bucket-website --bucket $B 2>/dev/null  # static site hosting
aws s3api get-bucket-replication --bucket $B 2>/dev/null
```

### Subtle pitfalls

- `AuthenticatedUsers` ACL means any AWS account, not your org.
- Bucket policy `Condition: {"StringEquals": {"aws:SourceVpce": ""}}` with empty string is effectively no condition.
- Presigned URLs with long expiry committed to code.
- `BucketOwnerEnforced` disables ACLs entirely; absence means legacy ACL rules still apply.
- Cross-account replication targets — verify `roleArn` and destination account ownership.

### External probing

```bash
s3scanner scan --bucket-file candidate-names.txt

aws s3 ls s3://bucket --no-sign-request
aws s3api get-object --bucket bucket --key file --no-sign-request -
```

## GCP Cloud Storage

### Controls

- **Uniform bucket-level access** (UBLA): when enabled, ACLs disabled — all access via IAM.
- **Public Access Prevention** (`inherited` | `enforced`): enforced blocks public at bucket level regardless of IAM.
- **IAM bindings**: check for `allUsers` / `allAuthenticatedUsers` anywhere.

```bash
gsutil ls

gcloud storage buckets describe gs://BUCKET --format=json \
  | jq '{ubla: .iamConfiguration.uniformBucketLevelAccess.enabled,
         pap:  .iamConfiguration.publicAccessPrevention,
         enc:  .encryption,
         ver:  .versioning,
         log:  .logging}'

gcloud storage buckets get-iam-policy gs://BUCKET \
  --format="json" | jq '.bindings[] | select(.members[] | contains("allUsers") or contains("allAuthenticatedUsers"))'

# Anonymous probes
curl -I https://storage.googleapis.com/BUCKET/
curl   https://storage.googleapis.com/BUCKET/OBJECT
```

### Pitfalls

- `allAuthenticatedUsers` means any Google account.
- Object ACLs can override bucket IAM when UBLA is disabled — `gsutil acl get gs://bucket/object`.
- `Signed URLs` with long lifetimes committed to repos.
- Legacy ACL grants survive an IAM "cleanup" unless UBLA is enabled.

## Azure Blob Storage

### Layered controls

1. **Storage account**: `allowBlobPublicAccess`, `allowSharedKeyAccess`, `minimumTlsVersion`, `publicNetworkAccess`.
2. **Network rules**: default action (`Deny` preferred), VNet/private endpoint usage.
3. **Container public access**: `None` | `Blob` | `Container`.
4. **SAS tokens**: scope, expiry, IP restrictions, signed protocol.
5. **RBAC vs shared key**: prefer Entra-ID RBAC; disable shared key if possible.

```bash
az storage account list -o table

A=mystorageacct
az storage account show --name $A --query "{pub:allowBlobPublicAccess, sharedKey:allowSharedKeyAccess, tls:minimumTlsVersion, https:enableHttpsTrafficOnly, netDefault:networkAcls.defaultAction}"

az storage container list --account-name $A --auth-mode login \
  --query "[].{Name:name,PublicAccess:properties.publicAccess}" -o table

# Anonymous list probe
curl "https://$A.blob.core.windows.net/CONTAINER?restype=container&comp=list"
```

### Pitfalls

- `allowBlobPublicAccess=true` at the account level enables container-level `Blob` or `Container` public settings.
- SAS tokens with `sp=racwdlup` and no expiry ("permanent SAS") in application code or URLs.
- Stored access policies enabling SAS re-use without rotation.
- `Microsoft.Storage` service tag in NSG rules effectively whitelists ALL Azure tenants.
- Static websites (`$web` container) with sensitive files.
- Legacy "classic" storage accounts without modern controls.

## Reasoning budget

- **Enumeration + checks**: minimal thinking — script-driven, per-bucket.
- **SAS token / signed URL analysis**: light thinking — parse token, evaluate scope/expiry.
- **Cross-account replication implications**: moderate thinking — trace data flow.

## Parallelism

Per-bucket audits are fully independent. Fan out:

- AWS: `aws s3api list-buckets` → N buckets → N parallel audit jobs.
- GCP: `gcloud storage buckets list` → parallel.
- Azure: `az storage account list` → per-account, then containers parallel.

Use a sub-agent per storage service when bucket count > 20.
