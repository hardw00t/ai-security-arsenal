# Secrets Management Methodology

Audit where credentials and secrets live, how they're accessed, and how rotation is handled.

## Universal triage

1. **Inventory secret stores**: where are secrets stored natively?
2. **Access controls**: who can read, update, delete?
3. **Rotation**: automated or stale?
4. **Exposure surface**: are secrets exfiltratable via compute env vars, image layers, user-data, metadata?
5. **Logging**: every read of a secret should be auditable.

## AWS

### Secrets Manager

```bash
aws secretsmanager list-secrets \
  --query "SecretList[].{Name:Name,LastRotated:LastRotatedDate,LastChanged:LastChangedDate,RotationEnabled:RotationEnabled}" \
  --output table

# Resource policy — check for broad principals
for s in $(aws secretsmanager list-secrets --query "SecretList[].Name" --output text); do
  aws secretsmanager get-resource-policy --secret-id $s 2>/dev/null
done

# CloudTrail: who's reading GetSecretValue?
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=GetSecretValue \
  --max-results 50
```

### Parameter Store (SSM)

```bash
# SecureString params with their KMS key
aws ssm describe-parameters \
  --query "Parameters[?Type=='SecureString'].{Name:Name,KeyId:KeyId}"

# Unencrypted String params that look secret-ish
aws ssm describe-parameters \
  --query "Parameters[?Type=='String' && (contains(Name,'password') || contains(Name,'secret') || contains(Name,'key') || contains(Name,'token'))]"
```

### KMS

```bash
aws kms list-keys
aws kms list-aliases

# Keys with broad key policies
for k in $(aws kms list-keys --query "Keys[].KeyId" --output text); do
  echo "=== $k ==="
  aws kms get-key-policy --key-id $k --policy-name default
done

# Rotation
aws kms list-keys --query "Keys[].KeyId" --output text | \
  while read k; do
    aws kms get-key-rotation-status --key-id $k
  done
```

### Exfil surfaces to check

- Lambda environment variables (`aws lambda list-functions` → inspect `Environment.Variables`).
- ECS task definition env vars (`aws ecs describe-task-definition`).
- EC2 user-data (`aws ec2 describe-instance-attribute --attribute userData`).
- CloudFormation stack outputs + parameters with `NoEcho=false`.
- CodeBuild project environment variables.
- Elastic Beanstalk env vars.

```bash
# Lambda env var sweep
aws lambda list-functions --query "Functions[].FunctionName" --output text | \
  while read f; do
    aws lambda get-function-configuration --function-name $f \
      --query "{name:FunctionName,env:Environment.Variables}"
  done
```

## GCP

### Secret Manager

```bash
gcloud secrets list
gcloud secrets versions list SECRET_NAME

# IAM on each secret
for s in $(gcloud secrets list --format="value(name)"); do
  echo "=== $s ==="
  gcloud secrets get-iam-policy $s
done

# Rotation period
gcloud secrets describe SECRET_NAME --format="value(rotation)"
```

### KMS

```bash
gcloud kms keyrings list --location=global
gcloud kms keys list --keyring=RING --location=LOC

# IAM on each key
gcloud kms keys get-iam-policy KEY --keyring RING --location LOC

# Rotation period (should be <= 90d for high-value keys)
gcloud kms keys describe KEY --keyring RING --location LOC \
  --format="value(rotationPeriod,nextRotationTime)"
```

### Exfil surfaces

- Cloud Function environment variables.
- Cloud Run service env vars (`gcloud run services describe`).
- Compute instance metadata (per-instance and project-wide).
- App Engine `app.yaml` env vars.
- GKE Secrets that are unencrypted at rest (ensure application-layer secret encryption is enabled in cluster config).

```bash
# Compute user data / startup script
gcloud compute instances describe INSTANCE --zone ZONE \
  --format="value(metadata.items.filter(key:startup-script).extract(value))"

# Project-wide metadata
gcloud compute project-info describe --format="value(commonInstanceMetadata)"

# Cloud Run env vars
gcloud run services list --format="value(metadata.name,metadata.namespace)" | \
  while read n ns; do
    gcloud run services describe $n --region=REGION \
      --format="value(spec.template.spec.containers[0].env)"
  done
```

## Azure

### Key Vault

```bash
az keyvault list -o table

# Per vault posture
for v in $(az keyvault list --query "[].name" -o tsv); do
  az keyvault show --name $v \
    --query "{RBAC:properties.enableRbacAuthorization,SoftDelete:properties.enableSoftDelete,PurgeProtection:properties.enablePurgeProtection,PublicAccess:properties.publicNetworkAccess,NetworkDefault:properties.networkAcls.defaultAction}"
done

# Access policies (legacy, non-RBAC) — scrutinize each
az keyvault show --name VAULT --query "properties.accessPolicies"

# RBAC role assignments scoped to vaults
az role assignment list --scope /subscriptions/SUB/resourceGroups/RG/providers/Microsoft.KeyVault/vaults/VAULT

# Secret listings (if we have read perms)
az keyvault secret list --vault-name VAULT
az keyvault key list    --vault-name VAULT
az keyvault certificate list --vault-name VAULT
```

### Exfil surfaces

- App Settings / Application Insights connection strings on App Services.
- Azure Functions app settings.
- Container App secrets + env vars.
- VM extensions (Custom Script Extension contents).
- ARM template parameters (check deployment history).
- Logic Apps connection configurations.
- Automation Account variables (check `isEncrypted` flag).

```bash
# App Service settings (app-settings vs connection-strings — both)
az webapp config appsettings list --name APP --resource-group RG
az webapp config connection-string list --name APP --resource-group RG

# Function app settings
az functionapp config appsettings list --name FN --resource-group RG

# Automation variables
az automation variable list --automation-account-name AA --resource-group RG
```

## Universal exposure check

Regardless of cloud, also grep application artifacts for hardcoded creds:

```bash
# Common secret patterns (run against source trees / deployment bundles)
trufflehog filesystem ./
gitleaks detect --source ./
detect-secrets scan
```

For repository-level scanning, see `sast-orchestration` skill.

## Pitfalls to flag

- **Stale credentials**: access keys / SP secrets / SA keys older than 90 days.
- **Long-lived SAS tokens / presigned URLs** committed to code or logs.
- **Shared secrets** across environments (dev secret identical to prod).
- **Wildcard KMS key policies** (anyone in the account can decrypt).
- **Rotation disabled** on Secrets Manager / Key Vault / SM keys.
- **Broad read** on secret stores (e.g., entire `developers` group has `secretsmanager:GetSecretValue` on `*`).
- **Secrets in log output** — check CloudWatch / Cloud Logging / Log Analytics for leaked values.

## Reasoning budget

- **Inventory and IAM audit**: minimal thinking.
- **Trace access paths** (which principal → which secret → used where): moderate thinking.
- **Determine blast radius** of a leaked secret: moderate thinking.

## Parallelism

Each secret store + each compute service env-var sweep is independent. Fan out freely.
