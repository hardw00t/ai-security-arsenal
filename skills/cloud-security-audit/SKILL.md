---
name: cloud-security-audit
description: "Multi-cloud security audit skill for AWS, Azure, and GCP. Performs comprehensive security assessments covering IAM, storage, networking, compute, logging, and compliance. Use when: 'audit AWS security', 'check Azure configuration', 'GCP security assessment', 'cloud misconfiguration scan', or 'CIS benchmark audit'. (user)"
---

# Cloud Security Audit

This skill enables comprehensive security auditing of cloud infrastructure across AWS, Azure, and Google Cloud Platform. It covers IAM, storage, networking, compute, logging, secrets management, and compliance with industry standards (CIS, NIST, SOC2).

## When to Use This Skill

This skill should be invoked when:
- Performing cloud security assessments
- Auditing AWS/Azure/GCP configurations
- Checking for cloud misconfigurations
- Running CIS benchmark compliance audits
- Reviewing IAM policies and permissions
- Analyzing storage bucket/blob security
- Assessing network security configurations
- Reviewing logging and monitoring setup
- Identifying exposed secrets and credentials
- Generating cloud security reports

### Trigger Phrases
- "audit my AWS account security"
- "check Azure security configuration"
- "GCP security assessment"
- "find cloud misconfigurations"
- "CIS benchmark audit for AWS"
- "review IAM policies"
- "check S3 bucket security"
- "audit cloud logging"
- "scan for exposed secrets in cloud"
- "multi-cloud security review"

---

## Prerequisites

### Required Tools

| Tool | Purpose | Installation |
|------|---------|--------------|
| AWS CLI | AWS interaction | `pip install awscli` |
| Azure CLI | Azure interaction | Install from Microsoft |
| gcloud | GCP interaction | Install Google Cloud SDK |
| Prowler | AWS/Azure/GCP auditing | `pip install prowler` |
| ScoutSuite | Multi-cloud auditing | `pip install scoutsuite` |
| Steampipe | Cloud query engine | Install from steampipe.io |
| CloudSploit | Cloud security scanner | `npm install -g cloudsploit` |
| trivy | IaC scanning | `apt install trivy` |

### Authentication Setup

#### AWS
```bash
# Configure AWS credentials
aws configure
# Or use environment variables
export AWS_ACCESS_KEY_ID="your-key-id"
export AWS_SECRET_ACCESS_KEY="your-secret-key"
export AWS_DEFAULT_REGION="us-east-1"

# Or use IAM role (recommended for EC2)
# Attach appropriate IAM role to instance

# Verify access
aws sts get-caller-identity
```

#### Azure
```bash
# Login to Azure
az login

# Set subscription
az account set --subscription "subscription-name"

# Verify access
az account show
```

#### GCP
```bash
# Authenticate with GCP
gcloud auth login
gcloud auth application-default login

# Set project
gcloud config set project PROJECT_ID

# Verify access
gcloud config list
```

---

## Quick Start Guide

### 1. AWS Security Audit (5 minutes)

```bash
# Run Prowler for comprehensive AWS audit
prowler aws --severity critical high -M json-ocsf -o results/

# Quick check with ScoutSuite
scout aws --report-dir ./scoutsuite-report

# Check specific services
python3 scripts/aws_security_audit.py --profile default --services iam,s3,ec2
```

### 2. Azure Security Audit (5 minutes)

```bash
# Run Prowler for Azure
prowler azure -M json-ocsf -o results/

# ScoutSuite for Azure
scout azure --report-dir ./scoutsuite-report

# Custom audit
python3 scripts/azure_security_audit.py --subscription "sub-id"
```

### 3. GCP Security Audit (5 minutes)

```bash
# Run Prowler for GCP
prowler gcp -M json-ocsf -o results/

# ScoutSuite for GCP
scout gcp --report-dir ./scoutsuite-report

# Custom audit
python3 scripts/gcp_security_audit.py --project "project-id"
```

---

## Security Audit Categories

### 1. Identity and Access Management (IAM)

| Check | AWS | Azure | GCP |
|-------|-----|-------|-----|
| Root/Owner account MFA | `aws iam get-account-summary` | N/A | N/A |
| User MFA enabled | IAM users | Azure AD users | Cloud Identity |
| Access key rotation | IAM access keys | Service principals | Service accounts |
| Inactive users | Last activity | Sign-in logs | Activity logs |
| Overly permissive policies | IAM policies | RBAC roles | IAM policies |
| Service account security | IAM roles | Managed identities | Service accounts |
| Cross-account access | Trust policies | Guest access | IAM bindings |

### 2. Storage Security

| Check | AWS | Azure | GCP |
|-------|-----|-------|-----|
| Public access | S3 bucket policies | Blob container access | GCS bucket IAM |
| Encryption at rest | S3/EBS encryption | Storage encryption | Cloud KMS |
| Versioning enabled | S3 versioning | Blob versioning | Object versioning |
| Logging enabled | S3 access logs | Storage analytics | Audit logs |
| Lifecycle policies | S3 lifecycle | Lifecycle management | Object lifecycle |
| Data classification | Macie | Purview | DLP |

### 3. Network Security

| Check | AWS | Azure | GCP |
|-------|-----|-------|-----|
| Public IPs | EC2, ELB | VMs, Load Balancers | Compute instances |
| Security groups | Inbound/outbound rules | NSG rules | Firewall rules |
| VPC/VNet configuration | VPC flow logs | VNet flow logs | VPC flow logs |
| WAF enabled | AWS WAF | Azure WAF | Cloud Armor |
| DDoS protection | AWS Shield | Azure DDoS | Cloud Armor |
| Private endpoints | PrivateLink | Private Endpoints | Private Access |

### 4. Compute Security

| Check | AWS | Azure | GCP |
|-------|-----|-------|-----|
| Instance metadata | IMDSv2 | Metadata service | Metadata server |
| Patch management | SSM Patch | Update Management | OS Patch |
| Instance profiles | IAM roles | Managed identities | Service accounts |
| Disk encryption | EBS encryption | Disk encryption | Persistent disk encryption |
| Serial console | Disabled | Disabled | Disabled |

### 5. Logging & Monitoring

| Check | AWS | Azure | GCP |
|-------|-----|-------|-----|
| Audit logging | CloudTrail | Activity Log | Cloud Audit Logs |
| Multi-region logging | CloudTrail all regions | Diagnostic settings | Org-level logging |
| Log encryption | KMS encryption | Storage encryption | CMEK |
| Alerting | CloudWatch Alarms | Azure Monitor | Cloud Monitoring |
| SIEM integration | CloudWatch to SIEM | Sentinel | Chronicle |

---

## Detailed Testing Workflows

### Workflow 1: Complete AWS Security Assessment

```python
# Phase 1: IAM Audit
# Check root account
aws iam get-account-summary
aws iam generate-credential-report
aws iam get-credential-report

# Check MFA
aws iam list-virtual-mfa-devices
aws iam list-users --query 'Users[?PasswordLastUsed!=`null`]'

# Check access keys
aws iam list-access-keys --user-name USERNAME
aws iam get-access-key-last-used --access-key-id KEY_ID

# Check policies
aws iam list-policies --only-attached
aws iam list-attached-user-policies --user-name USERNAME
aws iam get-policy-version --policy-arn ARN --version-id v1

# Phase 2: S3 Audit
# List all buckets
aws s3api list-buckets

# Check bucket policies
aws s3api get-bucket-policy --bucket BUCKET_NAME
aws s3api get-bucket-acl --bucket BUCKET_NAME
aws s3api get-public-access-block --bucket BUCKET_NAME

# Check encryption
aws s3api get-bucket-encryption --bucket BUCKET_NAME

# Check logging
aws s3api get-bucket-logging --bucket BUCKET_NAME

# Phase 3: EC2 Audit
# Check security groups
aws ec2 describe-security-groups --query 'SecurityGroups[?IpPermissions[?IpRanges[?CidrIp==`0.0.0.0/0`]]]'

# Check instances
aws ec2 describe-instances --query 'Reservations[].Instances[].{ID:InstanceId,Profile:IamInstanceProfile}'

# Check EBS encryption
aws ec2 describe-volumes --query 'Volumes[?Encrypted==`false`]'

# Phase 4: CloudTrail Audit
aws cloudtrail describe-trails
aws cloudtrail get-trail-status --name TRAIL_NAME
aws cloudtrail get-event-selectors --trail-name TRAIL_NAME

# Phase 5: Network Audit
# Check VPCs
aws ec2 describe-vpcs
aws ec2 describe-flow-logs

# Check public IPs
aws ec2 describe-addresses
aws ec2 describe-network-interfaces --query 'NetworkInterfaces[?Association.PublicIp]'
```

### Workflow 2: AWS IAM Deep Dive

```python
# Step 1: Generate and download credential report
aws iam generate-credential-report
sleep 5
aws iam get-credential-report --query Content --output text | base64 -d > cred_report.csv

# Step 2: Analyze credential report
# Check for:
# - Users without MFA
# - Old access keys (>90 days)
# - Unused credentials
# - Root account access key

# Step 3: Check for overly permissive policies
# Find policies with "*" permissions
aws iam list-policies --only-attached --query 'Policies[].Arn' --output text | \
while read arn; do
  version=$(aws iam get-policy --policy-arn $arn --query 'Policy.DefaultVersionId' --output text)
  aws iam get-policy-version --policy-arn $arn --version-id $version --query 'PolicyVersion.Document'
done

# Step 4: Check cross-account access
aws iam list-roles --query 'Roles[].AssumeRolePolicyDocument.Statement[?Principal.AWS]'

# Step 5: Find inline policies
aws iam list-users --query 'Users[].UserName' --output text | \
while read user; do
  aws iam list-user-policies --user-name $user
done
```

### Workflow 3: Azure Security Assessment

```bash
# Phase 1: Azure AD Audit
# List users
az ad user list --query '[].{Name:displayName,UPN:userPrincipalName,MFA:strongAuthenticationMethods}'

# Check guest users
az ad user list --query "[?userType=='Guest']"

# List service principals
az ad sp list --all --query '[].{Name:displayName,AppId:appId}'

# Phase 2: Resource Audit
# List all resources
az resource list --query '[].{Name:name,Type:type,RG:resourceGroup}'

# Check storage accounts
az storage account list --query '[].{Name:name,Https:enableHttpsTrafficOnly,Encryption:encryption.services.blob.enabled}'

# Check network security groups
az network nsg list --query '[].{Name:name,Rules:securityRules[?access==`Allow` && direction==`Inbound`]}'

# Phase 3: Key Vault Audit
az keyvault list
az keyvault show --name VAULT_NAME --query 'properties.enableSoftDelete'

# Phase 4: Activity Log
az monitor activity-log list --start-time 2024-01-01 --query '[].{Operation:operationName.value,Caller:caller}'

# Phase 5: Policy Compliance
az policy state list --query '[?complianceState==`NonCompliant`]'
```

### Workflow 4: GCP Security Assessment

```bash
# Phase 1: IAM Audit
# List service accounts
gcloud iam service-accounts list

# Check service account keys
gcloud iam service-accounts keys list --iam-account SA_EMAIL

# Get IAM policy
gcloud projects get-iam-policy PROJECT_ID

# Find overly permissive bindings
gcloud projects get-iam-policy PROJECT_ID --format=json | \
jq '.bindings[] | select(.members[] | contains("allUsers") or contains("allAuthenticatedUsers"))'

# Phase 2: Storage Audit
# List buckets
gsutil ls

# Check bucket IAM
gsutil iam get gs://BUCKET_NAME

# Check bucket ACL
gsutil acl get gs://BUCKET_NAME

# Phase 3: Compute Audit
# List instances
gcloud compute instances list

# Check firewall rules
gcloud compute firewall-rules list --filter="sourceRanges=('0.0.0.0/0')"

# Check instance metadata
gcloud compute instances describe INSTANCE --zone ZONE --format='value(metadata)'

# Phase 4: Logging Audit
# Check audit logs
gcloud logging sinks list
gcloud logging logs list

# Check if audit logs are enabled
gcloud projects get-iam-policy PROJECT_ID --format=json | \
jq '.auditConfigs'

# Phase 5: Network Audit
# List VPCs
gcloud compute networks list

# Check VPC flow logs
gcloud compute networks subnets list --format='table(name,enableFlowLogs)'
```

---

## Critical Misconfigurations to Check

### AWS Critical Checks

```yaml
Critical:
  - S3 bucket public access
  - Root account without MFA
  - IAM users with inline policies
  - Security groups with 0.0.0.0/0 to sensitive ports
  - CloudTrail disabled
  - Access keys older than 90 days
  - EBS volumes unencrypted
  - RDS publicly accessible
  - Lambda functions with overly permissive roles

High:
  - S3 bucket logging disabled
  - VPC flow logs disabled
  - IMDSv1 enabled on EC2
  - GuardDuty disabled
  - Config not enabled
  - SNS topics with public access
  - SQS queues with public access
```

### Azure Critical Checks

```yaml
Critical:
  - Storage accounts allowing public blob access
  - Network security groups with any-to-any rules
  - Key Vaults without soft delete
  - SQL databases without encryption
  - Azure AD without MFA enforcement
  - Storage accounts without HTTPS only
  - VMs with public IPs

High:
  - Activity logging not to storage
  - Azure Defender disabled
  - Network Watcher disabled
  - Disk encryption disabled
  - No resource locks on critical resources
```

### GCP Critical Checks

```yaml
Critical:
  - Buckets with allUsers/allAuthenticatedUsers
  - Firewall rules allowing 0.0.0.0/0
  - Service account keys (prefer Workload Identity)
  - Compute instances with default service account
  - Cloud SQL without SSL enforcement
  - Public IPs on instances

High:
  - VPC flow logs disabled
  - Cloud Audit Logs not enabled
  - Binary Authorization not enabled
  - Security Command Center disabled
  - Cloud Armor not configured
```

---

## CIS Benchmark Mapping

### AWS CIS Benchmark v3.0.0 (Key Controls)

| Control | Description | Check Command |
|---------|-------------|---------------|
| 1.4 | Root account MFA | `aws iam get-account-summary` |
| 1.5 | Root access keys | `aws iam get-credential-report` |
| 1.8 | Password policy | `aws iam get-account-password-policy` |
| 1.14 | Access key rotation | Check credential report |
| 2.1.1 | S3 public access | `aws s3api get-public-access-block` |
| 2.1.2 | S3 bucket logging | `aws s3api get-bucket-logging` |
| 2.2.1 | EBS encryption | `aws ec2 get-ebs-encryption-by-default` |
| 3.1 | CloudTrail enabled | `aws cloudtrail describe-trails` |
| 3.4 | CloudTrail log validation | Check trail configuration |
| 4.1 | Security group ports | `aws ec2 describe-security-groups` |
| 5.1 | VPC Flow Logs | `aws ec2 describe-flow-logs` |

### Azure CIS Benchmark v2.0.0 (Key Controls)

| Control | Description | Check Command |
|---------|-------------|---------------|
| 1.1 | MFA for privileged users | Azure AD Conditional Access |
| 1.2 | MFA for all users | Azure AD Settings |
| 2.1 | Microsoft Defender | `az security pricing list` |
| 3.1 | Storage secure transfer | `az storage account list` |
| 3.7 | Storage encryption | Storage account settings |
| 4.1.1 | SQL auditing | SQL Database settings |
| 5.1.1 | Activity log alerts | Azure Monitor |
| 6.1 | Network security groups | `az network nsg list` |
| 7.1 | VM disk encryption | `az vm encryption show` |

### GCP CIS Benchmark v2.0.0 (Key Controls)

| Control | Description | Check Command |
|---------|-------------|---------------|
| 1.1 | Corporate credentials | Cloud Identity |
| 1.4 | Service account keys | `gcloud iam service-accounts keys list` |
| 2.1 | Cloud audit logging | Logging settings |
| 3.1 | Default VPC | `gcloud compute networks list` |
| 3.6 | Firewall rules | `gcloud compute firewall-rules list` |
| 4.1 | Compute OS login | Instance settings |
| 5.1 | Storage bucket IAM | `gsutil iam get` |
| 6.1 | SQL public IP | Cloud SQL settings |

---

## Scripts Reference

| Script | Description | Usage |
|--------|-------------|-------|
| `aws_security_audit.py` | Comprehensive AWS audit | `python3 scripts/aws_security_audit.py` |
| `azure_security_audit.py` | Comprehensive Azure audit | `python3 scripts/azure_security_audit.py` |
| `gcp_security_audit.py` | Comprehensive GCP audit | `python3 scripts/gcp_security_audit.py` |
| `iam_analyzer.py` | IAM policy analysis | `python3 scripts/iam_analyzer.py` |
| `storage_scanner.py` | Storage security scan | `python3 scripts/storage_scanner.py` |
| `network_auditor.py` | Network config audit | `python3 scripts/network_auditor.py` |
| `compliance_checker.py` | CIS compliance check | `python3 scripts/compliance_checker.py` |
| `secret_scanner.py` | Find exposed secrets | `python3 scripts/secret_scanner.py` |
| `cloud_report_generator.py` | Generate reports | `python3 scripts/cloud_report_generator.py` |

---

## Example Claude Code Interactions

### Example 1: AWS Security Audit

```
User: Audit my AWS account for security issues

Claude: I'll perform a comprehensive AWS security audit.

[Phase 1: IAM Security]

1. Checking root account:
   > aws iam get-account-summary

   [!] CRITICAL: Root account has access keys enabled
   [!] HIGH: Root account MFA not enabled

2. Analyzing IAM users:
   > aws iam get-credential-report

   Found 15 users:
   - 3 users without MFA
   - 5 users with access keys > 90 days old
   - 2 users never logged in (stale accounts)

3. Checking IAM policies:
   [!] HIGH: Policy "arn:aws:iam::123456:policy/AdminAccess" grants "*:*"
   [!] MEDIUM: 8 users have inline policies

[Phase 2: Storage Security]

1. S3 Bucket Analysis:
   > aws s3api list-buckets

   Found 12 buckets:
   [!] CRITICAL: "company-backups" allows public access
   [!] HIGH: "logs-bucket" has no encryption
   [!] MEDIUM: 4 buckets without versioning

[Phase 3: Network Security]

1. Security Groups:
   > aws ec2 describe-security-groups

   [!] CRITICAL: sg-abc123 allows 0.0.0.0/0 to port 22 (SSH)
   [!] CRITICAL: sg-def456 allows 0.0.0.0/0 to port 3389 (RDP)
   [!] HIGH: sg-ghi789 allows 0.0.0.0/0 to port 3306 (MySQL)

[Phase 4: Logging]

1. CloudTrail Status:
   [!] HIGH: CloudTrail not enabled in us-west-2
   [+] OK: CloudTrail enabled in us-east-1

Summary:
| Severity | Count |
|----------|-------|
| Critical | 5 |
| High | 12 |
| Medium | 18 |
| Low | 8 |

Full report: reports/aws-audit-2024-01-15.html
```

### Example 2: Multi-Cloud Assessment

```
User: Run security assessment across our AWS, Azure, and GCP environments

Claude: I'll perform a comprehensive multi-cloud security assessment.

[AWS Account: 123456789012]

Running Prowler scan...
Critical findings: 3
- Public S3 buckets: 2
- Root MFA disabled: 1

High findings: 8
- Unencrypted EBS volumes: 4
- Overly permissive security groups: 4

[Azure Subscription: Production]

Running Azure audit...
Critical findings: 2
- Storage account public access: 1
- Key Vault soft-delete disabled: 1

High findings: 5
- NSG with any-to-any rules: 3
- SQL without encryption: 2

[GCP Project: prod-project-123]

Running GCP audit...
Critical findings: 4
- Public GCS buckets: 2
- Firewall 0.0.0.0/0 rules: 2

High findings: 6
- Default service account usage: 3
- VPC flow logs disabled: 3

[Multi-Cloud Summary]

| Provider | Critical | High | Medium |
|----------|----------|------|--------|
| AWS | 3 | 8 | 15 |
| Azure | 2 | 5 | 12 |
| GCP | 4 | 6 | 10 |
| Total | 9 | 19 | 37 |

Priority Remediations:
1. Enable MFA on AWS root account
2. Remove public access from S3/GCS buckets
3. Restrict security group/NSG/firewall rules
4. Enable encryption on all storage

Reports generated:
- reports/aws-audit.html
- reports/azure-audit.html
- reports/gcp-audit.html
- reports/multi-cloud-summary.html
```

---

## Troubleshooting

### Authentication Issues

**AWS: Access Denied**
```bash
# Check current identity
aws sts get-caller-identity

# Check permissions
aws iam simulate-principal-policy --policy-source-arn arn:aws:iam::ACCOUNT:user/USER \
  --action-names iam:ListUsers s3:ListBuckets ec2:DescribeInstances
```

**Azure: Subscription Not Found**
```bash
# List subscriptions
az account list

# Set correct subscription
az account set --subscription "SUBSCRIPTION_NAME"
```

**GCP: Permission Denied**
```bash
# Check current account
gcloud auth list

# Check project permissions
gcloud projects get-iam-policy PROJECT_ID --filter="bindings.members:user:YOUR_EMAIL"
```

---

## Checklists Reference

| Checklist | Purpose |
|-----------|---------|
| [checklists/aws_cis_v3.md](checklists/aws_cis_v3.md) | AWS CIS Benchmark v3.0 |
| [checklists/azure_cis_v2.md](checklists/azure_cis_v2.md) | Azure CIS Benchmark v2.0 |
| [checklists/gcp_cis_v2.md](checklists/gcp_cis_v2.md) | GCP CIS Benchmark v2.0 |
| [checklists/quick_wins.md](checklists/quick_wins.md) | Fast critical checks |
| [checklists/iam_audit.md](checklists/iam_audit.md) | IAM deep dive |
| [checklists/storage_audit.md](checklists/storage_audit.md) | Storage security |

---

## Templates Reference

| Template | Purpose |
|----------|---------|
| [templates/finding_template.md](templates/finding_template.md) | Individual finding |
| [templates/executive_summary.md](templates/executive_summary.md) | Executive report |
| [templates/remediation_guide.md](templates/remediation_guide.md) | Fix guidance |
| [templates/compliance_report.md](templates/compliance_report.md) | Compliance status |

---

## Related Resources

- [AWS Security Hub](https://aws.amazon.com/security-hub/)
- [Azure Security Center](https://azure.microsoft.com/en-us/services/security-center/)
- [Google Cloud Security Command Center](https://cloud.google.com/security-command-center)
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks)
- [Prowler](https://github.com/prowler-cloud/prowler)
- [ScoutSuite](https://github.com/nccgroup/ScoutSuite)

---

## Bundled Scripts

### scripts/
- `aws_security_audit.py` - Comprehensive AWS security audit
- `azure_security_audit.py` - Comprehensive Azure security audit
- `gcp_security_audit.py` - Comprehensive GCP security audit
- `iam_analyzer.py` - Multi-cloud IAM policy analyzer
- `storage_scanner.py` - Storage bucket/blob security scanner
- `network_auditor.py` - Network security configuration audit
- `compliance_checker.py` - CIS benchmark compliance checker
- `secret_scanner.py` - Exposed secrets and credentials scanner
- `cloud_report_generator.py` - Multi-format report generator
- `remediation_generator.py` - Auto-generate remediation scripts

### policies/
- `aws_audit_policy.json` - Minimum IAM policy for AWS audit
- `azure_audit_role.json` - Minimum role for Azure audit
- `gcp_audit_role.yaml` - Minimum role for GCP audit
