# AWS Security Reference

Command reference and pitfall catalog for AWS security assessment. Load this when `cloud_provider == aws`.

## Authentication Setup

```bash
# Configure AWS CLI
aws configure

# Or via environment variables
export AWS_ACCESS_KEY_ID="AKIA..."
export AWS_SECRET_ACCESS_KEY="..."
export AWS_SESSION_TOKEN="..."     # if STS
export AWS_DEFAULT_REGION="us-east-1"

# Cross-account assume role
aws sts assume-role \
  --role-arn arn:aws:iam::ACCOUNT:role/AuditRole \
  --role-session-name audit-$(date +%s) \
  --duration-seconds 3600

# Verify current identity (always run first)
aws sts get-caller-identity
```

Minimum viable read-only audit policy: `arn:aws:iam::aws:policy/SecurityAudit` + `ViewOnlyAccess`. Prefer `ReadOnlyAccess` for deeper enumeration; avoid anything broader unless explicitly authorized.

## Prowler

```bash
# Full assessment (all checks, all services)
prowler aws

# CIS Benchmark (use latest — v3.0+ supersedes 2.0)
prowler aws --compliance cis_3.0_aws

# Other compliance profiles
prowler aws --compliance pci_3.2.1_aws soc2_aws hipaa_aws nist_800_53_revision_5_aws

# Scope by service
prowler aws --services iam s3 ec2 rds

# Scope by severity
prowler aws --severity critical high

# Specific checks (comma-separated)
prowler aws --checks iam_user_mfa_enabled_console_access iam_root_hardware_mfa_enabled

# Multi-format output
prowler aws -M csv html json-ocsf

# Legacy groupings (still work in recent Prowler)
prowler aws -g iam           # Identity
prowler aws -g logging       # Logging
prowler aws -g monitoring    # Monitoring
prowler aws -g networking    # Networking
```

## IAM Enumeration

```bash
# Start with account-wide authorization details (one-shot dump)
aws iam get-account-authorization-details > iam-dump.json

# Users, roles, groups, policies
aws iam list-users
aws iam list-roles
aws iam list-groups
aws iam list-policies --scope Local
aws iam list-policies --only-attached --scope Local

# Credentials report (CSV — MFA, key age, password age)
aws iam generate-credential-report
aws iam get-credential-report --query Content --output text | base64 -d

# Access Analyzer external findings
aws accessanalyzer list-analyzers
aws accessanalyzer list-findings --analyzer-arn ARN

# Blind enumeration (no list perms) — use enumerate-iam
enumerate-iam --access-key AKIA... --secret-key ...

# Deep enumeration + privesc scanning with Pacu
pacu
> import_keys --access-key AKIA... --secret-key ...
> run iam__enum_permissions
> run iam__enum_users_roles_policies_groups
> run iam__privesc_scan
```

See `methodology/iam_privilege_escalation.md` for the 22+ known AWS privesc vectors.

## S3 / Storage

```bash
# Enumerate buckets in account
aws s3api list-buckets

# Policy & ACL
aws s3api get-bucket-policy --bucket BUCKET
aws s3api get-bucket-policy-status --bucket BUCKET
aws s3api get-bucket-acl --bucket BUCKET
aws s3api get-public-access-block --bucket BUCKET
aws s3api get-bucket-encryption --bucket BUCKET
aws s3api get-bucket-versioning --bucket BUCKET
aws s3api get-bucket-logging --bucket BUCKET
aws s3api get-bucket-ownership-controls --bucket BUCKET

# External / public scan
s3scanner scan --bucket-file buckets.txt
s3scanner scan --bucket target-bucket

# Unauthenticated probes
aws s3 ls s3://bucket-name --no-sign-request
aws s3 cp test.txt s3://bucket-name --no-sign-request

# Block Public Access precedence: account-level > bucket-level > policy/ACL
aws s3control get-public-access-block --account-id $(aws sts get-caller-identity --query Account --output text)
```

Storage pitfalls to confirm per bucket: Block Public Access disabled, bucket policy allows `Principal: "*"`, ACL grants `AllUsers`/`AuthenticatedUsers`, bucket website/static hosting enabled without auth, replication to unowned account, MFA Delete not enabled on versioned buckets with sensitive data.

## EC2 / VPC / Networking

```bash
# Security groups wide open
aws ec2 describe-security-groups \
  --query "SecurityGroups[?IpPermissions[?IpRanges[?CidrIp=='0.0.0.0/0']]].[GroupId,GroupName,VpcId]" \
  --output table

# Public EC2 instances
aws ec2 describe-instances \
  --query "Reservations[].Instances[?PublicIpAddress!=null].[InstanceId,PublicIpAddress,Tags[?Key=='Name'].Value|[0]]" \
  --output table

# IMDSv2 enforcement (IMDSv1 enabled = SSRF -> creds)
aws ec2 describe-instances \
  --query "Reservations[].Instances[?MetadataOptions.HttpTokens=='optional'].InstanceId"

# VPC flow logs disabled
aws ec2 describe-flow-logs
aws ec2 describe-vpcs --query "Vpcs[].VpcId" --output text

# Unused EIPs, default VPCs still active, NACLs allowing all
aws ec2 describe-vpcs --filters Name=isDefault,Values=true
```

## RDS / Databases

```bash
aws rds describe-db-instances \
  --query "DBInstances[?PubliclyAccessible==\`true\`].[DBInstanceIdentifier,Endpoint.Address]"

aws rds describe-db-snapshots --snapshot-type public
aws rds describe-db-cluster-snapshots --snapshot-type public

# Encryption
aws rds describe-db-instances \
  --query "DBInstances[?StorageEncrypted==\`false\`].DBInstanceIdentifier"
```

## Logging & Monitoring

```bash
# CloudTrail: multi-region + log file validation + KMS
aws cloudtrail describe-trails
aws cloudtrail get-trail-status --name TRAIL

# GuardDuty detector per region
for r in $(aws ec2 describe-regions --query "Regions[].RegionName" --output text); do
  aws guardduty list-detectors --region $r
done

# Config recorder + Security Hub
aws configservice describe-configuration-recorders
aws securityhub get-enabled-standards
```

## Common AWS Misconfigurations

### Critical
- [ ] Public S3 buckets with sensitive data
- [ ] IAM users with `AdministratorAccess` or `*:*`
- [ ] Root account used for daily operations
- [ ] No MFA on root or privileged accounts
- [ ] Hardcoded credentials in Lambda env vars / EC2 user-data
- [ ] IMDSv1 enabled on EC2 (SSRF -> role credentials)

### High
- [ ] Security groups with `0.0.0.0/0` on 22/3389/3306/5432/etc.
- [ ] RDS instances / snapshots publicly accessible
- [ ] CloudTrail disabled or single-region only
- [ ] Default VPC in use for production workloads
- [ ] IAM policies with `Resource: "*"` on write actions
- [ ] S3 Block Public Access disabled at account level

### Medium
- [ ] S3 buckets without versioning / MFA Delete
- [ ] EBS volumes / snapshots unencrypted
- [ ] Access keys > 90 days old
- [ ] VPC flow logs disabled
- [ ] GuardDuty / Security Hub not enabled in all regions

## Metadata / IMDS

```
# IMDSv1 (vulnerable)
curl http://169.254.169.254/latest/meta-data/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME
curl http://169.254.169.254/latest/user-data/

# IMDSv2 (token required)
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

## Regional Enumeration Pattern

Always iterate regions — findings commonly hide in unused regions where logging/monitoring is off:

```bash
for r in $(aws ec2 describe-regions --query "Regions[].RegionName" --output text); do
  echo "=== $r ==="
  aws s3api list-buckets --region $r
  aws ec2 describe-instances --region $r
  aws rds describe-db-instances --region $r
done
```

## Last validated: 2026-04

- AWS CLI v2.15+
- Prowler v4.0+
- Pacu 1.5+
