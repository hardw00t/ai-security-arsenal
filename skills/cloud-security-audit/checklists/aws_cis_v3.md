# AWS CIS Benchmark v3.0.0 Audit Checklist

## 1. Identity and Access Management

### 1.1 Account Setup
- [ ] 1.4 Ensure MFA is enabled for the root user
- [ ] 1.5 Ensure no access keys exist for root user
- [ ] 1.6 Ensure hardware MFA is enabled for root user (Level 2)

### 1.2 Password Policy
- [ ] 1.8 Ensure IAM password policy requires minimum length of 14+
- [ ] 1.9 Ensure IAM password policy prevents password reuse (24+)
- [ ] 1.10 Ensure MFA is enabled for all IAM users with console password

### 1.3 Access Keys
- [ ] 1.12 Ensure credentials unused for 45+ days are disabled
- [ ] 1.13 Ensure there is only one active access key per user
- [ ] 1.14 Ensure access keys are rotated every 90 days or less

### 1.4 IAM Policies
- [ ] 1.15 Ensure IAM policies that allow full "*:*" admin privileges are not attached
- [ ] 1.16 Ensure IAM policies are attached only to groups or roles
- [ ] 1.17 Ensure a support role has been created for incident handling
- [ ] 1.19 Ensure IAM instance roles are used for AWS resource access

### 1.5 IAM Access Analyzer
- [ ] 1.20 Ensure IAM Access Analyzer is enabled for all regions
- [ ] 1.21 Ensure that all expired SSL/TLS certificates are removed

---

## 2. Storage

### 2.1 S3
- [ ] 2.1.1 Ensure S3 Bucket Policy allows HTTPS only
- [ ] 2.1.2 Ensure MFA Delete is enabled on S3 buckets
- [ ] 2.1.3 Ensure all data in S3 has been discovered and classified
- [ ] 2.1.4 Ensure S3 buckets are configured with 'Block public access'
- [ ] 2.1.5 Ensure S3 bucket ACL does not grant 'Everyone' access

### 2.2 EBS
- [ ] 2.2.1 Ensure EBS volume encryption is enabled in all regions

### 2.3 RDS
- [ ] 2.3.1 Ensure RDS database instances are not publicly accessible
- [ ] 2.3.2 Ensure Auto Minor Version Upgrade is enabled for RDS
- [ ] 2.3.3 Ensure RDS instances have Multi-AZ enabled

---

## 3. Logging

### 3.1 CloudTrail
- [ ] 3.1 Ensure CloudTrail is enabled in all regions
- [ ] 3.2 Ensure CloudTrail log file validation is enabled
- [ ] 3.3 Ensure S3 bucket used for CloudTrail logging is not publicly accessible
- [ ] 3.4 Ensure CloudTrail trails are integrated with CloudWatch Logs
- [ ] 3.5 Ensure AWS Config is enabled in all regions
- [ ] 3.6 Ensure S3 bucket access logging is enabled on CloudTrail S3 bucket
- [ ] 3.7 Ensure CloudTrail logs are encrypted at rest using KMS CMKs
- [ ] 3.8 Ensure rotation for customer-created CMKs is enabled
- [ ] 3.9 Ensure VPC flow logging is enabled in all VPCs
- [ ] 3.10 Ensure object-level logging for write events is enabled for S3 buckets
- [ ] 3.11 Ensure object-level logging for read events is enabled for S3 buckets

---

## 4. Monitoring

### 4.1 CloudWatch Alarms
- [ ] 4.1 Ensure unauthorized API calls alarm exists
- [ ] 4.2 Ensure console sign-in without MFA alarm exists
- [ ] 4.3 Ensure root account usage alarm exists
- [ ] 4.4 Ensure IAM policy changes alarm exists
- [ ] 4.5 Ensure CloudTrail configuration changes alarm exists
- [ ] 4.6 Ensure AWS Management Console authentication failures alarm exists
- [ ] 4.7 Ensure disabling/deletion of CMKs alarm exists
- [ ] 4.8 Ensure S3 bucket policy changes alarm exists
- [ ] 4.9 Ensure AWS Config configuration changes alarm exists
- [ ] 4.10 Ensure security group changes alarm exists
- [ ] 4.11 Ensure Network ACL changes alarm exists
- [ ] 4.12 Ensure network gateway changes alarm exists
- [ ] 4.13 Ensure route table changes alarm exists
- [ ] 4.14 Ensure VPC changes alarm exists
- [ ] 4.15 Ensure AWS Organizations changes alarm exists

### 4.2 Security Hub
- [ ] 4.16 Ensure AWS Security Hub is enabled

---

## 5. Networking

### 5.1 VPC
- [ ] 5.1 Ensure no Network ACLs allow ingress from 0.0.0.0/0 to remote admin ports
- [ ] 5.2 Ensure no security groups allow ingress from 0.0.0.0/0 to remote admin ports
- [ ] 5.3 Ensure no security groups allow ingress from ::/0 to remote admin ports
- [ ] 5.4 Ensure default security group restricts all traffic
- [ ] 5.5 Ensure routing tables for VPC peering are "least access"
- [ ] 5.6 Ensure EC2 Metadata Service (IMDS) requires IMDSv2

---

## Quick Check Commands

```bash
# 1.4 - Root MFA
aws iam get-account-summary --query 'SummaryMap.AccountMFAEnabled'

# 1.5 - Root access keys
aws iam get-credential-report
# Check if root has access_key_1_active or access_key_2_active

# 1.8 - Password policy
aws iam get-account-password-policy

# 1.14 - Access key rotation
aws iam list-access-keys --user-name USER
aws iam get-access-key-last-used --access-key-id KEY

# 2.1.4 - S3 public access block
aws s3api get-public-access-block --bucket BUCKET

# 2.2.1 - EBS encryption default
aws ec2 get-ebs-encryption-by-default

# 3.1 - CloudTrail enabled
aws cloudtrail describe-trails
aws cloudtrail get-trail-status --name TRAIL

# 5.1/5.2 - Security groups
aws ec2 describe-security-groups \
  --query 'SecurityGroups[?IpPermissions[?IpRanges[?CidrIp==`0.0.0.0/0`]]]'

# 5.6 - IMDSv2
aws ec2 describe-instances \
  --query 'Reservations[].Instances[].{ID:InstanceId,IMDS:MetadataOptions.HttpTokens}'
```

---

## Automated Tools

```bash
# Prowler - Full CIS check
prowler aws --compliance cis_3.0_aws

# ScoutSuite
scout aws --report-dir ./scoutsuite-report

# AWS Security Hub CIS Standard
# Enable in AWS Console: Security Hub > Security standards > CIS AWS Foundations
```
