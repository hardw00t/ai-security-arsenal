# CloudFormation Security Reference

CloudFormation (YAML / JSON) scanning, lint, and security checklist.

## Scanners

### Checkov

```bash
# Single template
checkov -f template.yaml --framework cloudformation

# Directory
checkov -d ./cfn-templates --framework cloudformation

# With parameters file (resolves !Ref values for more accurate checks)
checkov -f template.yaml --var-file parameters.json
```

### cfn-lint

```bash
pip install cfn-lint

# Basic lint
cfn-lint template.yaml

# Include extra rule packs
cfn-lint template.yaml -a /path/to/additional/rules

# Ignore specific rules
cfn-lint template.yaml -i W3002
```

`cfn-lint` catches schema / resource-property problems that security scanners miss (bad intrinsic functions, invalid resource types). Run it BEFORE security scans to avoid noise from malformed templates.

### cfn-nag

```bash
gem install cfn-nag

# Scan
cfn_nag_scan --input-path template.yaml

# JSON output
cfn_nag_scan --input-path template.yaml --output-format json

# Rule suppression via metadata
#   Metadata:
#     cfn_nag:
#       rules_to_suppress:
#         - id: W41
#           reason: "Bucket is public by design"
```

### KICS

```bash
docker run -v /path/to/cfn:/path checkmarx/kics scan -p /path -t CloudFormation

docker run -v "$(pwd)":/path checkmarx/kics scan \
  -p /path \
  -t CloudFormation \
  -o /path \
  --report-formats json,sarif
```

## Security Checklist

### IAM
- [ ] No inline policies with `Action: "*"` or `Resource: "*"`
- [ ] Roles use least privilege
- [ ] `ManagedPolicyArns` preferred over inline
- [ ] No hardcoded credentials in `Parameters` or `Metadata`
- [ ] `AssumeRolePolicyDocument` scoped to specific principals

### Encryption
- [ ] S3 buckets encrypted (`BucketEncryption` with SSE-S3 or SSE-KMS)
- [ ] RDS `StorageEncrypted: true`
- [ ] EBS `Encrypted: true`
- [ ] SQS `KmsMasterKeyId` set
- [ ] SNS `KmsMasterKeyId` set
- [ ] Secrets Manager / SSM Parameter Store for secrets (not `Parameters` with `NoEcho`)

### Network
- [ ] Security groups restrictive (no `0.0.0.0/0` on admin ports)
- [ ] NACLs properly configured
- [ ] VPC endpoints for AWS services (S3, DynamoDB, KMS)
- [ ] No public IPs on internal resources (`AssociatePublicIpAddress: false`)

### Logging & Monitoring
- [ ] CloudTrail enabled (multi-region, log file validation)
- [ ] VPC flow logs configured
- [ ] Access logging on S3 / ALB / CloudFront
- [ ] CloudWatch log retention set (not default infinite)

## Inline Suppressions

```yaml
Resources:
  MyBucket:
    Type: AWS::S3::Bucket
    Metadata:
      checkov:
        skip:
          - id: CKV_AWS_18
            comment: "Access logs live in sibling bucket"
      cfn_nag:
        rules_to_suppress:
          - id: W35
            reason: "Access logs live in sibling bucket"
```
