# Terraform Security Reference

Terraform-specific scanning commands, common misconfigurations, and custom policy authoring.

## Scanners

### Checkov

```bash
# Scan directory
checkov -d /path/to/terraform

# Single file
checkov -f main.tf

# Output formats
checkov -d . -o json      > results.json
checkov -d . -o sarif     > results.sarif
checkov -d . -o junitxml  > results.xml

# Framework filter (useful when repo mixes IaC types)
checkov -d . --framework terraform

# Skip / include specific checks
checkov -d . --skip-check CKV_AWS_1,CKV_AWS_2
checkov -d . --check      CKV_AWS_20,CKV_AWS_21

# Custom checks directory
checkov -d . --external-checks-dir /path/to/custom_checks

# Scan a Terraform plan (more accurate for dynamic values)
terraform plan -out=tfplan.binary
terraform show -json tfplan.binary > tfplan.json
checkov -f tfplan.json
```

### tfsec

```bash
tfsec /path/to/terraform

# Output formats
tfsec . --format json  > tfsec-results.json
tfsec . --format sarif > tfsec-results.sarif
tfsec . --format csv   > tfsec-results.csv

# Minimum severity gate
tfsec . --minimum-severity HIGH

# Exclude specific checks
tfsec . --exclude aws-s3-enable-bucket-logging

# Include passed checks (useful for compliance evidence)
tfsec . --include-passed

# Soft fail (exit 0 even with issues) — CI warning-only mode
tfsec . --soft-fail

# Custom checks
tfsec . --custom-check-dir /path/to/custom
```

### Terrascan

```bash
terrascan scan -t terraform

# Cloud policy pack
terrascan scan -t terraform -p aws
terrascan scan -t terraform --policy-type aws --policy-path /custom/policies

# Output formats
terrascan scan -t terraform -o json  > terrascan.json
terrascan scan -t terraform -o sarif > terrascan.sarif

# Don't recurse into child modules
terrascan scan -t terraform --non-recursive
```

## Common Misconfigurations (triage order)

### Critical
- S3 buckets without encryption (CKV_AWS_19, aws-s3-enable-bucket-encryption)
- Security groups with `0.0.0.0/0` ingress on sensitive ports (22, 3389, 3306, 5432)
- RDS instances publicly accessible (`publicly_accessible = true`)
- IAM policies with `"Action": "*"` or `"Resource": "*"`
- Hardcoded secrets in variables / outputs (use `gitleaks` alongside)
- KMS keys without key rotation (`enable_key_rotation = false`)

### High
- EBS volumes unencrypted
- CloudTrail not enabled account-wide
- VPC flow logs disabled
- ALB without HTTPS listener or weak TLS policy
- Missing resource tagging (compliance/ownership)
- Default VPC in use

### Medium
- S3 buckets without versioning
- Missing lifecycle policies
- Overly permissive security groups (wide port ranges)
- Missing backup / snapshot configurations
- Weak TLS configurations on endpoints

## Custom Policy Authoring

### Checkov Python check

```python
# custom_checks/s3_custom.py
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.common.models.enums import CheckResult, CheckCategories

class S3BucketCustomCheck(BaseResourceCheck):
    def __init__(self):
        name = "Ensure S3 bucket has Environment tag"
        id = "CKV_CUSTOM_1"
        supported_resources = ['aws_s3_bucket']
        categories = [CheckCategories.GENERAL_SECURITY]
        super().__init__(name=name, id=id, categories=categories,
                         supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        tags = conf.get('tags', [{}])[0]
        if tags.get('Environment'):
            return CheckResult.PASSED
        return CheckResult.FAILED

check = S3BucketCustomCheck()
```

### Checkov YAML check

```yaml
# custom_checks/s3_naming.yaml
metadata:
  id: CKV_CUSTOM_2
  name: S3 bucket name must follow naming convention
  category: CONVENTION
  severity: LOW
scope:
  provider: aws
definition:
  cond_type: attribute
  resource_types:
    - aws_s3_bucket
  attribute: bucket
  operator: regex_match
  value: "^(dev|staging|prod)-[a-z0-9-]+$"
```

### tfsec custom check

```yaml
# .tfsec/custom_checks.yaml
checks:
  - code: CUS001
    description: S3 bucket must have Department tag
    impact: Billing and ownership tracking affected
    resolution: Add Department tag to bucket
    requiredTypes:
      - resource
    requiredLabels:
      - aws_s3_bucket
    severity: LOW
    matchSpec:
      name: tags
      action: contains
      value: Department
    errorMessage: S3 bucket missing required Department tag
```

## Inline Suppressions

```hcl
# Checkov
#checkov:skip=CKV_AWS_20:Bucket is explicitly a public website
resource "aws_s3_bucket" "website" {
  bucket = "my-site"
  acl    = "public-read"
}

# tfsec
#tfsec:ignore:aws-s3-no-public-access-with-acl
resource "aws_s3_bucket" "website" { ... }
```

Always require a justification after the rule ID; unjustified suppressions are themselves a finding.
