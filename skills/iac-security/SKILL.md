---
name: iac-security
description: "Infrastructure as Code security scanning skill for Terraform, CloudFormation, Kubernetes manifests, Helm charts, and ARM templates. This skill should be used when auditing IaC configurations for misconfigurations, scanning Terraform plans, validating Kubernetes security policies, checking cloud infrastructure compliance, or integrating security into CI/CD pipelines. Triggers on requests to scan Terraform, audit CloudFormation, check Kubernetes manifests, validate Helm charts, or find IaC security issues."
---

# Infrastructure as Code Security

This skill enables comprehensive security scanning of Infrastructure as Code configurations including Terraform, CloudFormation, Kubernetes manifests, Helm charts, Pulumi, and ARM templates using tools like Checkov, tfsec, Terrascan, KICS, and kubesec.

## When to Use This Skill

This skill should be invoked when:
- Scanning Terraform configurations for security misconfigurations
- Auditing CloudFormation templates
- Validating Kubernetes manifests and Helm charts
- Checking ARM templates for Azure security
- Verifying compliance with CIS benchmarks
- Integrating security scanning into CI/CD pipelines
- Reviewing infrastructure changes before deployment

### Trigger Phrases
- "scan this Terraform for security issues"
- "audit my CloudFormation template"
- "check Kubernetes manifests for misconfigurations"
- "validate Helm chart security"
- "IaC security scan"
- "check infrastructure compliance"

---

## Prerequisites

### Required Tools

| Tool | Purpose | Installation |
|------|---------|--------------|
| Checkov | Multi-framework IaC scanner | `pip install checkov` |
| tfsec | Terraform security scanner | `brew install tfsec` or `go install github.com/aquasecurity/tfsec/cmd/tfsec@latest` |
| Terrascan | Multi-cloud IaC scanner | `brew install terrascan` |
| KICS | Keeping Infrastructure as Code Secure | Docker or binary from GitHub |
| kubesec | Kubernetes manifest scanner | `brew install kubesec` |
| Trivy | Config scanning (IaC mode) | `brew install trivy` |
| OPA/Conftest | Policy-as-code testing | `brew install conftest` |

---

## Quick Start Workflow

```markdown
1. **Identify IaC Type**
   - Terraform (.tf, .tf.json)
   - CloudFormation (.yaml, .json, .template)
   - Kubernetes (.yaml, .yml)
   - Helm (Chart.yaml, templates/)
   - ARM (.json)
   - Pulumi (various)

2. **Initial Scan**
   - Run Checkov for comprehensive coverage
   - Run specialized tool (tfsec for TF, kubesec for K8s)

3. **Analyze Results**
   - Prioritize by severity (CRITICAL, HIGH)
   - Group by category (IAM, encryption, network)

4. **Remediation**
   - Fix critical issues first
   - Use framework documentation
   - Re-scan to verify fixes

5. **CI/CD Integration**
   - Add to pipeline
   - Set failure thresholds
   - Generate reports
```

---

## Terraform Security Scanning

### Checkov for Terraform

```bash
# Scan entire directory
checkov -d /path/to/terraform

# Scan specific file
checkov -f main.tf

# Output formats
checkov -d . -o json > results.json
checkov -d . -o sarif > results.sarif
checkov -d . -o junitxml > results.xml

# With specific framework
checkov -d . --framework terraform

# Skip specific checks
checkov -d . --skip-check CKV_AWS_1,CKV_AWS_2

# Run specific checks only
checkov -d . --check CKV_AWS_20,CKV_AWS_21

# External checks from custom policies
checkov -d . --external-checks-dir /path/to/custom_checks
```

### tfsec Scanning

```bash
# Basic scan
tfsec /path/to/terraform

# Output formats
tfsec . --format json > tfsec-results.json
tfsec . --format sarif > tfsec-results.sarif
tfsec . --format csv > tfsec-results.csv

# Minimum severity
tfsec . --minimum-severity HIGH

# Exclude specific checks
tfsec . --exclude aws-s3-enable-bucket-logging

# Include passed checks
tfsec . --include-passed

# Soft fail (exit 0 even with issues)
tfsec . --soft-fail

# Custom check directory
tfsec . --custom-check-dir /path/to/custom
```

### Terrascan for Terraform

```bash
# Scan Terraform
terrascan scan -t terraform

# Scan with specific policy
terrascan scan -t terraform -p aws

# Output formats
terrascan scan -t terraform -o json > terrascan.json
terrascan scan -t terraform -o sarif > terrascan.sarif

# Scan remote modules
terrascan scan -t terraform --non-recursive

# Use specific policies
terrascan scan -t terraform --policy-type aws --policy-path /custom/policies
```

### Common Terraform Misconfigurations

```markdown
### Critical
- [ ] S3 buckets without encryption
- [ ] Security groups with 0.0.0.0/0 ingress
- [ ] RDS instances publicly accessible
- [ ] IAM policies with * actions/resources
- [ ] Hardcoded secrets in variables
- [ ] KMS keys without rotation

### High
- [ ] EBS volumes unencrypted
- [ ] CloudTrail not enabled
- [ ] VPC flow logs disabled
- [ ] ALB without HTTPS
- [ ] Missing resource tagging
- [ ] Default VPC in use

### Medium
- [ ] S3 buckets without versioning
- [ ] Missing lifecycle policies
- [ ] Overly permissive security groups
- [ ] Missing backup configurations
- [ ] Weak TLS configurations
```

---

## CloudFormation Security Scanning

### Checkov for CloudFormation

```bash
# Scan CloudFormation templates
checkov -f template.yaml --framework cloudformation

# Scan directory
checkov -d ./cfn-templates --framework cloudformation

# With parameters file
checkov -f template.yaml --var-file parameters.json
```

### cfn-lint Integration

```bash
# Install
pip install cfn-lint

# Basic lint
cfn-lint template.yaml

# With specific rules
cfn-lint template.yaml -a /path/to/additional/rules

# Ignore rules
cfn-lint template.yaml -i W3002
```

### KICS for CloudFormation

```bash
# Using Docker
docker run -v /path/to/cfn:/path checkmarx/kics scan -p /path -t CloudFormation

# Output formats
docker run -v $(pwd):/path checkmarx/kics scan \
  -p /path \
  -t CloudFormation \
  -o /path \
  --report-formats json,sarif
```

### CloudFormation Security Checklist

```markdown
### IAM
- [ ] No inline policies with *
- [ ] Roles use least privilege
- [ ] ManagedPolicyArns preferred over inline
- [ ] No hardcoded credentials

### Encryption
- [ ] S3 buckets encrypted (SSE-S3 or SSE-KMS)
- [ ] RDS encryption enabled
- [ ] EBS volumes encrypted
- [ ] SQS/SNS encryption enabled

### Network
- [ ] Security groups restrictive
- [ ] NACLs properly configured
- [ ] VPC endpoints for AWS services
- [ ] No public IPs on internal resources

### Logging
- [ ] CloudTrail enabled
- [ ] VPC flow logs configured
- [ ] Access logging on S3/ALB
- [ ] CloudWatch log retention set
```

---

## Kubernetes Manifest Security

### kubesec Scanning

```bash
# Scan single manifest
kubesec scan deployment.yaml

# Scan via stdin
cat deployment.yaml | kubesec scan -

# JSON output
kubesec scan deployment.yaml -o json

# Remote scanning (HTTP API)
curl -sSX POST --data-binary @deployment.yaml https://v2.kubesec.io/scan
```

### Checkov for Kubernetes

```bash
# Scan Kubernetes manifests
checkov -d ./k8s-manifests --framework kubernetes

# Scan Helm charts
checkov -d ./helm-chart --framework helm

# Scan kustomize
checkov -d ./kustomize --framework kustomize
```

### Trivy Config Scanning

```bash
# Scan Kubernetes manifests
trivy config ./k8s-manifests

# Scan with specific severity
trivy config --severity HIGH,CRITICAL ./k8s-manifests

# Output formats
trivy config -f json -o results.json ./k8s-manifests

# Scan Helm chart
trivy config ./my-chart
```

### OPA/Conftest for Kubernetes

```bash
# Install conftest
brew install conftest

# Test manifests against policies
conftest test deployment.yaml -p policy/

# Pull policies from OPA bundle
conftest pull oci://ghcr.io/policies/kubernetes

# Test with specific namespace
conftest test deployment.yaml -p policy/ --namespace kubernetes
```

### Kubernetes Security Policies (OPA Rego)

```rego
# policy/deployment.rego

package kubernetes

# Deny containers running as root
deny[msg] {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    not container.securityContext.runAsNonRoot
    msg := sprintf("Container %s must set runAsNonRoot", [container.name])
}

# Deny privileged containers
deny[msg] {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    container.securityContext.privileged
    msg := sprintf("Container %s must not be privileged", [container.name])
}

# Require resource limits
deny[msg] {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    not container.resources.limits
    msg := sprintf("Container %s must define resource limits", [container.name])
}

# Deny hostNetwork
deny[msg] {
    input.kind == "Deployment"
    input.spec.template.spec.hostNetwork
    msg := "Deployments must not use hostNetwork"
}

# Require read-only root filesystem
deny[msg] {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    not container.securityContext.readOnlyRootFilesystem
    msg := sprintf("Container %s should use readOnlyRootFilesystem", [container.name])
}
```

### Kubernetes Security Checklist

```markdown
### Pod Security
- [ ] runAsNonRoot: true
- [ ] readOnlyRootFilesystem: true
- [ ] allowPrivilegeEscalation: false
- [ ] privileged: false
- [ ] capabilities dropped (ALL)
- [ ] seccompProfile defined

### Resource Management
- [ ] CPU/memory limits set
- [ ] CPU/memory requests set
- [ ] No hostPID/hostIPC
- [ ] No hostNetwork
- [ ] No hostPath volumes

### Network
- [ ] NetworkPolicies defined
- [ ] Ingress TLS configured
- [ ] Service account tokens auto-mounted only when needed

### Images
- [ ] Images from trusted registries
- [ ] Image tags pinned (no :latest)
- [ ] Image pull policy: Always for production
- [ ] Image signing verified

### RBAC
- [ ] Least privilege service accounts
- [ ] No cluster-admin bindings
- [ ] Namespace-scoped roles preferred
```

---

## Helm Chart Security

### Helm Template Scanning

```bash
# Render templates then scan
helm template my-release ./my-chart > rendered.yaml
checkov -f rendered.yaml --framework kubernetes

# Or with values
helm template my-release ./my-chart -f values-prod.yaml > rendered.yaml
kubesec scan rendered.yaml
```

### Checkov Helm Native

```bash
# Direct Helm chart scanning
checkov -d ./my-chart --framework helm

# With values file
checkov -d ./my-chart --framework helm --var-file values-prod.yaml
```

### Chart.yaml Security

```markdown
### Verify
- [ ] appVersion pinned to specific version
- [ ] dependencies from trusted repos
- [ ] kubeVersion constraints set
- [ ] No deprecated API versions
```

---

## ARM Template Security

### Checkov for ARM

```bash
# Scan ARM templates
checkov -f azuredeploy.json --framework arm

# Scan directory
checkov -d ./arm-templates --framework arm
```

### KICS for ARM

```bash
# Scan ARM with KICS
docker run -v $(pwd):/path checkmarx/kics scan \
  -p /path \
  -t AzureResourceManager \
  -o /path
```

### ARM Security Checklist

```markdown
### Storage
- [ ] Storage accounts HTTPS only
- [ ] Blob public access disabled
- [ ] Network rules configured
- [ ] Encryption enabled

### Compute
- [ ] VMs with managed disks
- [ ] Disk encryption enabled
- [ ] No public IP where unnecessary
- [ ] Update management configured

### Network
- [ ] NSG rules restrictive
- [ ] No * in NSG rules
- [ ] Azure Firewall/WAF where needed
- [ ] Private endpoints for PaaS

### Identity
- [ ] Managed Identity preferred
- [ ] No hardcoded credentials
- [ ] Key Vault for secrets
- [ ] RBAC properly scoped
```

---

## CI/CD Integration

### GitHub Actions

```yaml
name: IaC Security Scan

on:
  pull_request:
    paths:
      - 'terraform/**'
      - 'k8s/**'
      - 'cloudformation/**'

jobs:
  checkov:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run Checkov
        uses: bridgecrewio/checkov-action@v12
        with:
          directory: .
          framework: terraform,kubernetes,cloudformation
          output_format: sarif
          output_file_path: checkov.sarif
          soft_fail: false

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: checkov.sarif

  tfsec:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run tfsec
        uses: aquasecurity/tfsec-action@v1.0.0
        with:
          working_directory: terraform/
          soft_fail: false

  trivy-config:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run Trivy config scan
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: 'config'
          scan-ref: '.'
          severity: 'HIGH,CRITICAL'
          exit-code: '1'
```

### GitLab CI

```yaml
stages:
  - security

checkov:
  stage: security
  image: bridgecrew/checkov:latest
  script:
    - checkov -d . --framework terraform,kubernetes -o junitxml > checkov.xml
  artifacts:
    reports:
      junit: checkov.xml
  only:
    changes:
      - "**/*.tf"
      - "**/*.yaml"
      - "**/*.yml"

tfsec:
  stage: security
  image: aquasec/tfsec:latest
  script:
    - tfsec . --format junit > tfsec.xml
  artifacts:
    reports:
      junit: tfsec.xml
  only:
    changes:
      - "**/*.tf"
```

### Pre-commit Hooks

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/antonbabenko/pre-commit-terraform
    rev: v1.83.0
    hooks:
      - id: terraform_fmt
      - id: terraform_validate
      - id: terraform_tfsec
      - id: checkov
        args: ['--framework', 'terraform']

  - repo: https://github.com/zricethezav/gitleaks
    rev: v8.18.0
    hooks:
      - id: gitleaks
```

---

## Custom Policy Development

### Checkov Custom Policies (Python)

```python
# custom_checks/s3_custom.py
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.common.models.enums import CheckResult, CheckCategories

class S3BucketCustomCheck(BaseResourceCheck):
    def __init__(self):
        name = "Ensure S3 bucket has custom tag"
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

### Checkov Custom Policies (YAML)

```yaml
# custom_checks/s3_custom.yaml
metadata:
  id: CKV_CUSTOM_2
  name: Ensure S3 bucket name follows naming convention
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

### tfsec Custom Checks

```yaml
# .tfsec/custom_checks.yaml
checks:
  - code: CUS001
    description: S3 bucket must have department tag
    impact: Billing and ownership tracking affected
    resolution: Add department tag to bucket
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

---

## Compliance Frameworks

### CIS Benchmarks

| Framework | Checkov Flag | tfsec Flag |
|-----------|--------------|------------|
| CIS AWS | `--check CKV_AWS_*` | Built-in |
| CIS Azure | `--check CKV_AZURE_*` | Built-in |
| CIS GCP | `--check CKV_GCP_*` | Built-in |
| CIS Kubernetes | `--check CKV_K8S_*` | N/A |

### SOC 2 / PCI DSS Mapping

```bash
# Checkov with compliance framework
checkov -d . --framework terraform --check CKV_AWS_* --output-bc-ids

# Filter by guideline
checkov -d . --list | grep -i encryption
```

---

## Reporting Template

```markdown
# IaC Security Scan Report

## Executive Summary
- Scan date: YYYY-MM-DD
- Framework(s) scanned: Terraform/K8s/CFN
- Total findings: X
- Critical: X | High: X | Medium: X | Low: X

## Findings by Category

### IAM/Access Control
| ID | Severity | Resource | Description |
|----|----------|----------|-------------|
| CKV_AWS_40 | HIGH | aws_iam_policy.admin | IAM policy with * actions |

### Encryption
| ID | Severity | Resource | Description |
|----|----------|----------|-------------|
| CKV_AWS_19 | HIGH | aws_s3_bucket.data | S3 bucket missing encryption |

### Network Security
| ID | Severity | Resource | Description |
|----|----------|----------|-------------|
| CKV_AWS_24 | CRITICAL | aws_security_group.web | 0.0.0.0/0 ingress on port 22 |

## Remediation Priority
1. [CRITICAL] Fix security group CKV_AWS_24
2. [HIGH] Enable S3 encryption CKV_AWS_19
3. [HIGH] Restrict IAM policy CKV_AWS_40

## Tool Versions
- Checkov: X.X.X
- tfsec: X.X.X
- Terrascan: X.X.X
```

---

## Bundled Resources

### scripts/
- `scan_all.sh` - Multi-tool IaC scanning automation
- `merge_results.py` - Combine results from multiple scanners
- `generate_report.py` - Create consolidated HTML report

### references/
- `cis_mappings.md` - CIS benchmark control mappings
- `checkov_checks.md` - Common Checkov check reference
- `remediation_snippets.md` - Quick fix code snippets

### checklists/
- `terraform_audit.md` - Terraform security audit checklist
- `kubernetes_audit.md` - Kubernetes manifest audit checklist
- `cloudformation_audit.md` - CloudFormation audit checklist
