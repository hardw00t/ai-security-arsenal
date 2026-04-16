# CI/CD Integration Reference

Wire IaC scanners into PR gates and pre-commit hooks.

## GitHub Actions

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

Put each scanner in its own job so they run concurrently.

## GitLab CI

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

## Pre-commit Hooks

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

## Gate policy recommendation

- `pre-commit`: fast scanners only (tfsec, cfn-lint). Hard fail only on `CRITICAL`.
- `PR check`: full scanner fleet in parallel. Hard fail on `HIGH`+, warning on `MEDIUM`.
- `main branch / nightly`: add KICS + Conftest/OPA policy suite. Emit SARIF to centralized dashboard.

## Compliance framework filters

| Framework        | Checkov flag           | tfsec flag   |
|------------------|------------------------|--------------|
| CIS AWS          | `--check CKV_AWS_*`    | Built-in     |
| CIS Azure        | `--check CKV_AZURE_*`  | Built-in     |
| CIS GCP          | `--check CKV_GCP_*`    | Built-in     |
| CIS Kubernetes   | `--check CKV_K8S_*`    | N/A          |

```bash
# Map Checkov findings to BC/compliance IDs
checkov -d . --framework terraform --check CKV_AWS_* --output-bc-ids
checkov -d . --list | grep -i encryption
```
