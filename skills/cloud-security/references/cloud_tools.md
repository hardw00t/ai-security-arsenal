# Cloud Security Tools Reference

Comparison and invocation cheatsheet for multi-cloud assessment tooling.

## Tool Selection Matrix

| Tool        | AWS | Azure | GCP | Strengths                                              | Weaknesses                            |
|-------------|-----|-------|-----|--------------------------------------------------------|---------------------------------------|
| ScoutSuite  | Yes | Yes   | Yes | Broad HTML dashboard, easy read-only runs              | Slower, heavier on API calls          |
| Prowler     | Yes | Yes   | Yes | Deep AWS CIS coverage, CLI-native, JSON-OCSF output    | Requires more permissions for depth   |
| CloudSploit | Yes | Yes   | Yes | Fast triage, simple CI integration                     | Less deep than Prowler                |
| Steampipe   | Yes | Yes   | Yes | Declarative SQL across clouds, scriptable pipelines    | Learning curve on plugin schemas      |
| Pacu        | Yes | No    | No  | Offensive AWS modules, privesc scanning, persistence   | AWS-only, not for compliance scoring  |
| ROADtools   | No  | Yes*  | No  | Entra ID deep enumeration, offline analysis            | *Azure AD / Graph only (no ARM)       |
| PMapper     | Yes | No    | No  | IAM privilege escalation graph analysis                | AWS IAM-only                          |

Recommended default stack:
- **Read-only compliance scan**: Prowler + ScoutSuite (both clouds where available) + Steampipe for deep-dive SQL.
- **Offensive / privesc focused**: Pacu (AWS) + ROADtools (Azure/Entra) + manual gcloud enumeration (GCP).

## ScoutSuite

```bash
pip install scoutsuite

scout aws   --profile default --report-dir ./scout-aws
scout azure --cli            --report-dir ./scout-azure
scout gcp   --project-id ID  --report-dir ./scout-gcp

# Ruleset selection
scout aws --ruleset cis_v1.2.0
scout aws --ruleset detailed

# Offline render (if DB already collected)
scout aws --offline --report-dir ./scout-aws
```

Color codes in the HTML dashboard: red (Danger) = critical, orange (Warning) = high, grey = info.

## Prowler

```bash
pip install prowler

# Full assessments
prowler aws
prowler azure --az-cli-auth
prowler gcp   --project-ids PROJECT_ID

# Compliance frameworks
prowler aws --compliance cis_3.0_aws pci_3.2.1_aws nist_800_53_revision_5_aws

# Severity filter (triage fast)
prowler aws --severity critical high

# Service scoping
prowler aws --services iam s3 ec2

# Output
prowler aws -M csv html json-ocsf json-asff

# Allowlist false positives
prowler aws --allowlist-file allowlist.yaml
```

OCSF output integrates with AWS Security Hub and SIEMs. Prefer `json-ocsf` for pipelines.

## CloudSploit

```bash
npm install -g cloudsploit

# Config file approach
cat > config.js <<'EOF'
module.exports = { credentials: { aws: { access_key: '...', secret_key: '...' } } };
EOF

cloudsploit scan --config config.js --cloud aws

# Compliance profile
cloudsploit scan --compliance cis1 --cloud aws

# Specific plugin (check)
cloudsploit scan --plugin s3Encryption --cloud aws
```

## Steampipe

```bash
# Install
brew install turbot/tap/steampipe

# Plugins
steampipe plugin install aws azure gcp

# Interactive shell
steampipe query
> .inspect aws_s3_bucket   -- list columns
> SELECT name FROM aws_s3_bucket WHERE bucket_policy_is_public = true;

# Scripted
steampipe query ./audit.sql --output json > results.json
steampipe query ./audit.sql --output csv  > results.csv

# Multi-account / multi-region via aggregators (configure in ~/.steampipe/config/aws.spc)
```

See `references/steampipe_queries.sql` for a working pattern library.

## Pacu (AWS offense)

```bash
pip install pacu

pacu
> new_session audit-2026-04
> import_keys --access-key AKIA... --secret-key ...

# Enumerate what the key can do
> run iam__enum_permissions
> run iam__enum_users_roles_policies_groups

# Privesc scan (22+ known vectors)
> run iam__privesc_scan

# Data exfiltration / secondary
> run s3__download_bucket
> run ec2__download_userdata
> run lambda__search
```

## ROADtools (Entra ID)

```bash
pip install roadrecon

# Collect
roadrecon auth -u user@tenant.com -p PASSWORD
roadrecon gather           # enumerates users, groups, apps, SPs, roles, devices

# Analyze
roadrecon gui              # launches local web UI at http://127.0.0.1:5000

# Query
roadrecon dump users
roadrecon dump servicePrincipals
```

## PMapper (AWS IAM graph)

```bash
pip install principalmapper

# Build graph for current account
pmapper graph create

# Query escalation paths
pmapper query "preset privesc *"
pmapper query "who can do iam:PassRole with * ?"
pmapper query "preset connected alice bob"

# Visualize
pmapper visualize
```

Essential when you suspect multi-hop privilege escalation via roles.

## Other handy utilities

```bash
# enumerate-iam — blind IAM enumeration with minimal perms
enumerate-iam --access-key AKIA... --secret-key ...

# s3scanner — external S3 bucket discovery
s3scanner scan --bucket-file buckets.txt

# GCPBucketBrute — similar for GCS
python3 gcpbucketbrute.py -k keywords.txt

# MicroBurst (Azure offense, PowerShell)
# https://github.com/NetSPI/MicroBurst
```

## When NOT to use these tools

- **Container workload scanning inside EKS/GKE/AKS** → use `container-security` skill (kubectl, kube-bench, trivy).
- **Pre-deployment IaC misconfig (Terraform, CloudFormation, ARM, Bicep)** → use `iac-security` skill (checkov, tfsec, terrascan).
- **Application-layer pentesting of apps running in the cloud** → use `api-security` or `dast-automation`.

## Last validated: 2026-04

- Prowler v4.0+
- ScoutSuite 5.14+
- Steampipe 0.22+
- Pacu 1.5+
