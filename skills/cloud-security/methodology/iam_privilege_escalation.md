# IAM Privilege Escalation — Cross-Cloud Methodology

Enumerate and prove privilege escalation paths in cloud IAM. This is the highest-reasoning workflow in the skill — engage extended thinking when building the escalation graph.

## General approach

1. **Map the current principal.** Who am I? What roles/perms do I have?
2. **Enumerate reachable principals.** Who can I impersonate, assume, or abuse to get to?
3. **Build the hop graph.** `(me) -permission-> (intermediate) -permission-> (target)`.
4. **Identify terminal privilege.** The "win" is usually an admin-equivalent role (`AdministratorAccess`, `roles/owner`, `Owner`, Global Admin, or the ability to create one).
5. **Prove exploitability safely.** Dry-run where possible; coordinate with the account owner before modifying policies.

Graph traversal is non-trivial — use `pmapper` (AWS), `roadrecon` GUI (Azure), or build your own graph from asset inventory SQL. Extended thinking helps spot non-obvious multi-hop chains.

---

## AWS — Known Privilege Escalation Vectors

Rhino Security's catalog (still the canonical list, with additions). Test each against your enumerated permission set.

| # | Vector | Minimum permission(s) | Outcome |
|---|--------|------------------------|---------|
| 1 | CreatePolicyVersion | `iam:CreatePolicyVersion` | Overwrite default policy version with admin access |
| 2 | SetDefaultPolicyVersion | `iam:SetDefaultPolicyVersion` | Switch to an older, more permissive policy version |
| 3 | AttachUserPolicy | `iam:AttachUserPolicy` | Attach `AdministratorAccess` to self |
| 4 | AttachGroupPolicy | `iam:AttachGroupPolicy` + group membership | Attach admin to a group I belong to |
| 5 | AttachRolePolicy | `iam:AttachRolePolicy` + `sts:AssumeRole` on role | Attach admin to an assumable role |
| 6 | PutUserPolicy | `iam:PutUserPolicy` | Inline admin policy on self |
| 7 | PutGroupPolicy | `iam:PutGroupPolicy` | Inline admin on containing group |
| 8 | PutRolePolicy | `iam:PutRolePolicy` + assumable role | Inline admin on assumable role |
| 9 | AddUserToGroup | `iam:AddUserToGroup` | Add self to admin group |
| 10 | UpdateLoginProfile | `iam:UpdateLoginProfile` | Reset another user's console password |
| 11 | CreateLoginProfile | `iam:CreateLoginProfile` | Create console password for user without one |
| 12 | CreateAccessKey | `iam:CreateAccessKey` | Create access keys for another user |
| 13 | PassExistingRoleToNewLambda | `iam:PassRole` + `lambda:CreateFunction` + `lambda:InvokeFunction` | Lambda assumes powerful role, exfil creds |
| 14 | PassRoleToExistingLambda | `iam:PassRole` + `lambda:UpdateFunctionCode` | Modify code of Lambda with powerful role |
| 15 | PassExistingRoleToNewGlueDevEndpoint | `iam:PassRole` + `glue:CreateDevEndpoint` | SSH into Glue endpoint, use role creds |
| 16 | PassExistingRoleToCloudFormation | `iam:PassRole` + `cloudformation:CreateStack` | Stack executes with powerful role |
| 17 | PassExistingRoleToDataPipeline | `iam:PassRole` + `datapipeline:CreatePipeline` | Pipeline runs arbitrary EC2 as role |
| 18 | EditExistingLambdaFunctionWithRole | `lambda:UpdateFunctionCode` | Modify existing Lambda to exfil creds |
| 19 | PassExistingRoleToNewEC2 | `iam:PassRole` + `ec2:RunInstances` + SSH/SSM | Launch EC2, extract IMDS role creds |
| 20 | UpdateRolePolicyToAssumeIt | `iam:UpdateAssumeRolePolicy` | Modify trust policy to allow self to assume |
| 21 | sts:AssumeRole on privileged role | `sts:AssumeRole` with matching trust | Directly become a more privileged role |
| 22 | CodeBuild / CodePipeline role abuse | `codebuild:UpdateProject` + build role has `PassRole` | Run code as build role |
| 23 | SSM RunCommand / SendCommand | `ssm:SendCommand` on instance with powerful instance profile | Exec arbitrary commands as role |
| 24 | EventBridge/EventsPutTargets | `events:PutRule` + `events:PutTargets` + `iam:PassRole` | Schedule Lambda with powerful role |

### AWS enumeration workflow

```bash
# 1. Identity
aws sts get-caller-identity

# 2. Full permission dump via simulator
POLICY_ARNS=$(aws iam list-attached-user-policies --user-name ME --query 'AttachedPolicies[].PolicyArn' --output text)
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::ACCOUNT:user/ME \
  --action-names iam:CreatePolicyVersion iam:AttachUserPolicy iam:PassRole lambda:UpdateFunctionCode \
  --resource-arns '*'

# 3. Pacu automation
pacu
> run iam__enum_permissions
> run iam__privesc_scan

# 4. PMapper graph-based
pmapper graph create
pmapper query "preset privesc ME"
pmapper query "who can do iam:PassRole with arn:aws:iam::*:role/AdminRole"
```

---

## GCP — Privilege Escalation Vectors

| # | Vector | Permission | Outcome |
|---|--------|-----------|---------|
| 1 | Service Account Key Creation | `iam.serviceAccountKeys.create` | Create key for privileged SA, auth as it |
| 2 | Service Account Impersonation | `iam.serviceAccounts.getAccessToken` or `actAs` | Mint token for privileged SA |
| 3 | SetIamPolicy on project | `resourcemanager.projects.setIamPolicy` | Grant self Owner |
| 4 | SetIamPolicy on SA | `iam.serviceAccounts.setIamPolicy` | Grant self `iam.serviceAccountTokenCreator` on target SA |
| 5 | Cloud Function deploy / update | `cloudfunctions.functions.update` + SA with privileges | Run arbitrary code as function's SA |
| 6 | Cloud Run deploy | `run.services.setIamPolicy` + `run.services.update` + `iam.serviceAccounts.actAs` | Run code as privileged SA |
| 7 | Compute instance create with SA | `compute.instances.create` + `iam.serviceAccounts.actAs` | SSH in, use metadata token |
| 8 | Compute instance setMetadata (SSH keys) | `compute.instances.setMetadata` | Add SSH key to instance running as privileged SA |
| 9 | Compute project setCommonInstanceMetadata | `compute.projects.setCommonInstanceMetadata` | Project-wide SSH key → any instance |
| 10 | Dataflow / Dataproc job create | `dataflow.jobs.create` / `dataproc.jobs.create` + actAs | Run code as worker SA |
| 11 | GKE cluster workload identity abuse | `container.clusters.get` + pod deploy | Pod assumes bound KSA → GSA |
| 12 | Deployment Manager deploy | `deploymentmanager.deployments.create` | Runs as `cloudservices` SA (project-owner-equivalent historically) |

### GCP enumeration

```bash
# Who am I
gcloud auth list
gcloud config list

# My direct bindings
gcloud projects get-iam-policy PROJECT_ID \
  --flatten="bindings[].members" \
  --format="value(bindings.role,bindings.members)" | grep "$(gcloud config get-value account)"

# Test specific permissions (batched)
gcloud iam list-testable-permissions //cloudresourcemanager.googleapis.com/projects/PROJECT_ID

gcloud iam test-iam-permissions PROJECT_ID \
  --permissions=iam.serviceAccountKeys.create,iam.serviceAccounts.getAccessToken,resourcemanager.projects.setIamPolicy

# Cloud Asset Inventory for cross-resource discovery
gcloud asset search-all-iam-policies --scope=projects/PROJECT_ID \
  --query="policy.role.permissions:iam.serviceAccountKeys.create"
```

---

## Azure / Entra ID — Privilege Escalation Vectors

### ARM (Resource) layer

| # | Vector | Required | Outcome |
|---|--------|---------|---------|
| 1 | User Access Administrator | Role assignment | Assign Owner to self on any scope |
| 2 | Owner at management group | Role assignment | Propagates down to all subscriptions |
| 3 | VM Contributor + runCommand | `Microsoft.Compute/virtualMachines/runCommand/action` | Execute as VM's managed identity |
| 4 | Managed Identity token theft | VM access (SSH/RDP/runCommand) | IMDS → token → acts as MI |
| 5 | Automation Account RunAs abuse | Automation Contributor | Runbooks often have Contributor+ |
| 6 | Key Vault secret read | `Microsoft.KeyVault/vaults/secrets/getSecret/action` | Extract SP creds / certs |
| 7 | Logic Apps + Managed Identity | `Microsoft.Logic/workflows/write` | Invoke with MI privileges |
| 8 | Deployment Scripts (ARM) | `Microsoft.Resources/deployments/write` | Execute as user-assigned MI |

### Entra ID layer

| # | Vector | Required | Outcome |
|---|--------|---------|---------|
| E1 | Global Admin | Built-in role | Full tenant |
| E2 | Privileged Role Administrator | Built-in role | Can elevate any principal |
| E3 | Application Administrator | Built-in role | Add credential to any non-privileged app, auth as SP, pivot |
| E4 | Cloud Application Administrator | Built-in role | Same as E3, no on-prem apps |
| E5 | Directory Synchronization Accounts | Hidden role | Sync account → Global Admin equivalent (AADConnect abuse) |
| E6 | Owner of SP / App | Ownership | Add client secret, auth as SP |
| E7 | Conditional Access bypass | Misconfigured CA | Legacy auth endpoints skip MFA |
| E8 | Service Principal with high Graph API perms | `RoleManagement.ReadWrite.Directory` etc. | Assign Global Admin via Graph |

### Azure enumeration

```bash
# Current context
az account show
az ad signed-in-user show

# My role assignments
az role assignment list --assignee $(az ad signed-in-user show --query id -o tsv) --all

# Group memberships (transitive)
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/me/transitiveMemberOf"

# Directory roles I hold
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/me/memberOf/microsoft.graph.directoryRole"

# ROADtools for full enumeration + offline analysis
roadrecon auth -u user@tenant.com -p PASSWORD
roadrecon gather
roadrecon gui
```

---

## Reasoning Budget Guidance

- **Enumerate permissions** → minimal thinking, tool-driven.
- **Match against known vectors (this file)** → minimal thinking; straightforward table lookup.
- **Multi-hop chains across principals / services** → extended thinking. Draw the graph, verify each edge, confirm trust relationships and resource scopes.
- **Cross-cloud escalation (federated identities, AWS-Azure-GCP links)** → extended thinking + explicit graph.

## Evidence to capture per finding

For each escalation path, record into `schemas/finding.json`:
- `privilege_escalation_path`: ordered principals / permissions / targets
- `evidence.cli_command` + `evidence.cli_output` proving each hop (or dry-run equivalent)
- `evidence.policy_document`: the offending policy JSON
- `detection`: the CloudTrail / Activity Log / Audit Log event name that would fire on exploitation
