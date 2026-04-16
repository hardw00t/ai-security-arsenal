# Workflow: Full Azure Security Assessment

End-to-end assessment across one or more Azure subscriptions plus the Entra ID tenant.

## Preconditions

- `az account show` returns a valid context.
- Minimum: `Reader` + `Security Reader` at management group or subscription.
- For Entra: `Global Reader` or at minimum `Directory Readers`.
- Scope confirmed: subscription IDs, management group, tenant, exclusions.

## Phase 0: Context & scope

```bash
az account show                   > ctx-identity.json
az account list --all             > ctx-subscriptions.json
az account management-group list  > ctx-mgmt-groups.json
az ad signed-in-user show         > ctx-ad-user.json
```

## Phase 1: Broad scanner sweep (parallel)

```bash
scout azure --cli --report-dir scout-azure/ &
prowler azure --az-cli-auth --compliance cis_2.1_azure -M json-ocsf -o prowler-azure/ &
steampipe query references/steampipe_queries.sql --output json > steampipe-azure.json &
wait
```

For Entra-specific enumeration:

```bash
roadrecon auth -u USER -p PASSWORD      # or device-code auth
roadrecon gather
# Results in roadrecon.db; analyze with `roadrecon gui`
```

## Phase 2: ARM (Resource) role assignments

```bash
# All role assignments at subscription root
az role assignment list --all --subscription SUB_ID \
  --query "[?scope=='/subscriptions/SUB_ID']" > role-assignments-root.json

# Privileged roles anywhere
for role in "Owner" "Contributor" "User Access Administrator"; do
  az role assignment list --role "$role" --all > role-$(echo $role | tr ' ' '_').json
done

# Custom role definitions
az role definition list --custom-role-only true > custom-roles.json
```

**Extended thinking**: identify horizontal/vertical escalation via MI → ARM → Key Vault → SP creds.

## Phase 3: Entra ID deep dive

```bash
# Directory roles and members
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/directoryRoles" > entra-roles.json

# Privileged directory role members (Global Admin etc.)
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/directoryRoles?\$expand=members" > entra-role-members.json

# Applications + service principals
az ad app list --all > apps.json
az ad sp list --all > sps.json

# Apps with long-lived secrets
az ad app list --all \
  --query "[?length(passwordCredentials) > \`0\`]" > apps-with-secrets.json

# Conditional Access
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" > ca-policies.json
```

See `methodology/iam_privilege_escalation.md` for Entra-specific vectors (App Admin, MI abuse, CA bypass).

## Phase 4: Per-service audits (parallel)

| Sub-agent | Scope |
|-----------|-------|
| storage   | Storage Accounts, Blob, Files, Queues, Tables |
| compute   | VMs, Scale Sets, App Services, Functions, Container Apps |
| data      | SQL, Cosmos DB, Synapse, Data Lake |
| network   | VNets, NSGs, Public IPs, App Gateways, Front Door |
| secrets   | Key Vault, App Service config, Automation variables |
| logging   | Defender for Cloud, Activity Log, Diagnostic Settings, Sentinel |
| aks       | AKS control plane (workload → container-security) |

Multi-subscription environments: fan out one sub-agent per subscription.

## Phase 5: Resource Graph bulk queries

Azure Resource Graph (KQL) is the fastest way to answer "across all my subs, show me…":

```bash
# Unencrypted managed disks
az graph query -q "Resources | where type =~ 'microsoft.compute/disks' \
  | where properties.encryption.type !~ 'EncryptionAtRestWithCustomerKey' \
  | project name,resourceGroup,subscriptionId"

# VMs with public IP
az graph query -q "Resources | where type =~ 'microsoft.network/publicipaddresses' \
  | where isnotempty(properties.ipAddress) \
  | project ip=properties.ipAddress, attachedTo=properties.ipConfiguration.id"
```

## Phase 6: Reporting

Same output pattern:
- Findings conforming to `schemas/finding.json`.
- `cis_benchmark_id` for CIS-Azure-x.y; include `CIS-AzureAD` where Entra-specific.
- Detection gap: Azure Activity Log `operationName`, Sentinel/Defender alert IDs.

## Output artifacts

```
azure-assessment-YYYY-MM-DD/
├── ctx-*
├── role-assignments-root.json
├── role-Owner.json
├── role-Contributor.json
├── role-User_Access_Administrator.json
├── custom-roles.json
├── entra-*.json
├── ca-policies.json
├── apps-with-secrets.json
├── scout-azure/
├── prowler-azure/
├── roadrecon.db
├── steampipe-azure.json
├── findings/
└── report.md
```

## Parallelism summary

- Scanner sweep + ROADtools gather: parallel.
- Per-subscription audits: parallel — one sub-agent per subscription.
- Per-service within a subscription: parallel.

## Reasoning budget summary

- Scanner orchestration, enumeration: minimal.
- Entra + ARM role cross-layer privesc analysis: extended.
- Conditional Access gap analysis: extended.
