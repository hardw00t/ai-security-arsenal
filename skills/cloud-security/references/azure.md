# Azure Security Reference

Command reference and pitfall catalog for Azure and Entra ID (formerly Azure AD). Load when `cloud_provider == azure`.

## Authentication Setup

```bash
# Interactive login
az login

# Service Principal
az login --service-principal \
  -u CLIENT_ID \
  -p CLIENT_SECRET \
  --tenant TENANT_ID

# Managed identity (from an Azure VM)
az login --identity

# Select subscription & verify context
az account list --output table
az account set --subscription "SUBSCRIPTION_ID"
az account show

# Enumerate all subscriptions the identity can see
az account list --all --query "[].{Name:name,Id:id,Tenant:tenantId}" -o table
```

Minimum recommended read roles: `Reader` + `Security Reader` at the management group or subscription scope. For Entra ID enumeration: `Global Reader` or `Directory Readers`.

## Assessment Tools

```bash
# ScoutSuite (CLI auth or SP)
scout azure --cli --report-dir ./scout-azure
scout azure --service-principal \
  --tenant-id TENANT --client-id ID --client-secret SECRET

# Prowler v4+ for Azure
prowler azure --az-cli-auth --compliance cis_2.1_azure
prowler azure --sp-env-auth --services storage keyvault network

# PowerZure / ROADtools for deeper Entra work
roadrecon auth -u user@tenant.com -p PASSWORD
roadrecon gather
roadrecon gui
```

## Azure Resource Manager (ARM) Layer

```bash
# Role assignments
az role assignment list --all \
  --query "[].{Principal:principalName,Role:roleDefinitionName,Scope:scope}" -o table

# Privileged assignments
az role assignment list --role "Owner" --all
az role assignment list --role "Contributor" --all
az role assignment list --role "User Access Administrator" --all

# Resource inventory
az resource list --output table

# Activity log (admin actions)
az monitor activity-log list \
  --start-time 2026-04-01 \
  --query "[?operationName.value=='Microsoft.Authorization/roleAssignments/write']"

# Resource Graph queries (fast, KQL-based, cross-subscription)
az graph query -q "Resources | where type =~ 'microsoft.storage/storageaccounts' \
  | where properties.allowBlobPublicAccess == true \
  | project name, resourceGroup, subscriptionId"
```

## Entra ID (Azure AD)

```bash
# Users / groups / apps
az ad user list --query "[].{UPN:userPrincipalName,Id:id}" -o table
az ad group list --query "[].{Name:displayName,Id:id}" -o table
az ad app list --all --query "[].{Name:displayName,AppId:appId}" -o table

# Service principals
az ad sp list --all --query "[].{Name:displayName,AppId:appId,Id:id}" -o table

# App registrations with credentials (look for old secrets/certs)
az ad app list --all \
  --query "[?length(passwordCredentials)>0 || length(keyCredentials)>0].{Name:displayName,AppId:appId,Secrets:length(passwordCredentials)}"

# Privileged directory roles (Global Admin, Privileged Role Admin, App Admin, etc.)
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/directoryRoles"

# Role members
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/directoryRoles/{role-id}/members"

# Conditional Access policies
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
```

See `methodology/iam_privilege_escalation.md` for Entra-specific escalation paths (Application Admin → service principal → Graph API).

## Storage Accounts

```bash
az storage account list -o table

# Public blob access
az storage account show --name ACCOUNT \
  --query "{PublicAccess:allowBlobPublicAccess,SharedKey:allowSharedKeyAccess,TlsVersion:minimumTlsVersion,HttpsOnly:enableHttpsTrafficOnly}"

# Network rules (default action should be Deny)
az storage account network-rule list --account-name ACCOUNT

# Container-level public access
az storage container list --account-name ACCOUNT --auth-mode login \
  --query "[].{Name:name,PublicAccess:properties.publicAccess}" -o table

# Anonymous blob probe
curl https://ACCOUNT.blob.core.windows.net/CONTAINER?restype=container\&comp=list

# SAS token scrutiny (look for long-lived, overly-permissive tokens in code/logs)
```

## Key Vault

```bash
az keyvault list -o table

# Per-vault access policies (legacy) vs RBAC (preferred)
az keyvault show --name VAULT \
  --query "{RbacEnabled:properties.enableRbacAuthorization,SoftDelete:properties.enableSoftDelete,Purge:properties.enablePurgeProtection,Network:properties.networkAcls}"

# Legacy access policies
az keyvault show --name VAULT --query "properties.accessPolicies"

# Can we list/read secrets/keys/certs?
az keyvault secret list --vault-name VAULT
az keyvault key list --vault-name VAULT
az keyvault certificate list --vault-name VAULT

# Firewall rules
az keyvault network-rule list --name VAULT
```

## Networking

```bash
# NSG rules allowing wide-open ingress
az network nsg list -o table
az network nsg rule list --nsg-name NSG --resource-group RG \
  --query "[?sourceAddressPrefix=='*' || sourceAddressPrefix=='Internet' || sourceAddressPrefix=='0.0.0.0/0']"

# Public IPs
az network public-ip list \
  --query "[?ipAddress!=null].{Name:name,IP:ipAddress,AssocTo:ipConfiguration.id}" -o table

# Exposed management ports (RDP/SSH)
az graph query -q "Resources | where type =~ 'microsoft.network/networksecuritygroups' \
  | mv-expand rules = properties.securityRules \
  | where rules.properties.access == 'Allow' \
    and rules.properties.direction == 'Inbound' \
    and (rules.properties.destinationPortRange in ('22','3389') or rules.properties.sourceAddressPrefix in ('*','Internet','0.0.0.0/0')) \
  | project name, rule=rules.name, port=rules.properties.destinationPortRange, src=rules.properties.sourceAddressPrefix"
```

## Virtual Machines

```bash
# Public-facing VMs
az vm list-ip-addresses -o table

# Managed identity attached?
az vm identity show --resource-group RG --name VM

# Disk encryption
az vm encryption show --resource-group RG --name VM

# Just-in-Time VM access policy
az security jit-policy list
```

## Defender for Cloud / Security Center

```bash
# Defender plans per subscription
az security pricing list -o table

# Assessments
az security assessment list --query "[?status.code=='Unhealthy']" -o table

# Secure score
az security secure-score list
```

## Common Azure Misconfigurations

### Critical
- [ ] Storage accounts with `allowBlobPublicAccess=true`
- [ ] Key Vault access policies with wildcard permissions or open to broad groups
- [ ] No MFA on privileged accounts (Global Admin, Priv Role Admin)
- [ ] Service Principal with Owner or Contributor at subscription/management group root
- [ ] Exposed management ports (RDP/3389, SSH/22) to `*` / Internet
- [ ] `allowSharedKeyAccess=true` on storage accounts in sensitive environments

### High
- [ ] NSGs too permissive (`0.0.0.0/0` on service ports)
- [ ] Entra ID users with standing Global Admin (should be PIM-gated)
- [ ] Defender for Cloud disabled on critical resource types
- [ ] Diagnostic settings not configured (activity logs not forwarded)
- [ ] Azure Policy not enforced at management-group level
- [ ] App registrations with expired-but-still-present client secrets / long-lived secrets

### Medium
- [ ] Managed disk encryption using PMK only (no CMK)
- [ ] Activity log retention < 90 days / not exported
- [ ] Resource locks not applied to prod subscriptions
- [ ] Azure Bastion not used (direct RDP/SSH exposure instead)
- [ ] Just-in-time VM access disabled
- [ ] Minimum TLS version < 1.2 on storage / App Services

## IMDS (Instance Metadata Service)

```bash
# Azure IMDS — requires `Metadata: true` header; no response if header missing
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/instance?api-version=2021-02-01"

# Managed identity token
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"

# Specific resource token
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net"
```

## Last validated: 2026-04

- Azure CLI 2.60+
- ScoutSuite 5.14+
- Prowler v4.0+ (Azure support)
- ROADtools 2.x
