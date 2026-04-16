# ARM / Bicep Security Reference

Azure Resource Manager templates (JSON) and Bicep (DSL that compiles to ARM).

## Scanners

### Checkov for ARM

```bash
# Single template
checkov -f azuredeploy.json --framework arm

# Directory
checkov -d ./arm-templates --framework arm
```

### Checkov for Bicep

```bash
# Bicep support requires the bicep CLI on PATH
checkov -d ./bicep --framework bicep
```

For Bicep, Checkov transpiles to ARM under the hood; errors usually mean `bicep` isn't installed or the file has unresolved module refs.

### KICS for ARM

```bash
docker run -v "$(pwd)":/path checkmarx/kics scan \
  -p /path \
  -t AzureResourceManager \
  -o /path
```

### PSRule for Azure

```bash
# In CI
Install-Module -Name PSRule.Rules.Azure -Scope CurrentUser
Invoke-PSRule -InputPath './templates/' -Module PSRule.Rules.Azure
```

PSRule is the Microsoft-first-party option; rule IDs map directly to Azure Security Benchmark.

### Bicep-native linter

```bash
bicep build main.bicep   # Emits warnings for deprecated / insecure patterns
bicep lint  main.bicep
```

## Security Checklist

### Storage
- [ ] `supportsHttpsTrafficOnly: true` on storage accounts
- [ ] `allowBlobPublicAccess: false`
- [ ] `minimumTlsVersion: TLS1_2`
- [ ] `networkAcls.defaultAction: Deny` with explicit allowlist
- [ ] Encryption at rest enabled (default) + CMK where required

### Compute
- [ ] VMs use managed disks (no unmanaged page blobs)
- [ ] OS / data disk encryption enabled (`encryptionSettings`)
- [ ] No public IP where unnecessary
- [ ] Update management configured
- [ ] `osProfile.linuxConfiguration.disablePasswordAuthentication: true` (SSH keys only)

### Network
- [ ] NSG rules restrictive — no `sourceAddressPrefix: "*"` on admin ports
- [ ] Azure Firewall / WAF where needed
- [ ] Private endpoints for PaaS (Storage, Key Vault, SQL)
- [ ] `publicNetworkAccess: Disabled` where supported

### Identity
- [ ] Managed Identity preferred over service principals with secrets
- [ ] No hardcoded credentials in `parameters` / `variables`
- [ ] Key Vault references for secrets (`@Microsoft.KeyVault(...)`)
- [ ] RBAC role assignments scoped to resource / resource group (not subscription)

### Logging
- [ ] Diagnostic settings enabled with Log Analytics / Storage destinations
- [ ] Activity Log export configured
- [ ] Azure Policy diagnostic settings compliance

## Inline Suppressions (ARM JSON)

```json
{
  "type": "Microsoft.Storage/storageAccounts",
  "metadata": {
    "checkov": {
      "skip": [
        { "id": "CKV_AZURE_33", "comment": "Queue logs handled centrally" }
      ]
    }
  }
}
```
