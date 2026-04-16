# Trust Boundary Patterns

Catalog of common trust boundaries to look for when building a DFD. For each boundary: what crosses, what controls belong there, typical weaknesses.

## 1. Internet ↔ DMZ

**What crosses**: All external user traffic (HTTPS), inbound APIs from partners, outbound DNS/HTTPS.
**Controls**: WAF, DDoS protection, TLS termination, rate limiting, bot detection, geofencing.
**Typical weaknesses**:
- Direct-to-origin bypass of WAF
- Legacy cleartext endpoints still reachable
- Weak TLS versions / ciphers
- Open management ports (SSH, RDP)

## 2. DMZ ↔ Internal Network

**What crosses**: Reverse-proxy forwarded requests, auth callbacks, egress traffic.
**Controls**: Stateful firewall, mTLS between tiers, private routing, egress proxy, network segmentation.
**Typical weaknesses**:
- Flat internal network (no segmentation past DMZ)
- Management / CI-CD network connected to app network
- DMZ host used as pivot

## 3. Application Tier ↔ Data Tier

**What crosses**: DB queries, cache reads/writes, object storage calls.
**Controls**: Network ACLs, DB firewall, minimum-privilege DB accounts, row-level security, encrypted channels, secrets rotation.
**Typical weaknesses**:
- DB reachable from developer laptops
- App connects as super-user
- Credentials in env vars / source code
- No query audit

## 4. User ↔ Admin (privilege boundary)

**What crosses**: Admin API calls, role-change requests, billing changes.
**Controls**: Separate admin domain, MFA + SSO, step-up auth for sensitive operations, four-eyes approval, admin VLAN / bastion.
**Typical weaknesses**:
- Admin endpoints reachable from same domain
- Privilege check at UI but not API
- Stolen user session can trivially add admin role
- No audit of admin actions

## 5. Tenant A ↔ Tenant B (multi-tenant isolation)

**What crosses**: Nothing (in theory). In practice: shared infrastructure.
**Controls**: Tenant ID on every query, row-level security, per-tenant encryption keys, per-tenant rate limits, cache key segregation, observability per tenant.
**Typical weaknesses**:
- Missing WHERE tenant_id on one query → full bypass
- Shared cache key across tenants
- Common crypto keys across tenants (no crypto segregation)
- Cross-tenant identifiers predictable (sequential IDs)

## 6. Production ↔ Non-Production

**What crosses**: Logs/metrics (shouldn't be reverse), shared services (auth?).
**Controls**: Zero overlap in accounts/keys/networks, data masking for lower envs, access approvals for prod, secrets separated.
**Typical weaknesses**:
- Prod data copied to staging for testing
- Shared KMS/secrets manager
- Developer VPN reaches prod
- CI pipeline deploys prod from developer laptops

## 7. Control Plane ↔ Data Plane

**What crosses**: Configuration pushes, telemetry, management commands.
**Controls**: mTLS + strong identity on control plane, signed configuration, control-plane change audit, bulkhead data plane from control plane failure.
**Typical weaknesses**:
- Control-plane compromise = total compromise
- Control plane reachable from internet
- Unsigned config can be tampered in transit
- No blast-radius limits

## 8. Client Code ↔ Server Code

**What crosses**: Browser/mobile app sends data/tokens to backend.
**Controls**: Treat client as untrusted, authn/authz all server-side, integrity checks on inputs, rate limits, anti-replay (nonces, timestamps), CSRF/CSP for browsers, cert pinning for mobile.
**Typical weaknesses**:
- Client-side business logic (price in HTML form)
- Client-side authz (route-guard only, no server check)
- Shared secret in mobile app binary
- Hidden fields assumed untamperable

## 9. Microservice A ↔ Microservice B

**What crosses**: Internal RPC (gRPC, HTTP, event bus).
**Controls**: Workload identity (SPIFFE/SPIRE), mTLS, service-mesh policy, per-service secrets, request propagation context, zero-trust — never trust "it's internal".
**Typical weaknesses**:
- Flat mesh with no policy
- Any pod can call any service
- No per-service authz
- Service account shared across services

## 10. Regulatory Zone Boundary (e.g. EU/US data residency)

**What crosses**: Personal data copies, aggregates, metadata.
**Controls**: Data-classification-aware routing, geo-fenced storage, transfer impact assessments, contractual (SCCs), encryption with keys held in source region.
**Typical weaknesses**:
- Metadata crosses unrecorded
- Backups in wrong region
- SaaS subprocessor in non-approved region

## 11. Cloud Account / Subscription Boundary

**What crosses**: Cross-account IAM assumptions, VPC peering, shared buckets.
**Controls**: Trust relationships minimized, SCPs/Azure policies, resource policies, no wildcard principals, cross-account read-only where possible.
**Typical weaknesses**:
- `Principal: "*"` on resource policies
- Over-broad `sts:AssumeRole` trust
- Snapshots shared publicly
- S3 bucket policy allows AWS-wide access

## 12. Human Boundary (people / role)

**What crosses**: Tickets, requests, documents, verbal communication.
**Controls**: RBAC, JIT access, approval workflows, separation of duties, background checks for privileged roles.
**Typical weaknesses**:
- Help-desk can reset anyone's password — social engineering attack surface
- Developer has prod DB access "just in case"
- Leavers' access not revoked

## How to Use This Reference

1. Walk the list against your DFD — for each boundary type, is it present?
2. For each present boundary, verify: what controls are there, which typical weaknesses apply?
3. For each boundary, run STRIDE-across-boundary: can spoofing / tampering / etc. cross it?
4. Boundaries map 1-to-many with trust-zone names — a single DFD can show two parallel boundaries (e.g. privilege + network).
