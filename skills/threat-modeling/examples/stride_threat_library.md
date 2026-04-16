# STRIDE Threat Library (per Element Type)

Pre-built threats for each STRIDE category × element type. Use as a checklist when seeding threat enumeration.

## External Entity

### Spoofing
- Stolen or shared credentials used by wrong user
- Phishing harvests user credentials
- Session hijacking via stolen cookie/token
- SIM-swap bypass of SMS MFA
- OAuth2 redirect-URI abuse for account takeover
- Compromised 3rd-party service impersonated (certificate mis-issuance)

### Repudiation
- User denies performing action; audit log insufficient
- Shared service account masks actual caller
- Signed receipts absent for high-value transactions

## Process

### Spoofing (of the process, or of peers it trusts)
- Rogue pod/container impersonates service via stolen workload identity
- DNS spoofing redirects traffic to attacker process
- JWT `alg=none` / `alg=HS256-with-public-key-as-secret` forgery
- Service-to-service call without mTLS — any peer on network can pose

### Tampering
- Input validation bypass (SQLi, OS command injection, LDAPi, SSTI, XXE, deserialization)
- Prototype pollution / mass assignment in web frameworks
- Cache poisoning (HTTP cache, DNS cache, CDN cache)
- Parameter tampering on hidden form fields
- Supply-chain tampering in build artifacts (SolarWinds-class)

### Repudiation
- No audit log for privileged actions
- Audit logs writable by the process being audited
- Shared credentials across components; who did what unclear
- Clock skew enables backdating

### Information Disclosure
- Verbose error messages reveal stack traces, SQL queries, file paths
- BOLA/IDOR — direct object reference without ownership check
- Mass-assignment responses leak sensitive fields
- Timing / side-channel attacks on crypto or auth
- Secrets in environment variables captured by crash reporters
- Debug endpoints exposed in production (`/metrics`, `/debug/vars`, Actuator)

### Denial of Service
- Unbounded requests/recursion — memory exhaustion
- ReDoS (catastrophic backtracking regex)
- Algorithmic complexity on user input (hash-flooding, zip bombs, XML billion-laughs)
- Resource exhaustion via thread / connection pools
- Slowloris-style connection holding
- Amplification in protocols returning large responses

### Elevation of Privilege
- Path traversal → arbitrary file read/write
- Command injection → code execution
- Deserialization → RCE
- JWT algorithm confusion → forge admin token
- Race conditions (TOCTOU) in privilege checks
- Broken function-level authz — privileged endpoints reachable as normal user
- SSRF to cloud-metadata endpoint → instance role theft

## Data Store

### Tampering
- Direct DB write by compromised app
- Backup-restore from untrusted source overwrites data
- Unauthorized `UPDATE`/`DELETE` via lateral movement
- Cache write without invalidation on source change

### Repudiation (applies if store is the audit log)
- Audit log writable by monitored components
- No write-once semantics
- Missing hash-chaining / external timestamping

### Information Disclosure
- Backup files in public bucket
- Snapshot shared with wrong AWS account
- TDE/FDE absent on lost disk
- `SELECT *` exposes fields outside minimum need
- Weak ACL — public read to blob container
- Secrets in connection string or config committed to repo

### Denial of Service
- Storage filled (quota not enforced)
- Row-level lock exhaustion
- Runaway query consumes IO
- Ransomware encrypts store

## Data Flow

### Tampering
- MitM alters request/response (no TLS, weak TLS, downgrade)
- Missing HSTS → protocol stripping
- Request smuggling between reverse proxy and origin
- Replay attacks (no nonces / expiries)
- Message-queue message modification in transit

### Information Disclosure
- Cleartext protocol (HTTP, FTP, Telnet, SMB-no-signing)
- API key in URL — captured in access logs / Referer
- Broad CORS with credentials
- Clickjacking / UI redressing leaks tokens
- TLS with deprecated ciphers / no certificate validation

### Denial of Service
- Network flooding / amplification
- Connection exhaustion on TLS termination
- BGP / DNS route hijack blocks traffic
- Queue backpressure overwhelming consumers

## Trust Boundary

### Spoofing across the boundary
- Internal service address reachable from outside — untrusted callers pose as internal
- Cross-tenant request header trusted (e.g. `X-Tenant-ID` not validated)

### Tampering across the boundary
- WAF rules bypassed via encoding/obfuscation
- SSRF pivots untrusted inputs into trusted zone
- Bypass via direct-to-origin routing (missing WAF enforcement)

### Information Disclosure across the boundary
- Data exfiltration via permitted egress (DNS tunneling, covert HTTPS)
- Cross-origin read due to misconfigured CORS/SOP
- Debug tooling reachable from wrong zone

### Elevation via boundary bypass
- Internal admin endpoints reachable from internet (no mesh policy)
- Service-to-service calls without identity — any internal pod poses
- Tenant isolation bypass (shared cache key, shared encryption key)

## Using This Library

1. For each element in your DFD, walk the applicable STRIDE categories from this list.
2. Mark each threat: applies / N/A / needs investigation.
3. For threats that apply, write a concrete realization for *your* system (not just the generic description).
4. Map mitigations via `workflows/threat_to_mitigation.md`.
