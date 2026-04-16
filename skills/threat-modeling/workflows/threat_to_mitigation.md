# Workflow: Map Threats to Control Catalogs

For each identified threat, produce (a) concrete mitigations and (b) catalog IDs from NIST CSF / NIST 800-53 / CIS Controls / OWASP ASVS for traceability.

## Inputs
- Threat findings (`schemas/finding.json` objects) with `stride_category`, `element`, `attack_vector`
- Target control catalogs (pick per organizational requirement)

## Outputs
- Each finding has `mitigations[]` (concrete controls) and `control_mappings[]` (catalog IDs)
- A rollup table of mitigations grouped by control — highlights multi-threat wins

## Steps

### 1. Start from the STRIDE→controls matrix

| STRIDE | Primary Controls |
|--------|------------------|
| Spoofing | MFA, passkeys/WebAuthn, mTLS, certificate pinning, session management, DNSSEC, SPF/DKIM/DMARC |
| Tampering | Input validation, HMAC/signatures, TLS, SRI, immutable logs, code signing |
| Repudiation | Append-only audit log, hash-chained logs, trusted timestamps, log segregation |
| Information Disclosure | Encryption at rest/in-transit, KMS/HSM, secret management, DLP, error sanitization, response filtering, constant-time crypto |
| Denial of Service | Rate limiting, quotas, CDN/WAF, autoscaling, circuit breakers, bounded input sizes, timeouts |
| Elevation of Privilege | RBAC/ABAC, least privilege, sandboxing (seccomp/AppArmor/Firecracker), patching, capability-based security |

### 2. Refine to element-specific controls
| Element | Additional controls |
|---------|---------------------|
| External entity | Identity federation, verified 3rd-party attestation |
| Process | Container hardening, read-only FS, service mesh, workload identity |
| Data store | Encryption at rest, row-level security, backups, retention, DLP |
| Data flow | mTLS, message signing, replay protection, schema validation |
| Trust boundary | WAF, API gateway, segmentation, zero-trust policy engine |

### 3. Add defense-in-depth
For each primary control, add a **detective** complement. Example:
- Preventive: parameterized queries → Detective: SQL-injection WAF rules + SIEM alert on DB errors.
- Preventive: rate limiting → Detective: anomaly detection on request rates.

### 4. Map to catalogs
See `references/control_catalogs.md` for the full mapping tables. Core anchors:

**NIST CSF 2.0** (families):
- IDENTIFY (ID), PROTECT (PR), DETECT (DE), RESPOND (RS), RECOVER (RC), GOVERN (GV)

**NIST 800-53 Rev 5** (example control IDs):
- `AC-*` Access Control, `AU-*` Audit, `IA-*` Identification & Auth, `SC-*` System & Comm Protection, `SI-*` System & Info Integrity

**CIS Controls v8**:
- 1-18, Implementation Groups IG1/IG2/IG3

**OWASP ASVS v5** (verification requirements):
- V2 Authentication, V3 Session, V4 Access Control, V5 Validation, V7 Error & Logging, V8 Data Protection, V9 Communications, V10 Malicious Code, V11 Business Logic, V12 Files, V13 API, V14 Config

### 5. Write back to the finding

```json
{
  "threat_id": "TM-AUTH-001",
  "stride_category": ["spoofing"],
  "mitigations": [
    {"control": "Require MFA for all admin accounts", "type": "preventive", "status": "planned"},
    {"control": "Alert on anomalous login patterns", "type": "detective", "status": "implemented"}
  ],
  "control_mappings": [
    {"catalog": "NIST_800_53", "id": "IA-2(1)"},
    {"catalog": "OWASP_ASVS", "id": "V2.2.1"},
    {"catalog": "CIS", "id": "6.5"}
  ]
}
```

### 6. Rollup
Group by control — a single control like "Deploy a WAF" may address many threats. Surface those as quick wins.

## Automation Hooks

For bulk mapping, emit a JSONL stream of `{threat_id, stride, element_type}` and apply a static mapping table. Flag any threat where no control matched for human review — often surfaces novel threats.

## Parallelism

Mapping is independently parallelizable per finding. Run a sub-agent per STRIDE category, each responsible for finalizing mitigations + control IDs for its category's findings.

## Extended Thinking

Low-value here. Control mapping is largely lookup + pattern matching. Save extended thinking budget for threat enumeration.
