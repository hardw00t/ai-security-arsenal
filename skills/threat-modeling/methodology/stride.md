# STRIDE Methodology

STRIDE is a developer-focused threat classification framework. Six threat categories map against system elements; each element gets analyzed per applicable category.

## Categories

| Letter | Threat | Security Property Violated |
|--------|--------|----------------------------|
| S | Spoofing Identity | Authentication |
| T | Tampering | Integrity |
| R | Repudiation | Non-repudiation |
| I | Information Disclosure | Confidentiality |
| D | Denial of Service | Availability |
| E | Elevation of Privilege | Authorization |

### S - Spoofing Identity
**Definition**: Pretending to be someone or something else.
**Examples**: stolen credentials, session hijacking, IP spoofing, phishing, JWT forgery, DNS spoofing, service impersonation.
**Controls**: Strong authentication (MFA, WebAuthn), certificate pinning, mutual TLS, session management with secure cookies, DNSSEC, SPF/DKIM/DMARC.

### T - Tampering with Data
**Definition**: Modifying data maliciously.
**Examples**: SQL injection, MitM, file modification, memory corruption, parameter tampering, cache poisoning, supply chain tampering.
**Controls**: Input validation, HMAC/signatures, TLS, WORM storage, code signing, Subresource Integrity (SRI), immutable audit logs.

### R - Repudiation
**Definition**: Denying having performed an action.
**Examples**: Deleting logs, denying transactions, falsifying records, clock manipulation.
**Controls**: Tamper-evident audit logging (append-only, hash-chained), digital signatures, trusted timestamps (RFC 3161), log aggregation to separate trust zone.

### I - Information Disclosure
**Definition**: Exposing information to unauthorized entities.
**Examples**: Data breaches, verbose error messages, side-channel attacks (timing, cache), IDOR, improper ACLs, secrets in code, backup exposure.
**Controls**: Encryption at rest/in-transit, access controls, data classification, error sanitization, secret management (Vault, KMS), constant-time operations.

### D - Denial of Service
**Definition**: Making a system unavailable.
**Examples**: DDoS, resource exhaustion, crash bugs, algorithmic complexity (ReDoS, zip bombs), billion-laughs XML, Slowloris.
**Controls**: Rate limiting, resource quotas, CDN/WAF, graceful degradation, circuit breakers, bounded allocations, input size limits.

### E - Elevation of Privilege
**Definition**: Gaining higher privileges than authorized.
**Examples**: Buffer overflow, path traversal, SQLi to admin, RBAC bypass, sudo misconfigurations, container escape, JWT alg=none.
**Controls**: Least privilege, input validation, sandboxing (seccomp, AppArmor), regular patching, capability-based security, RBAC with deny-by-default.

## STRIDE-per-Element

Apply only the applicable categories to each element type.

| Element Type | S | T | R | I | D | E |
|--------------|---|---|---|---|---|---|
| External Entity | ✓ |   | ✓ |   |   |   |
| Process | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Data Store |   | ✓ | ? | ✓ | ✓ |   |
| Data Flow |   | ✓ |   | ✓ | ✓ |   |

`?` = applicable only if the store itself logs (most do; treat as yes if it's an audit log).

### Process (applies to all 6)
Questions to ask:
- How does the process authenticate callers? (S)
- Can inputs alter logic or data? (T)
- Are actions logged tamper-evidently? (R)
- Can the process leak data via logs, errors, or side channels? (I)
- Can it be crashed, starved, or slowed? (D)
- Can an attacker gain its privileges or those above it? (E)

### Data Store
- Can data be modified without authorization? (T)
- Do logs capture who changed what and when? (R, if audit store)
- Can data be read without authorization? (I)
- Can it be filled, locked, or corrupted to deny access? (D)

### Data Flow
- Can the data in transit be modified? (T)
- Can it be observed? (I)
- Can it be blocked, replayed, or flooded? (D)

### External Entity
- Can the entity be impersonated? (S)
- Can the entity deny having sent/received a message? (R)

## STRIDE-per-Interaction (preferred for API-heavy systems)

Instead of analyzing each element in isolation, analyze each `(source, flow, destination)` triple. Especially powerful when the system is described by an OpenAPI/AsyncAPI spec — see `workflows/stride_from_openapi.md`.

For each interaction, enumerate:
- S: can source be spoofed to destination?
- T: can the payload/response be tampered with in transit or at endpoints?
- R: can either side deny the interaction?
- I: can payload/response/metadata be disclosed?
- D: can the interaction be flooded or blocked?
- E: can the interaction be used to escalate privileges on either side?

## Analysis Process

1. Decompose system into DFD elements (see `workflows/dfd_creation.md`).
2. Apply STRIDE to each element or interaction.
3. For each applicable threat:
   - Identify specific realization (e.g. "JWT forged using alg=none")
   - Assess likelihood and impact
   - Design mitigations (preventive + detective)
   - Document residual risk
4. Feed outputs into `schemas/finding.json` structure.

## Parallelization

Each STRIDE category is independently analyzable. Spawn 6 sub-agents in parallel — one per category — across the full element set for maximum coverage. See the parent `SKILL.md` Sub-Agent Delegation section.

## Extended Thinking Guidance

Threat enumeration is the archetypal extended-thinking task. Turn on extended thinking for:
- Initial per-element enumeration (think adversarially about edge cases)
- Interaction analysis where multiple trust boundaries are crossed
- Control gap analysis (what's missing from the proposed mitigation set)

Skip extended thinking for:
- Formatting findings into the schema
- Generating boilerplate Mermaid
