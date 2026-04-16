# Threat Model Report Template

Copy and fill. Keep per-threat entries aligned to `schemas/finding.json`.

---

# Threat Model: <System Name>

## Document Information
- **Application / System**: `<name>`
- **Version**: `<x.y.z>`
- **Date**: `YYYY-MM-DD`
- **Author(s)**: `<names>`
- **Reviewers**: `<names>`
- **Methodology**: STRIDE / PASTA / LINDDUN / Attack Trees / ...
- **Last Validated**: `YYYY-MM`

## Executive Summary
One-paragraph summary: what the system is, the most critical threats identified, overall residual risk posture, and top recommendations.

## Scope & Assumptions
- **In scope**: components, interfaces, data types
- **Out of scope**: what is excluded and why
- **Assumptions**: e.g. "TLS 1.3 is used everywhere", "attacker is not a nation-state", "cloud provider control plane is trusted"

## System Overview

### Architecture
Render the DFD (Mermaid). Level-0 for overview; Level-1+ for detail. See `workflows/dfd_creation.md`.

```mermaid
flowchart LR
    %% Level-0 context diagram here
```

### Components
| Component | Description | Technology | Owner |
|-----------|-------------|------------|-------|
| `<name>` | `<role>` | `<stack>` | `<team>` |

### Actors
| Actor | Description | Trust Level |
|-------|-------------|-------------|
| End user | `<...>` | Untrusted |
| Admin | `<...>` | Privileged |
| Service `<x>` | `<...>` | Trusted |

### Assets
| Asset | Classification | Integrity | Availability | Regulatory |
|-------|---------------|-----------|--------------|-----------|
| User credentials | Confidential | Critical | Critical | - |
| PII (email, name) | Confidential | High | High | GDPR |
| Session tokens | Confidential | High | High | - |

### Trust Boundaries
Reference `references/trust_boundary_patterns.md`.
1. Internet ↔ DMZ
2. DMZ ↔ Application tier
3. Application ↔ Data tier
4. Tenant ↔ Tenant (multi-tenant isolation)
5. Admin ↔ User (privilege)

## Threat Analysis

### Threat: TM-001 — `<short title>`
- **STRIDE Category**: `<S/T/R/I/D/E>` (may be multiple)
- **Element**: `<name>` (`<process / data store / data flow / external entity>`)
- **Trust Boundary**: `<boundary name>`
- **Attack Vector**: `<how an attacker realizes this>`
- **Attacker Profile**: `<unauthenticated_internet / authenticated_user / privileged / insider / supply_chain / physical>`
- **Likelihood**: High / Medium / Low
- **Impact**: Critical / High / Medium / Low
- **Risk Score**: `<0-10>`
- **DREAD** (if used): D=`<>` R=`<>` E=`<>` A=`<>` D=`<>` → `<avg>`
- **CWE / CAPEC / ATT&CK**: `<CWE-89 / CAPEC-66 / T1190>`

**Current State**: `<existing controls and gaps>`

**Proposed Mitigations**:
- Preventive: `<control>`
- Detective: `<control>`
- Corrective: `<control>`

**Control Mappings**:
- NIST 800-53: `<IA-2, SC-8, ...>`
- OWASP ASVS: `<V2.2.1, ...>`
- CIS: `<6.5, ...>`

**Residual Risk**: `<Low after mitigation>`

---

Repeat per threat.

## Attack Trees (for high-impact threats)
Embed key attack trees per `workflows/attack_tree_from_threat.md`.

## Risk Summary

| ID | Threat | STRIDE | Risk | Status | Mitigation | Residual |
|----|--------|--------|------|--------|-----------|----------|
| TM-001 | `<title>` | S+E | 8.4 | Planned | Parameterized queries | Low |
| TM-002 | `<title>` | I | 7.2 | Implemented | Output encoding | Low |

## Recommendations

### Priority 1 (Immediate — this sprint)
1. `<action>`
2. `<action>`

### Priority 2 (Short-term — this quarter)
1. `<action>`

### Priority 3 (Long-term — roadmap)
1. `<action>`

## Assumptions and Open Questions
- `<unresolved question>` — requires input from `<team>`

## Appendix
- Full DFD (Level-0 and Level-1)
- STRIDE-per-element worksheet
- Control implementation details
- References: links to architecture docs, OpenAPI specs, prior threat models
