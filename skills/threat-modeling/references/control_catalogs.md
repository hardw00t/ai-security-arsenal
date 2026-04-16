# Control Catalogs

Quick reference for mapping threats to industry control catalogs. See `workflows/threat_to_mitigation.md` for the workflow.

## NIST Cybersecurity Framework 2.0

Six core functions (added GOVERN in 2.0):

| Function | ID prefix | Scope |
|----------|-----------|-------|
| GOVERN | GV | Enterprise risk management, policy, roles |
| IDENTIFY | ID | Asset, risk, and supply-chain management |
| PROTECT | PR | Access control, data security, platform hardening |
| DETECT | DE | Continuous monitoring, anomaly detection |
| RESPOND | RS | Incident response planning, analysis, mitigation |
| RECOVER | RC | Recovery planning, communications |

Use CSF when the audience is executive or auditors — high-level, outcome-focused.

## NIST SP 800-53 Rev 5 (Control Families)

| Family | Name | Typical use |
|--------|------|-------------|
| AC | Access Control | Authz, account mgmt, separation of duties |
| AU | Audit and Accountability | Logs, log protection, correlation |
| AT | Awareness and Training | User/dev training |
| CA | Assessment, Authorization, Monitoring | Continuous ATO, POA&M |
| CM | Configuration Management | Baselines, change control |
| CP | Contingency Planning | BCP/DR |
| IA | Identification and Authentication | Auth, MFA, identity proofing |
| IR | Incident Response | IR program |
| MA | Maintenance | System maintenance |
| MP | Media Protection | Data-at-rest, sanitization |
| PE | Physical and Environmental | Physical access |
| PL | Planning | Security plans |
| PM | Program Management | InfoSec program |
| PS | Personnel Security | Screening, termination |
| PT | PII Processing & Transparency | Privacy |
| RA | Risk Assessment | Risk analysis, vuln scanning |
| SA | System & Services Acquisition | SDLC, SBOM, supply chain |
| SC | System & Communications Protection | TLS, crypto, boundary protection |
| SI | System & Info Integrity | Patching, input validation, monitoring |
| SR | Supply Chain Risk Management | Provenance, SBOM, C-SCRM |

Common STRIDE mappings:
- Spoofing → IA-2, IA-5, IA-8, SC-8, SC-17
- Tampering → SI-10, SC-8, SC-13, AU-9
- Repudiation → AU-2, AU-3, AU-6, AU-9, AU-10
- Information Disclosure → SC-8, SC-13, SC-28, AC-3, AC-4
- Denial of Service → SC-5, SC-6, SC-7
- Elevation of Privilege → AC-3, AC-6, CM-5, SI-7

## CIS Controls v8

18 controls, organized into Implementation Groups IG1/IG2/IG3 by org maturity.

| # | Control |
|---|---------|
| 1 | Inventory & Control of Enterprise Assets |
| 2 | Inventory & Control of Software Assets |
| 3 | Data Protection |
| 4 | Secure Configuration |
| 5 | Account Management |
| 6 | Access Control Management |
| 7 | Continuous Vulnerability Management |
| 8 | Audit Log Management |
| 9 | Email & Web Browser Protections |
| 10 | Malware Defenses |
| 11 | Data Recovery |
| 12 | Network Infrastructure Management |
| 13 | Network Monitoring & Defense |
| 14 | Security Awareness & Skills Training |
| 15 | Service Provider Management |
| 16 | Application Software Security |
| 17 | Incident Response Management |
| 18 | Penetration Testing |

Common STRIDE mappings (sub-control level):
- Spoofing → 5, 6 (MFA 6.5)
- Tampering → 3, 16.11 (parameterized queries)
- Repudiation → 8
- Info Disclosure → 3.11 (encryption at rest), 3.10 (in-transit)
- DoS → 12, 13
- Elevation → 5.4 (least priv), 6.8 (separation of duties)

## OWASP ASVS v5 (Application Security Verification Standard)

Chapter-level structure:

| Chapter | Topic |
|---------|-------|
| V1 | Architecture, Design, Threat Modeling |
| V2 | Authentication |
| V3 | Session Management |
| V4 | Access Control |
| V5 | Validation, Sanitization, Encoding |
| V6 | Stored Cryptography |
| V7 | Error Handling & Logging |
| V8 | Data Protection |
| V9 | Communications |
| V10 | Malicious Code |
| V11 | Business Logic |
| V12 | Files & Resources |
| V13 | API & Web Service |
| V14 | Configuration |

Levels: L1 (baseline), L2 (standard), L3 (high-assurance).

Common STRIDE mappings:
- Spoofing → V2 (all), V3 (session)
- Tampering → V5, V11
- Repudiation → V7
- Info Disclosure → V6, V7, V8, V9
- DoS → V11.1.4, V13
- Elevation → V4

## ISO/IEC 27001:2022 (Annex A)

93 controls in 4 themes: Organizational, People, Physical, Technological.

## PCI DSS v4.0 (Requirements)

12 requirements. Key ones for threat modeling:
- Req 1 — Network security controls
- Req 2 — Secure configuration
- Req 3 — Protect stored account data
- Req 4 — Protect data in transit
- Req 6 — Develop secure systems (6.2 authenticated scanning, 6.3 threat modeling, 6.4 public-facing app protection)
- Req 8 — Identify users & authenticate access
- Req 10 — Log & monitor
- Req 11 — Test security

## Mapping Strategy

Pick catalogs based on audience:
- **Auditors, board**: NIST CSF + ISO 27001
- **Federal/FedRAMP**: NIST 800-53
- **Developers**: OWASP ASVS
- **SMB / general IT**: CIS Controls
- **Payment systems**: PCI DSS

Record multiple mappings per finding — different stakeholders need different language.

## Tool References

- OSCAL (NIST) — machine-readable control catalogs
- Secure Controls Framework (SCF) — cross-walks between catalogs
- MITRE D3FEND — defensive technique taxonomy complementing ATT&CK
