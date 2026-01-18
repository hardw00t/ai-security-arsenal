---
name: threat-modeling
description: "Threat modeling skill for identifying security threats, attack surfaces, and designing mitigations. This skill should be used when performing threat assessments using STRIDE, PASTA, or Attack Trees, creating data flow diagrams, identifying trust boundaries, analyzing attack surfaces, or designing security controls for applications and systems. Triggers on requests to threat model, analyze attack surface, create DFD, apply STRIDE methodology, or assess security architecture."
---

# Threat Modeling

This skill enables systematic security analysis of applications and systems through structured threat identification methodologies including STRIDE, PASTA, Attack Trees, and DREAD scoring. It covers creating data flow diagrams, identifying trust boundaries, and designing security controls.

## When to Use This Skill

This skill should be invoked when:
- Starting a new project security assessment
- Designing security architecture for systems
- Identifying threats using STRIDE methodology
- Creating data flow diagrams (DFDs)
- Analyzing attack surfaces
- Prioritizing security risks with DREAD
- Designing mitigations for identified threats

### Trigger Phrases
- "threat model this application"
- "identify threats using STRIDE"
- "create a data flow diagram"
- "analyze the attack surface"
- "what are the security threats"
- "design security controls"

---

## Threat Modeling Methodologies

### Methodology Comparison

| Method | Focus | Best For | Complexity |
|--------|-------|----------|------------|
| STRIDE | Threat categories | Developer-focused, applications | Medium |
| PASTA | Risk-centric | Business-aligned, compliance | High |
| Attack Trees | Attack paths | Specific threat scenarios | Low-Medium |
| DREAD | Risk scoring | Prioritization | Low |
| LINDDUN | Privacy | Data protection, GDPR | Medium |
| OCTAVE | Enterprise | Organization-wide risk | High |

---

## STRIDE Methodology

### STRIDE Categories

```markdown
## S - Spoofing Identity
**Definition**: Pretending to be someone or something else
**Examples**:
- Using stolen credentials
- Session hijacking
- IP spoofing
- Phishing attacks

**Controls**:
- Strong authentication (MFA)
- Certificate pinning
- Session management
- Anti-phishing measures

## T - Tampering with Data
**Definition**: Modifying data maliciously
**Examples**:
- SQL injection
- Man-in-the-middle attacks
- File modification
- Memory corruption

**Controls**:
- Input validation
- Integrity checks (HMAC, signatures)
- Encryption in transit
- Access controls

## R - Repudiation
**Definition**: Denying having performed an action
**Examples**:
- Deleting logs
- Claiming never made a transaction
- Denying access to resources
- Falsifying records

**Controls**:
- Audit logging
- Digital signatures
- Timestamps
- Non-repudiation mechanisms

## I - Information Disclosure
**Definition**: Exposing information to unauthorized entities
**Examples**:
- Data breaches
- Error message leakage
- Side-channel attacks
- Improper access controls

**Controls**:
- Encryption at rest/transit
- Access control
- Data classification
- Secure error handling

## D - Denial of Service
**Definition**: Making a system unavailable
**Examples**:
- DDoS attacks
- Resource exhaustion
- Crash bugs
- Algorithmic complexity attacks

**Controls**:
- Rate limiting
- Resource quotas
- CDN/WAF
- Graceful degradation

## E - Elevation of Privilege
**Definition**: Gaining higher privileges than authorized
**Examples**:
- Buffer overflow exploits
- Privilege escalation bugs
- SQL injection to admin
- RBAC bypass

**Controls**:
- Least privilege
- Input validation
- Sandboxing
- Regular patching
```

### STRIDE per Element Analysis

```markdown
## Element Types & Applicable Threats

| Element | S | T | R | I | D | E |
|---------|---|---|---|---|---|---|
| External Entity | ✓ |   | ✓ |   |   |   |
| Process | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Data Store |   | ✓ | ? | ✓ | ✓ |   |
| Data Flow |   | ✓ |   | ✓ | ✓ |   |

### Analysis Process
1. Decompose system into DFD elements
2. Apply STRIDE to each element
3. For each applicable threat category:
   - Identify specific threats
   - Assess likelihood and impact
   - Design mitigations
   - Document residual risk
```

---

## Data Flow Diagrams (DFD)

### DFD Elements

```markdown
## Element Symbols

┌─────────────────┐
│  External       │  Rectangle: External Entity
│  Entity         │  (users, external systems)
└─────────────────┘

     ┌─────┐
     │     │
     │  ●──│──────>  Circle: Process
     │     │         (transforms data)
     └─────┘

  ═══════════════    Parallel lines: Data Store
  ═══════════════    (databases, files, queues)

  ─────────────>     Arrow: Data Flow
                     (data movement)

  - - - - - - - -    Dotted line: Trust Boundary
                     (security perimeter)
```

### Example: Web Application DFD

```
                    ┌─────────────────────────────────────────────┐
                    │              TRUST BOUNDARY                  │
                    │  ┌─────────────────────────────────────┐    │
┌──────────┐       │  │                                     │    │
│          │ HTTPS │  │   ┌─────────┐      ┌─────────┐     │    │
│   User   │───────┼──┼──>│   Web   │─────>│   API   │     │    │
│ (Browser)│       │  │   │ Server  │      │ Server  │     │    │
└──────────┘       │  │   └─────────┘      └────┬────┘     │    │
                    │  │                         │          │    │
                    │  │                         │ SQL      │    │
                    │  │                    ─────┴─────     │    │
                    │  │                    ═══════════     │    │
                    │  │                      Database      │    │
                    │  │                    ═══════════     │    │
                    │  └─────────────────────────────────────┘    │
                    └─────────────────────────────────────────────┘

External Services:
┌──────────┐
│ Payment  │<──── External API calls
│ Gateway  │
└──────────┘
```

### Trust Boundaries

```markdown
## Common Trust Boundaries

1. **Internet / DMZ**
   - Public network to internal network
   - Firewall boundary

2. **DMZ / Internal Network**
   - Web servers to application servers
   - Different security zones

3. **Application / Database**
   - App tier to data tier
   - Different privilege levels

4. **User / Admin**
   - Regular user functions vs admin
   - Role-based boundaries

5. **Client / Server**
   - Browser/mobile app to backend
   - Untrusted client code

## Questions for Each Boundary
- What crosses this boundary?
- What authentication/authorization exists?
- What can an attacker do from outside?
- What if boundary is bypassed?
```

---

## Attack Surface Analysis

### Attack Surface Components

```markdown
## Entry Points

### Network
- Open ports and services
- API endpoints
- WebSocket connections
- Protocol handlers

### Application
- User input fields
- File uploads
- API parameters
- Authentication endpoints
- Session management

### Data
- Database interfaces
- File system access
- Memory/cache access
- Configuration files

### Physical/Environment
- Physical access points
- USB/removable media
- Hardware interfaces
```

### Attack Surface Reduction

```markdown
## Reduction Strategies

### 1. Minimize Entry Points
- [ ] Close unnecessary ports
- [ ] Remove unused endpoints
- [ ] Disable unused features
- [ ] Remove debug interfaces

### 2. Reduce Privileges
- [ ] Least privilege principle
- [ ] Service accounts with minimal rights
- [ ] Role-based access control
- [ ] Time-limited access

### 3. Limit Data Exposure
- [ ] Minimize data collection
- [ ] Data masking/tokenization
- [ ] Encryption at rest
- [ ] Secure deletion

### 4. Code Reduction
- [ ] Remove unused code
- [ ] Minimize dependencies
- [ ] Disable unnecessary features
- [ ] Configuration hardening
```

---

## PASTA Methodology

### PASTA Stages

```markdown
## Stage 1: Define Objectives
- Business objectives
- Security requirements
- Compliance requirements
- Risk tolerance

## Stage 2: Define Technical Scope
- System architecture
- Technology stack
- Data flows
- Integration points

## Stage 3: Application Decomposition
- Identify components
- Map data flows
- Identify assets
- Trust boundaries

## Stage 4: Threat Analysis
- Identify threat sources
- Enumerate threat scenarios
- Map to attack patterns
- Use threat intelligence

## Stage 5: Vulnerability Analysis
- Known vulnerabilities
- Design weaknesses
- Implementation flaws
- Configuration issues

## Stage 6: Attack Modeling
- Attack trees
- Attack scenarios
- Exploit analysis
- Attack probability

## Stage 7: Risk & Impact Analysis
- Risk calculation
- Impact assessment
- Prioritization
- Mitigation planning
```

---

## Attack Trees

### Attack Tree Structure

```markdown
## Tree Components

ROOT: Ultimate attack goal
├── OR: Alternative methods (any one succeeds)
│   ├── AND: Required steps (all must succeed)
│   │   ├── Leaf: Atomic attack step
│   │   └── Leaf: Atomic attack step
│   └── Leaf: Alternative atomic attack
└── OR: Another path to goal
    └── AND: Required combination
        ├── Leaf: Step 1
        └── Leaf: Step 2
```

### Example: Compromise User Account

```
Compromise User Account
├── OR: Steal Credentials
│   ├── Phishing Attack
│   │   └── AND
│   │       ├── Create fake login page
│   │       └── Lure user to page
│   ├── Credential Stuffing
│   │   └── AND
│   │       ├── Obtain breached credentials
│   │       └── Try against target
│   └── Keylogger
│       └── AND
│           ├── Install malware
│           └── Capture keystrokes
├── OR: Session Hijacking
│   ├── XSS to steal token
│   │   └── AND
│   │       ├── Find XSS vulnerability
│   │       └── Inject payload
│   └── Session fixation
│       └── AND
│           ├── Set session ID
│           └── User authenticates
├── OR: Password Reset Exploit
│   ├── Weak reset questions
│   └── Email interception
└── OR: Brute Force
    └── AND
        ├── Enumerate usernames
        └── Password spray attack
```

### Attack Tree Analysis

```markdown
## Annotations

### Probability (P)
- High (H): Likely to succeed
- Medium (M): Possible
- Low (L): Unlikely

### Cost (C)
- High ($$$): Expensive resources
- Medium ($$): Moderate investment
- Low ($): Minimal cost

### Skill (S)
- Expert: Advanced knowledge required
- Intermediate: Some expertise
- Novice: Basic skills

## Node Evaluation
Each leaf node: P × C × S = Threat Score
Combine up tree based on AND/OR logic
```

---

## DREAD Risk Scoring

### DREAD Categories

```markdown
## D - Damage (0-10)
How bad would an attack be?
- 0: Nothing
- 5: Individual user data
- 10: Complete system compromise

## R - Reproducibility (0-10)
How easy to reproduce the attack?
- 0: Very hard, rare conditions
- 5: Requires specific configuration
- 10: Always reproducible

## E - Exploitability (0-10)
How easy to launch the attack?
- 0: Requires advanced knowledge
- 5: Requires some expertise
- 10: Novice can exploit

## A - Affected Users (0-10)
How many users affected?
- 0: None
- 5: Some users
- 10: All users

## D - Discoverability (0-10)
How easy to find the vulnerability?
- 0: Very difficult to find
- 5: Can be found with effort
- 10: Easily visible
```

### DREAD Calculation

```markdown
## Risk Score = (D + R + E + A + D) / 5

### Rating Scale
- 12-15: Critical
- 9-12: High
- 6-9: Medium
- 3-6: Low
- 0-3: Informational

### Example: SQL Injection in Login
- Damage: 10 (Full database access)
- Reproducibility: 10 (Always works)
- Exploitability: 6 (Requires some skill)
- Affected Users: 10 (All users)
- Discoverability: 6 (Found by testing)

Score = (10+10+6+10+6)/5 = 8.4 (Medium-High)
```

---

## Threat Modeling Process

### Step-by-Step Guide

```markdown
## 1. Preparation
- [ ] Gather architecture documentation
- [ ] Identify stakeholders
- [ ] Define scope and boundaries
- [ ] Schedule modeling session

## 2. System Decomposition
- [ ] Create/update DFD
- [ ] Identify all entry points
- [ ] Map data flows
- [ ] Mark trust boundaries
- [ ] List assets to protect

## 3. Threat Identification
- [ ] Apply STRIDE per element
- [ ] Use threat libraries
- [ ] Consider abuse cases
- [ ] Review historical threats

## 4. Threat Analysis
- [ ] Assess likelihood
- [ ] Evaluate impact
- [ ] Calculate risk scores
- [ ] Prioritize threats

## 5. Mitigation Design
- [ ] Identify controls for each threat
- [ ] Map to security requirements
- [ ] Consider defense in depth
- [ ] Document residual risk

## 6. Validation
- [ ] Review with security team
- [ ] Validate with developers
- [ ] Get stakeholder sign-off
- [ ] Plan for updates
```

### Threat Libraries

```markdown
## CAPEC (Common Attack Pattern Enumeration)
- Standard attack pattern catalog
- Categories: Social Engineering, Injection, etc.
- https://capec.mitre.org

## OWASP Top 10
- Web application threats
- Updated periodically
- https://owasp.org/Top10/

## MITRE ATT&CK
- Adversary tactics and techniques
- Enterprise/Mobile/ICS matrices
- https://attack.mitre.org

## CWE (Common Weakness Enumeration)
- Software weakness types
- Maps to vulnerabilities
- https://cwe.mitre.org
```

---

## Threat Modeling Tools

### Tool Comparison

| Tool | Type | Cost | Features |
|------|------|------|----------|
| Microsoft Threat Modeling Tool | Desktop | Free | STRIDE, DFD templates |
| OWASP Threat Dragon | Web/Desktop | Free | DFD, STRIDE, reporting |
| IriusRisk | SaaS | Paid | Automation, integrations |
| ThreatModeler | SaaS | Paid | Enterprise, compliance |
| Threagile | CLI | Free | As-code, YAML-based |
| draw.io | Web | Free | Manual DFD creation |

### OWASP Threat Dragon

```bash
# Install
npm install -g owasp-threat-dragon

# Run locally
threat-dragon

# Key features:
# - DFD creation
# - STRIDE per element
# - Threat suggestions
# - Report generation
```

### Threagile (Threat Modeling as Code)

```yaml
# threagile.yaml
title: My Application Threat Model
date: 2024-01-15

technical_assets:
  web_server:
    id: web-server
    usage: business
    type: process
    technologies:
      - web-server
    internet: true
    machine: container
    encryption: none

  database:
    id: database
    type: datastore
    technologies:
      - database
    encryption: transparent

data_assets:
  customer_data:
    id: customer-data
    usage: business
    quantity: many
    confidentiality: confidential
    integrity: critical
    availability: critical

trust_boundaries:
  dmz:
    id: dmz
    type: network-cloud-security-group
    technical_assets_inside:
      - web-server

communication_links:
  web_to_db:
    source_id: web-server
    target_id: database
    protocol: tcp
    authentication: credentials
```

---

## Security Control Mapping

### Control Categories

```markdown
## Preventive Controls
- Stop threats before they occur
- Examples: Firewalls, input validation, encryption

## Detective Controls
- Identify when threats occur
- Examples: IDS, logging, monitoring

## Corrective Controls
- Respond to threats after detection
- Examples: Incident response, patching, recovery

## Deterrent Controls
- Discourage threat actors
- Examples: Legal warnings, security awareness
```

### STRIDE to Controls Matrix

```markdown
| STRIDE | Controls |
|--------|----------|
| Spoofing | MFA, certificates, session management |
| Tampering | Integrity checks, signatures, validation |
| Repudiation | Audit logs, digital signatures, timestamps |
| Info Disclosure | Encryption, access control, masking |
| DoS | Rate limiting, quotas, redundancy |
| Elevation | Least privilege, sandboxing, RBAC |
```

---

## Reporting Template

```markdown
# Threat Model Report

## Document Information
- Application: [Name]
- Version: [X.Y]
- Date: YYYY-MM-DD
- Author: [Name]
- Reviewers: [Names]

## Executive Summary
Brief overview of the system, key assets, major threats identified,
and overall risk posture.

## System Overview
### Architecture
[DFD diagram]

### Components
| Component | Description | Technology |
|-----------|-------------|------------|
| Web Server | Handles HTTP requests | Nginx |
| API | Business logic | Node.js |
| Database | Data storage | PostgreSQL |

### Trust Boundaries
1. Internet / DMZ
2. DMZ / Internal
3. Application / Database

### Assets
| Asset | Sensitivity | Value |
|-------|-------------|-------|
| User credentials | High | Critical |
| Personal data | High | High |
| Session tokens | High | High |

## Threat Analysis

### Threat: SQL Injection in Login
**STRIDE Category**: Tampering, Information Disclosure, Elevation of Privilege
**Attack Vector**: Malicious input in username/password fields
**DREAD Score**: 8.4 (High)

**Current State**: No input validation
**Proposed Mitigation**: Parameterized queries, input validation
**Residual Risk**: Low (after mitigation)

### Threat: Session Hijacking
[Similar format for each threat]

## Risk Summary

| Threat | DREAD | Mitigation | Residual |
|--------|-------|------------|----------|
| SQL Injection | 8.4 | Parameterized queries | Low |
| XSS | 7.2 | Output encoding | Low |
| Brute Force | 5.0 | Rate limiting, MFA | Low |

## Recommendations

### Priority 1 (Immediate)
1. Implement parameterized queries
2. Add output encoding

### Priority 2 (Short-term)
1. Enable MFA
2. Implement rate limiting

### Priority 3 (Long-term)
1. Security awareness training
2. Regular penetration testing

## Appendix
- Full DFD
- STRIDE analysis worksheets
- Control implementation details
```

---

## Bundled Resources

### scripts/
- `stride_analyzer.py` - STRIDE threat enumeration
- `dread_calculator.py` - DREAD score calculation
- `threat_report.py` - Generate threat model reports

### references/
- `stride_threats.md` - STRIDE threat examples by element
- `control_catalog.md` - Security control reference
- `attack_patterns.md` - Common attack patterns

### templates/
- `threat_model_template.md` - Report template
- `dfd_template.drawio` - DFD template for draw.io
- `stride_worksheet.xlsx` - STRIDE analysis worksheet
