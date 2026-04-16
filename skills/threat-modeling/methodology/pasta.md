# PASTA (Process for Attack Simulation and Threat Analysis)

A seven-stage, risk-centric methodology that aligns threat modeling with business objectives. Heavier than STRIDE; preferred for compliance-driven or business-critical assessments.

## Stage 1: Define Business Objectives
- Identify business objectives and success criteria
- Capture security and compliance requirements (PCI DSS, HIPAA, GDPR, SOX)
- Define risk tolerance / appetite
- Inventory critical assets and their business value

## Stage 2: Define Technical Scope
- Document system architecture (logical + physical)
- Technology stack and versions
- Data flows (input: DFD from `workflows/dfd_creation.md`)
- Integration points and third-party dependencies
- Hosting and deployment topology

## Stage 3: Application Decomposition
- Identify components, services, and their owners
- Map data flows between components
- Identify assets (data + services) and classify
- Define trust boundaries (see `references/trust_boundary_patterns.md`)
- Build an Actor-Asset-Action matrix

## Stage 4: Threat Analysis
- Identify threat actors (script kiddie → nation state)
- Enumerate threat scenarios using threat intelligence (MITRE ATT&CK, CTI feeds)
- Map threats to attack patterns (CAPEC)
- Consider motive, opportunity, capability

## Stage 5: Vulnerability & Weakness Analysis
- Enumerate known vulnerabilities (CVE, vendor advisories)
- Identify design weaknesses (CWE)
- Identify implementation flaws (SAST/DAST/SCA; see sast-orchestration and api-security skills)
- Configuration issues (CIS benchmarks, cloud posture)

## Stage 6: Attack Modeling & Simulation
- Build attack trees per critical threat (see `methodology/attack_trees.md`)
- Construct attack scenarios/kill chains
- Analyze exploitability against each vulnerability
- Estimate probability of attack success
- Optionally simulate with red-team exercises

## Stage 7: Risk & Impact Analysis
- Calculate inherent and residual risk per scenario
- Quantify impact (monetary, reputational, regulatory)
- Prioritize by risk × impact
- Plan mitigations, assign owners, track in risk register
- Loop back to Stage 1 when business context changes

## When to Choose PASTA
- Regulated industries (finance, healthcare, critical infrastructure)
- Enterprise-wide initiatives requiring business alignment
- Cases where you need to justify security spend to leadership
- When existing threat intelligence and CTI feeds should be integrated

## When NOT to Choose PASTA
- Small teams / single service — STRIDE is lighter
- Rapid iteration / CI-integrated threat modeling — use STRIDE-per-interaction
- Privacy-focused projects — use LINDDUN

See `references/framework_comparison.md` for a full decision matrix.
