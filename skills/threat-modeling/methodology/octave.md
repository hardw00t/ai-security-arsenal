# OCTAVE / OCTAVE Allegro

OCTAVE (Operationally Critical Threat, Asset, and Vulnerability Evaluation) is an organization-wide, asset-driven risk assessment methodology from CERT/SEI. Use when threat modeling at the enterprise portfolio level, not a single application.

Two main variants:
- **OCTAVE Allegro** — the streamlined form, most common today. Focuses on information assets and their containers.
- **OCTAVE-S** — for small organizations (< 100 people).
- Original OCTAVE — heavyweight, largely superseded by Allegro.

## OCTAVE Allegro — Eight Steps

### Step 1: Establish Risk Measurement Criteria
Define the impact areas the organization cares about:
- Reputation & customer confidence
- Financial
- Productivity
- Safety & health
- Fines & legal penalties
- User-defined (e.g. research IP, mission)

For each, define low/medium/high impact thresholds in plain language.

### Step 2: Develop an Information Asset Profile
Pick critical information assets (not systems — the *information*). For each:
- Name, description, owner
- Confidentiality, integrity, availability requirements
- Rationale for choosing it

### Step 3: Identify Information Asset Containers
A *container* is anywhere the asset lives or moves:
- Technical: servers, databases, SaaS, endpoints, networks
- Physical: paper files, archives, facilities
- People: staff roles with access

### Step 4: Identify Areas of Concern
Brainstorm real-world scenarios that worry stakeholders. Do not yet evaluate — just collect.

### Step 5: Identify Threat Scenarios
Formalize areas of concern into threat scenarios:
- Actor (internal / external, accidental / deliberate)
- Means (technical / physical / social)
- Motive (financial / political / personal)
- Outcome (disclosure / modification / destruction / interruption)

Optionally use a threat tree (AND/OR; see `methodology/attack_trees.md`) for exhaustiveness.

### Step 6: Identify Risks
For each threat scenario, articulate the consequence in business terms: what happens to the asset? To the organization?

### Step 7: Analyze Risks
Score each risk against the Step-1 criteria. Produce a *relative risk score* as a weighted sum across impact areas.

### Step 8: Select Mitigation Approach
For each risk, one of:
- **Mitigate**: apply controls to reduce probability/impact
- **Accept**: document and monitor
- **Defer**: reassess later when more info available
- **Transfer**: insurance, contractual shift

For mitigations, pick controls across all containers (technical + physical + people) — OCTAVE's strength is cross-container thinking.

## When to Use OCTAVE

- Enterprise-wide risk programs
- Regulated organizations needing defensible risk-rating process
- Cross-functional risk assessments spanning IT, physical security, HR
- Mergers & acquisitions due diligence

## When NOT to Use OCTAVE

- Single application or microservice — too heavy
- Rapid agile iterations — cycle time is weeks, not hours
- Technical-only analysis — STRIDE/PASTA are a better fit

## Relation to Other Methodologies

- OCTAVE is orthogonal to STRIDE: use STRIDE to enumerate technical threats within an OCTAVE asset container.
- PASTA shares the business-alignment spirit but is more technical.
- OCTAVE's container model complements data-classification programs and DLP.

## References

- CERT/SEI OCTAVE Allegro guide: https://insights.sei.cmu.edu/library/introducing-octave-allegro-improving-the-information-security-risk-assessment-process/
