# Framework Comparison — Which Methodology to Pick

Decision matrix for selecting a threat modeling methodology.

## Quick-Pick Decision Tree

```
Is privacy / personal data the primary concern?
├── Yes → LINDDUN (methodology/linddun.md)
└── No
    │
    Is this an enterprise-wide / cross-org risk assessment?
    ├── Yes → OCTAVE Allegro (methodology/octave.md)
    └── No
        │
        Is compliance / business risk alignment required (regulated industry)?
        ├── Yes → PASTA (methodology/pasta.md)
        └── No
            │
            Do you need a single-threat deep dive?
            ├── Yes → Attack Trees (methodology/attack_trees.md)
            └── No → STRIDE (methodology/stride.md)   [DEFAULT]
```

Default: **STRIDE**. Most agile teams, most applications, most of the time.

## Full Comparison

| Aspect | STRIDE | PASTA | Attack Trees | DREAD | LINDDUN | OCTAVE |
|--------|--------|-------|--------------|-------|---------|--------|
| Primary focus | Threats per element | Business-aligned risk | Attack paths per goal | Risk scoring | Privacy threats | Org-wide asset risk |
| Granularity | Component | System + Business | Goal-specific | Per-threat | Data-subject data | Portfolio |
| Complexity | Medium | High | Low-Medium | Low | Medium | High |
| Cycle time | Hours-Days | Weeks | Hours | Minutes | Days | Weeks-Months |
| Owner | Dev + Security | Security + Business | Security | Anyone | Privacy + Security | Risk mgmt + IT |
| Input needed | DFD | Business context + architecture | Single threat | Identified threat | DFD + data flows | Asset inventory |
| Output | Threat list | Risk register | Prioritized attack paths | Ranked threats | Privacy threat list | Risk register + mitigations |
| Best for | Apps, APIs, microservices | Regulated enterprise apps | Specific high-impact scenarios | Quick triage | GDPR/CCPA systems | Enterprise programs |
| Weakness | Not risk-quantified | Heavy overhead | Doesn't enumerate goals | Subjective | Narrow scope | Not agile |
| Tooling | MS TMT, Threat Dragon, Threagile | CTI platforms, manual | Graphviz, ADTool | Spreadsheet | LINDDUN GO (TU Leuven) | CERT workbooks |

## Combine, Don't Choose Exclusively

Real programs combine methodologies:

- **STRIDE + Attack Trees**: STRIDE enumerates threats; build attack trees for the top N.
- **STRIDE + LINDDUN**: STRIDE covers security; LINDDUN adds privacy layer for PII flows.
- **STRIDE + DREAD**: STRIDE enumerates; DREAD scores for prioritization (warn on DREAD critiques).
- **PASTA wrapping STRIDE**: PASTA's Stage 4 threat analysis uses STRIDE internally.
- **OCTAVE Allegro + STRIDE**: OCTAVE picks assets; STRIDE threat-models systems holding them.

## Anti-Patterns

| Situation | Don't do this | Do this instead |
|-----------|--------------|-----------------|
| Microservice PR review | Full PASTA every PR | Lightweight STRIDE-per-interaction (`workflows/stride_from_openapi.md`) |
| New privacy feature | Generic STRIDE only | STRIDE + LINDDUN layer |
| Need to prioritize 100 threats | Eyeball it | CVSS or OWASP Risk Rating (not DREAD) |
| One CEO-level high-consequence threat | Skim STRIDE | Deep attack tree |
| Enterprise new initiative | Jump to STRIDE | OCTAVE Allegro first, then STRIDE per system |

## Selection Heuristics

- **Team is 1-5 devs, single service** → STRIDE, done in a meeting.
- **Regulated (PCI, HIPAA, SOX, GDPR)** → PASTA (with LINDDUN for GDPR).
- **Multi-tenant SaaS** → STRIDE + extra focus on tenant-isolation trust boundary.
- **AI/ML inference or training system** → STRIDE + MITRE ATLAS overlay.
- **High-assurance (finance, critical infra)** → PASTA + attack trees for top threats.
- **Privacy-by-design mandate** → LINDDUN.
- **Enterprise risk dashboard** → OCTAVE Allegro outputs roll into ERM.
