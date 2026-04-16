---
name: threat-modeling
description: "Systematic threat modeling skill for applications, APIs, and systems using STRIDE, PASTA, Attack Trees, DREAD, LINDDUN, and OCTAVE. Use when assessing security architecture, creating data flow diagrams (Mermaid), enumerating threats from OpenAPI specs or architecture docs, building attack trees, mapping threats to NIST/CIS/OWASP ASVS controls, or producing a threat model report. Triggers on requests to threat model, analyze attack surface, create a DFD, apply STRIDE, or design security mitigations."
---

# Threat Modeling

Adversarial design-time analysis: enumerate threats against a system and specify mitigations. This skill routes to methodology files, workflow runbooks, example libraries, and control-catalog references. Extended adversarial reasoning is the core value — spend thinking budget on threat enumeration.

## When to Use
- New system or major architecture change needs security review.
- An OpenAPI / AsyncAPI spec exists and you want automatic STRIDE-per-interaction.
- Architecture docs or diagrams need threat analysis.
- A specific high-impact threat requires attack-tree deep dive.
- Privacy / personal-data handling needs threat analysis (LINDDUN).
- Mitigations need mapping to NIST CSF / NIST 800-53 / CIS / OWASP ASVS.
- Producing a threat model report for stakeholders / auditors.
- Prioritizing existing threat lists by risk score.

## Trigger Phrases
- "threat model this application / service / API"
- "identify threats using STRIDE / PASTA / LINDDUN"
- "create a data flow diagram / DFD"
- "analyze the attack surface"
- "build an attack tree for X"
- "map these threats to NIST / ASVS / CIS controls"

## When NOT to Use This Skill
- **Runtime API testing / exploitation** of a live endpoint → use `api-security` (this skill identifies threats; `api-security` confirms exploitability).
- **Code-level vulnerability discovery** in a repo (SAST/DAST/SCA) → use `sast-orchestration`.
- **Container image CVE scanning** → use `container-security`.
- **Cloud posture misconfigurations** → use `iac-security` / cloud-security skill.
- **Incident response** on an active intrusion → this is design-time; use IR playbooks instead.
- **Compliance gap analysis** only (no threat enumeration) → use a compliance skill; thread results back here for design changes.

## Decision Tree

```
1. Have an OpenAPI / AsyncAPI spec?
   → workflows/stride_from_openapi.md         (highest-leverage entry point)

2. Have architecture docs or diagrams (or diagram images)?
   → workflows/stride_from_arch_docs.md
     (if diagrams only, first workflows/dfd_creation.md)

3. Need a DFD from scratch?
   → workflows/dfd_creation.md  (emit Mermaid)

4. Already have a high-level threat; need deep path analysis?
   → workflows/attack_tree_from_threat.md

5. Have threats; need mitigations + catalog mappings?
   → workflows/threat_to_mitigation.md

6. Privacy-specific modeling?
   → methodology/linddun.md

7. Enterprise-wide risk?
   → methodology/octave.md

8. Unsure which methodology?
   → references/framework_comparison.md
```

## Parallelism Hints

**Parallelizable:**
- STRIDE-per-element: one sub-agent per element across an entire DFD.
- STRIDE-per-category: one sub-agent per STRIDE letter (S, T, R, I, D, E) across the whole system.
- Attack-tree sub-branches: each first-level OR branch is independent.
- Trust-boundary deep dives: one sub-agent per boundary.
- OpenAPI operation analysis: batch operations across sub-agents (e.g., by tag).
- Control-catalog mapping: per finding.

**Sequential (do not parallelize):**
- DFD construction → threat enumeration (you need the DFD first).
- Threat enumeration → prioritization (need the full list to rank).
- Mitigation design → residual-risk assessment.
- Top-threat selection → attack-tree construction.

## Sub-Agent Delegation

Recommended patterns:

| Pattern | Sub-agents | When |
|---------|-----------|------|
| Per STRIDE category | 6 (S, T, R, I, D, E) | Comprehensive enumeration on a whole system — each sub-agent focuses adversarial reasoning on one category across all elements. |
| Per trust boundary | 1 per boundary | Deep dive on multi-zone systems; each sub-agent owns cross-boundary threats for their boundary. |
| Per subsystem | 1 per service / component | Microservice architectures — each sub-agent threat-models its service, then a merge step deduplicates. |
| Per attack-tree branch | 1 per first-level OR child | Parallel tree expansion. |
| Per OpenAPI tag group | 1 per tag | Large specs — shard operations by tag. |

Always define a **merger agent** that deduplicates findings (same threat surfaced by multiple sub-agents) and reconciles inconsistent risk scores.

## Reasoning Budget

**Extended thinking is the whole point of this skill.** Threat identification is an adversarial creativity task — models consistently miss threats when run without extended thinking.

**Extended thinking ON for:**
- Initial threat enumeration (per-element and per-interaction)
- Trust-boundary crossing analysis
- Attack-tree branch generation (step 2 of `workflows/attack_tree_from_threat.md`)
- Leaf annotation — accurate probability/cost estimation
- Finding novel abuse cases the documentation doesn't mention
- Deciding when the architecture is ambiguous vs attestable

**Extended thinking OFF for:**
- Formatting findings into `schemas/finding.json`
- Emitting Mermaid from a known DFD structure
- Looking up control IDs (`references/control_catalogs.md` is deterministic)
- Report assembly from template

Budget guidance: allocate ~70% of extended-thinking tokens to enumeration, ~20% to attack-tree depth, ~10% to prioritization / control-gap analysis.

## Multimodal Hooks

- **Diagrams in → Mermaid out**: when given an architecture-diagram image, re-emit as Mermaid before analysis (catches ambiguity; produces re-usable artefact).
- **DFDs out → Mermaid**: default rendering format. Inline-renders in most chat surfaces.
- **Complex diagrams** (deployment views, many components): use PlantUML (`@startuml`) or Graphviz DOT.
- **Attack trees**: Graphviz or Mermaid `flowchart TD`.
- **Template gallery**: see `examples/mermaid_dfd_templates.md` for ready-to-adapt diagrams.

## Structured Output

All threats conform to `schemas/finding.json`. Key fields:
- `threat_id`, `title`, `description`
- `stride_category` (array of six enum values)
- `element` (name, type, technology)
- `trust_boundary`
- `attack_vector`, `attacker_profile`
- `likelihood`, `impact`, `risk_score`
- `dread_score` (object with D/R/E/A/D + average)
- `cwe`, `capec`, `mitre_attack`
- `mitigations` (array with control/type/status)
- `control_mappings` (array mapping to NIST/CIS/ASVS/ISO/PCI)
- `residual_risk`, `status`

Emit as JSONL for bulk findings; emit in the report template for human review.

## Workflow Index

| Workflow | Purpose |
|----------|---------|
| [workflows/dfd_creation.md](workflows/dfd_creation.md) | Build Level-0/Level-1 DFD as Mermaid; identify trust boundaries. |
| [workflows/stride_from_openapi.md](workflows/stride_from_openapi.md) | **Key workflow.** OpenAPI/AsyncAPI spec → STRIDE-per-interaction table. |
| [workflows/stride_from_arch_docs.md](workflows/stride_from_arch_docs.md) | Architecture docs (+ optional diagram images) → full threat model. |
| [workflows/attack_tree_from_threat.md](workflows/attack_tree_from_threat.md) | High-level threat → concrete attack tree, cheapest-path analysis. |
| [workflows/threat_to_mitigation.md](workflows/threat_to_mitigation.md) | Findings → mitigations + NIST/CIS/ASVS control IDs. |

## Methodology Index

| File | When |
|------|------|
| [methodology/stride.md](methodology/stride.md) | Default. Per-element and per-interaction. |
| [methodology/pasta.md](methodology/pasta.md) | Regulated / business-aligned; 7 stages. |
| [methodology/attack_trees.md](methodology/attack_trees.md) | Single-goal deep dive; AND/OR decomposition. |
| [methodology/dread.md](methodology/dread.md) | Quick scoring; includes critiques and alternatives. |
| [methodology/linddun.md](methodology/linddun.md) | Privacy-focused (GDPR/CCPA/HIPAA). |
| [methodology/octave.md](methodology/octave.md) | Enterprise-wide, asset-driven. |

## References Index

| File | Contents |
|------|----------|
| [references/control_catalogs.md](references/control_catalogs.md) | NIST CSF 2.0, 800-53 Rev 5, CIS v8, OWASP ASVS v5, ISO 27001, PCI DSS v4. |
| [references/trust_boundary_patterns.md](references/trust_boundary_patterns.md) | 12 common boundary patterns + weaknesses. |
| [references/framework_comparison.md](references/framework_comparison.md) | Pick-your-methodology decision matrix. |

## Examples Index

| File | Contents |
|------|----------|
| [examples/mermaid_dfd_templates.md](examples/mermaid_dfd_templates.md) | 6+ ready-to-adapt DFD templates. |
| [examples/stride_threat_library.md](examples/stride_threat_library.md) | Pre-built threats per STRIDE × element type. |
| [examples/attack_tree_banking.md](examples/attack_tree_banking.md) | Fully worked attack tree: unauthorized money transfer. |

## Templates Index

| File | Contents |
|------|----------|
| [templates/threat_model_report.md](templates/threat_model_report.md) | Full report skeleton. |
| [templates/stride_table.md](templates/stride_table.md) | STRIDE-per-element and per-interaction tables. |

## Tools

| Tool | Purpose | Install |
|------|---------|---------|
| OWASP Threat Dragon | DFD + STRIDE auto-suggestion | `npm install -g owasp-threat-dragon` |
| Microsoft Threat Modeling Tool | Windows-native STRIDE + DFD | Download from MS |
| Threagile | Threat modeling as code (YAML) | Docker image `threagile/threagile` |
| draw.io / diagrams.net | Manual DFD editing | Web app or desktop |
| Mermaid CLI (`mmdc`) | Render Mermaid to SVG/PNG | `npm install -g @mermaid-js/mermaid-cli` |
| Graphviz | Attack trees, DOT rendering | `apt install graphviz` / `brew install graphviz` |
| PlantUML | Complex diagrams | `apt install plantuml` |

## Last Validated
2026-04. Reference catalogs: NIST CSF 2.0, NIST 800-53 Rev 5, CIS Controls v8, OWASP ASVS v5, PCI DSS v4.0, ISO/IEC 27001:2022.
