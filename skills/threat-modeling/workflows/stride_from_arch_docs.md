# Workflow: STRIDE from Architecture Docs

Produce a full threat model from architecture documentation (text, Markdown, Confluence export, or architecture diagram images).

## Inputs
- Architecture document(s) — prose, ADRs, HLDs, Confluence pages
- Optionally: diagram images (multimodal ingest)
- Optionally: repo + IaC for grounding

## Outputs
- DFD (Mermaid) — see `workflows/dfd_creation.md`
- STRIDE-per-element table
- Threat findings conforming to `schemas/finding.json`
- Threat model report via `templates/threat_model_report.md`

## Steps

### 1. Extract system facts
From the docs, enumerate:
- **Components**: every service, database, queue, cache, CDN, third-party SaaS
- **Actors**: every user type (end user, admin, ops, service account, tenant)
- **Data assets**: each data type + classification
- **Trust zones**: network segments, privilege levels, tenant boundaries, regulatory zones

Produce a table before drawing the DFD. If the doc is ambiguous, list ambiguities explicitly — don't guess.

### 2. Reconcile with ground truth (when available)
If a repo or IaC is available, cross-check the inferred architecture:
- Service list from `docker-compose.yml`, `k8s/*.yaml`, Terraform
- Route list from framework routing (Express routes, Rails routes.rb, FastAPI decorators, Spring @RequestMapping)
- Secrets / connection strings → dependencies not in the arch doc

Discrepancies become `Unknown` / `Drift` findings.

### 3. Parse diagram images (if provided)
For each image:
- List every labeled shape and its type (rectangle/circle/cylinder/cloud)
- List every arrow and its label
- List every boundary / region
- Re-emit as Mermaid — catches ambiguous or missing annotations

### 4. Build the DFD
Level-0 context + Level-1 decomposition. Annotate every flow with protocol + auth + data class.

### 5. Mark trust boundaries
Reference `references/trust_boundary_patterns.md`. Common ones: Internet/DMZ, DMZ/App, App/Data, Tenant-A/Tenant-B, Prod/Non-Prod, Control-plane/Data-plane.

### 6. Apply STRIDE per element
Use `methodology/stride.md` element×category matrix. Pre-seed with `examples/stride_threat_library.md`.

For each applicable `(element, STRIDE)` pair, ask:
- What's the specific realization of this threat here?
- What makes it likely / unlikely for this system?
- What's the impact if realized?
- What existing controls reduce likelihood or impact?
- What new controls are needed?

### 7. Deep-dive top threats
For the top N threats (by risk score), build attack trees using `workflows/attack_tree_from_threat.md`.

### 8. Map mitigations to controls
Use `workflows/threat_to_mitigation.md` to map each threat to NIST CSF / CIS / OWASP ASVS controls.

### 9. Compose the report
Render with `templates/threat_model_report.md`.

## Ambiguity Handling

When the doc is silent on a material detail, DO:
- List the ambiguity as an explicit finding with `confidence: suspected`
- Pose a clarifying question for the human review

DO NOT:
- Invent facts ("I'll assume TLS 1.3 is used" — only say so if attested)
- Silently omit a component because its role is unclear

## Parallelism

Spawn sub-agents:
- One per major subsystem (enumerate threats in parallel)
- One per STRIDE category across all elements
- One to cross-check the repo/IaC

Converge results into a single deduplicated finding set.

## Extended Thinking

Always on for this workflow — adversarial reasoning across a whole system benefits from extended thinking. Turn off only for the final report-composition step.
