# Workflow: STRIDE-per-Interaction from OpenAPI/AsyncAPI

**Key workflow.** Frontier models can consume an OpenAPI/AsyncAPI document and auto-generate a STRIDE-per-interaction threat table. This short-circuits the slowest part of threat modeling.

## Inputs
- `openapi.yaml` / `openapi.json` (v3.x) OR `asyncapi.yaml` (v2/v3)
- Optional: deployment / infra context (which services are internet-facing, what trust boundaries exist)
- Optional: authn/authz scheme details beyond the spec

## Outputs
- STRIDE-per-interaction table (one row per operation)
- Markdown threat catalog with `schemas/finding.json`-shaped findings
- Prioritized mitigation list

## Steps

### 1. Parse operations
For OpenAPI 3: iterate every `{path}{method}` pair. For each, record:
- `operationId`, path, method
- Request body schema & content types
- Response bodies & status codes
- Security requirements (`security` at global + operation level)
- Parameters (path, query, header, cookie)
- Tags (for grouping by trust zone)

For AsyncAPI: iterate every channel × operation pair. Record pub/sub direction, message schemas, bindings, security.

### 2. Classify each operation
Attach attributes to drive threat selection:
| Attribute | Values |
|-----------|--------|
| Auth | none / api_key / bearer / mTLS / OAuth2 |
| Exposure | internet / partner / internal |
| Side effects | read / write / destructive / privileged |
| PII touched | yes / no |
| Rate-limit-sensitive | yes / no |

### 3. Apply STRIDE per operation
For every operation, run this six-question checklist:

| STRIDE | Question | Example Threat |
|--------|----------|----------------|
| S | Can the caller identity be forged? | Missing/weak auth, JWT alg=none, API key in URL |
| T | Can request/response be modified undetected? | No TLS, no HMAC, parameter tampering, mass assignment |
| R | Can the caller deny having made the call? | No audit log, shared service account, no request IDs |
| I | Can the response leak data beyond what the caller should see? | Verbose errors, BOLA/IDOR, sensitive fields in response, debug stacks |
| D | Can the operation be used to exhaust resources? | No rate limit, unbounded pagination/query, ReDoS-prone regex, large body |
| E | Can this operation escalate privileges? | Missing authz checks, broken function-level authz, role-editing endpoint open to normal users |

### 4. Generate STRIDE-per-interaction table
Write one row per `(operationId, STRIDE_category)` where a threat exists. Use `templates/stride_table.md` for format.

### 5. Emit findings
Populate `schemas/finding.json` for each threat with:
- `threat_id` like `TM-{operationId}-{STRIDE-letter}-{n}`
- `element.type = "data_flow"` (or `process` for the backing service)
- `element.name = operationId`
- `attack_vector` filled from the threat description
- `mitigations` mapped via `workflows/threat_to_mitigation.md`

### 6. Prioritize
Rank operations by: `internet-exposed × destructive × PII × missing-control`. Focus mitigation effort on top 20%.

## Heuristics the Model Should Apply

- Any `security: []` at operation level on a non-idempotent endpoint: **flag Spoofing + Elevation**.
- `GET` that accepts user-controlled ID in path and has a `200` response with object data: **flag Information Disclosure (BOLA/IDOR)** unless obvious tenant check exists.
- `POST` / `PUT` / `PATCH` without response schema or returning full object: **flag Mass Assignment / Info Disclosure**.
- Any endpoint with no rate-limit indicator and no auth: **flag DoS**.
- Missing `WWW-Authenticate` 401 flow / vague 401s: **flag Spoofing + Repudiation**.
- `apiKey` in query parameter (vs header): **flag Info Disclosure** (logs, referer leakage).
- OAuth2 with `implicit` flow or `password` grant in new specs: **flag Spoofing**.
- Server sends fields starting with `_`, `internal`, `debug`, `password`, `hash`, `secret`: **flag Info Disclosure**.

## Parallelism

Process operations in batches across sub-agents. One sub-agent per tag group (or per STRIDE letter across all ops). See parent `SKILL.md` Sub-Agent Delegation.

## Extended Thinking

Turn on extended thinking when:
- The spec has >50 operations (strategic grouping matters)
- Custom auth schemes need modeling
- Cross-operation attack chains are possible (e.g., low-priv read + privileged write)

## Complementary Skill

For runtime testing to confirm the identified threats are exploitable, hand off to the `api-security` skill.

## Reference Template
See `examples/stride_threat_library.md` for pre-built threat patterns per element type.
