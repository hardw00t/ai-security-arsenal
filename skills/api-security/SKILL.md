---
name: api-security
description: "Router skill for API penetration testing across REST, GraphQL, gRPC, and WebSocket. Covers OWASP API Top 10 (2023) including BOLA/BFLA/BOPLA, JWT attack chains, GraphQL introspection abuse, and mass assignment. Invoke when the user asks to pentest an API, analyze OpenAPI/Swagger, test auth/authorization, fuzz endpoints, or find API vulnerabilities."
---

# API Security Testing

Thin router for API penetration testing. Use the index sections to load the
specific workflow, payload file, or methodology doc for the phase you're in.
Do not pre-load everything.

## When to Use

- Pentesting a REST, GraphQL, gRPC, or WebSocket API.
- OWASP API Top 10 (2023) coverage assessment.
- BOLA / BFLA / BOPLA authorization matrix analysis.
- JWT / OAuth / API-key auth testing.
- Fuzzing endpoints, parameters, or schemas.
- Parsing and attacking OpenAPI / Swagger / GraphQL schemas.
- Rate-limit / resource-consumption testing.

## Trigger Phrases

"pentest this API", "test the REST API", "test GraphQL security", "check for
BOLA/IDOR", "analyze OpenAPI spec", "test API authentication", "JWT attacks",
"fuzz API endpoints", "GraphQL introspection".

## When NOT to Use This Skill

- **Browser / DOM-based testing** (XSS, CSP, clickjacking, client-side auth
  flows rendered in a browser) -> use `dast-automation`.
- **Reviewing API source code** for injection/authz bugs at the code level ->
  use `sast-orchestration`.
- **Mobile client reversing** to recover API endpoints from an APK/IPA ->
  use `mobile-security` first, then return here with the recovered spec.
- **Cloud-provider IAM / API-gateway config auditing** (not the API itself) ->
  use `cloud-security`.

## Decision Tree

```
Is there a schema (OpenAPI / GraphQL SDL / .proto)?
  yes -> parse it first, feed endpoints.txt to fuzzers
  no  -> methodology/api_recon.md

What protocol?
  REST / JSON over HTTP -> workflows/rest_testing.md
  GraphQL               -> workflows/graphql_introspection_triage.md
                           then workflows/graphql_testing.md
  gRPC                  -> workflows/grpc_testing.md
  WebSocket             -> workflows/websocket_testing.md

Is a JWT in use?
  yes -> workflows/jwt_attack_chooser.md  (alg-none -> key-conf -> kid -> brute)

Primary finding target?
  Authorization bugs  -> methodology/bola_bfla_matrix.md  (HIGHEST yield)
  Misconfig / inventory -> nuclei + references/owasp_api_top10_2023.md (API8/API9)
  Injection / SSRF    -> payloads/injection.txt
```

## Parallelism Hints

Run concurrently (independent I/O):
- Spec discovery: `swagger.json`, `openapi.json`, `.well-known/openapi.json`,
  `v1/api-docs`, `v2/api-docs`.
- Endpoint discovery: ffuf + kiterunner + katana can run on the same host.
- Auth enumeration: collect a token per role (unauth / user / admin / service)
  in parallel — each is a separate login flow.
- Nuclei `exposures/`, `vulnerabilities/`, `misconfiguration/` template packs.

Keep sequential (state-dependent):
- Spec parse must finish before endpoint-driven fuzzers can consume it.
- Authorization matrix diffing must wait for all per-role scans to complete.
- JWT attack chain steps are ordered (see `workflows/jwt_attack_chooser.md`).

## Sub-Agent Delegation

Spawn one sub-agent **per auth context** when building the BOLA/BFLA matrix:
- Agent U — unauthenticated
- Agent A — user-role (account A)
- Agent B — user-role (account B, cross-user)
- Agent X — admin-role (if available)
- Agent S — service / machine account (if applicable)

Each agent iterates the full endpoint list with its own token and returns
`{endpoint, method, status, body_hash, leaks_cross_user}`. Main agent diffs
the five result sets. This is the single biggest parallelism win in API
pentesting.

For GraphQL, also delegate: one sub-agent enumerates all `Query` fields,
another all `Mutation` fields, another maps ID-bearing types for BOLA targeting.

## Reasoning Budget

- **Extended thinking** — authorization matrix analysis, JWT attack-path
  selection, GraphQL schema-driven attack planning, business-logic flow
  modeling (API6).
- **Minimal / execute directly** — payload fuzzing, nuclei runs, ffuf brute
  force, grpcurl calls, JWT decoding, spec parsing.

## Multimodal Hooks

- Screenshots of Swagger / GraphiQL / Postman UIs can accelerate spec recovery
  when text scraping fails.
- For JWT and GraphQL evidence, prefer text blobs (`evidence.jwt_header`,
  `evidence.graphql_query`) over screenshots.

## Structured Output

Every finding: `schemas/finding.json`. Required API-specific fields:
`endpoint`, `http_method`, `api_type` (rest/graphql/grpc/websocket),
`auth_context`, `owasp_api_id` (e.g. `API1:2023`).

## Workflow Index

| Workflow                                           | When to load                                    |
|----------------------------------------------------|-------------------------------------------------|
| `workflows/rest_testing.md`                        | REST/JSON APIs, full 7-phase runbook            |
| `workflows/graphql_testing.md`                     | GraphQL testing, post-introspection triage      |
| `workflows/graphql_introspection_triage.md`        | Deciding how to get the GraphQL schema          |
| `workflows/grpc_testing.md`                        | gRPC services (reflection or `.proto`-driven)   |
| `workflows/websocket_testing.md`                   | WebSocket / socket.io / GraphQL subscriptions   |
| `workflows/jwt_attack_chooser.md`                  | JWTs present — ordered attack chain             |

## Methodology Index

| Doc                                   | When to load                                         |
|---------------------------------------|------------------------------------------------------|
| `methodology/api_recon.md`            | Before attack: building endpoint + auth inventory    |
| `methodology/bola_bfla_matrix.md`     | Authorization testing — highest-value phase          |
| `methodology/bounty_patterns_2024_2026.md` | Post-2023 public bug-bounty TTPs (OAuth ATO, JWT `request_uri`, refresh-token persistence, mass-assignment, ORM leakage) |

## Payloads Index

| File                               | Use                                                  |
|------------------------------------|------------------------------------------------------|
| `payloads/bola_idor.txt`           | Object-ID substitution values for BOLA/IDOR          |
| `payloads/bfla_privilege.txt`      | Admin paths, method overrides, role-spoof headers    |
| `payloads/graphql_queries.txt`     | Introspection, batching, alias DoS, mutation BOLA    |
| `payloads/jwt_attacks.txt`         | Header / claim tampering recipes                     |
| `payloads/mass_assignment.txt`     | Over-posting keys for POST/PUT/PATCH                 |
| `payloads/injection.txt`           | SQLi, NoSQLi, cmdi, SSRF, XXE, SSTI, proto pollution |

## References Index

| File                                              | Content                                    |
|---------------------------------------------------|--------------------------------------------|
| `references/owasp_api_top10_2023.md`              | OWASP API Top 10 (2023) table + pointers   |
| `references/tools.md`                             | Tool install / version reference           |

## Examples Index

| File                                       | Content                                    |
|--------------------------------------------|--------------------------------------------|
| `examples/bola_finding.md`                 | REST BOLA — filled-in finding JSON         |
| `examples/jwt_none_finding.md`             | JWT alg=none — filled-in finding JSON      |
| `examples/graphql_bola_finding.md`         | GraphQL mutation BOLA — finding JSON       |

## Tools

| Tool         | Purpose                   | Install                                                          |
|--------------|---------------------------|------------------------------------------------------------------|
| Burp Suite   | HTTP intercept            | https://portswigger.net/burp                                     |
| ffuf         | HTTP fuzzer               | `go install github.com/ffuf/ffuf/v2@latest`                      |
| nuclei       | Template scanner          | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| jwt_tool     | JWT attack CLI            | `pip install jwt_tool`                                           |
| graphql-cop  | GraphQL misconfig scan    | `pip install graphql-cop`                                        |
| grpcurl      | gRPC CLI                  | `go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest`  |
| arjun        | Parameter discovery       | `pip install arjun`                                              |
| kiterunner   | API route discovery       | https://github.com/assetnote/kiterunner/releases                 |

Full list: `references/tools.md`.

## Last Validated

2026-04. Minimum tool versions: nuclei >= 3.3, ffuf >= 2.1, grpcurl >= 1.9,
jwt_tool >= 2.2, graphql-cop >= 1.13.
