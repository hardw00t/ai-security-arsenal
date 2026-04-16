# GraphQL Introspection Triage

Decide how to obtain the schema and whether introspection exposure is itself
a finding.

```
          POST /graphql  { __schema { types { name } } }
                           |
           +---------------+----------------+
           |                                |
      200 with data                   Error / 400 / 403
           |                                |
   [INTROSPECTION ON]                [INTROSPECTION OFF ?]
           |                                |
           |                      Try alternate transports:
           |                        - GET  /graphql?query=...
           |                        - Content-Type: application/graphql
           |                        - Content-Type: text/plain
           |                        - Batched JSON array
           |                        - Persisted-query bypass
           |                                |
           |                      +---------+---------+
           |                      |                   |
           |                 Any returns schema    Still blocked
           |                      |                   |
           |              [PARTIAL INTROSPECTION]  [Field-name
           |                      |                 brute force /
           |                      |                 client scraping]
           v                      v                   v
  Dump full schema        Dump what you can      Use graphql-cop,
  (graphql-cop,           via working transport  clairvoyance,
  clairvoyance, or the    and mark as finding    schema-inference
  __schema query in       (introspection gated   against error
  payloads/graphql_       by transport = weak    messages
  queries.txt)            control)
           |                      |                   |
           +----------+-----------+-------------------+
                      |
                      v
         Proceed to workflows/graphql_testing.md
         Phase 2 (schema-driven mapping)
```

## Scoring

- Production introspection ON by default: `API8:2023` Security Misconfiguration
  (medium-high) + `API9:2023` Improper Inventory Management (medium).
- Introspection OFF but leaking via alternate transport: same rating; the
  gating is just transport filtering, not a real control.
- Introspection OFF and uniformly blocked: not a finding; note the defense and move on.

## When introspection is fully blocked

Tools to reconstruct schema:
- `clairvoyance` — uses field-name suggestions from error responses.
- Static analysis of client bundles (JS, mobile APK) — GraphQL queries are
  usually hardcoded or in generated files.
- `graphql-cop` and `inql` for partial fingerprinting.

Do NOT waste reasoning budget on blocked-introspection targets; mine the
client first — it's cheaper and often complete.
