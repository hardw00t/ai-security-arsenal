# GraphQL Testing Workflow

## 0 — Locate the endpoint

Common paths: `/graphql`, `/graphiql`, `/graphql/console`, `/graphql-explorer`,
`/v1/graphql`, `/api/graphql`, `/query`, `/index.php?graphql`.

## 1 — Introspection triage

Run the decision tree in `workflows/graphql_introspection_triage.md` first. It
determines whether you can rely on introspection, need field-name brute force,
or should pivot to client-scraped schema reconstruction.

```bash
curl -sX POST https://target.tld/graphql \
  -H 'Content-Type: application/json' \
  -d '{"query":"{ __schema { types { name } } }"}'
```

Also try:
- `GET /graphql?query={__schema{types{name}}}`
- `Content-Type: application/graphql` with raw query body
- `Content-Type: application/x-www-form-urlencoded` with `query=...`
- Batched request: `[{"query":"{__schema{types{name}}}"}]`

Tool: `graphql-cop -t https://target.tld/graphql`.

## 2 — Schema-driven attack surface mapping (parallelizable)

Once you have the schema, split work across sub-agents:
- Agent A: enumerate all `Query` fields, map each to an authorization check.
- Agent B: enumerate all `Mutation` fields (prioritize `update*`, `delete*`, `create*`, admin-sounding ones).
- Agent C: enumerate all object types with `id`/`email`/`ssn`/`token`/`secret` fields for BOLA targeting.

## 3 — Authorization testing (BOLA/BFLA via GraphQL)

See `payloads/graphql_queries.txt` for ready-made:
- `user(id: "...")` BOLA probes
- Nested / tenant-crossing BOLA
- Mutation BOLA / privilege escalation

Repeat each query across auth contexts (unauth / userA / userB / admin) and
diff the responses. Extended thinking is worth budgeting here.

## 4 — Denial of service / cost

Try (carefully, in authorized scope only):
- Alias amplification (N aliases of the same expensive resolver)
- Deep nesting (recursive relationships: `friends.friends.friends...`)
- Circular fragments
- Directive overloading (`@skip(if:false)` repeated)
- Batched query arrays

If the server accepts and executes these without cost limits, it is vulnerable
to `API4:2023 Unrestricted Resource Consumption`.

## 5 — Rate limit bypass

Check whether batched queries bypass per-request rate limiting by packing N
login attempts into a single HTTP request.

## 6 — Auxiliary

- CSRF via `GET /graphql?query=...` — check if state-changing ops respond to GET.
- CORS — check `Access-Control-*` headers.
- Field-suggestion disclosure — misspell fields (`passwor`) and read suggestion errors.
- Error verbosity — look for stack traces, SQL fragments, file paths in errors.

Record findings per `schemas/finding.json` with `api_type: "graphql"` and
`evidence.graphql_query` populated.
