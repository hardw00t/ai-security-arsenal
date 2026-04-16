# REST API Testing Workflow

End-to-end runbook for a REST API engagement. Each phase lists independent operations you can parallelize.

## Phase 1 — Reconnaissance (parallelizable)

Run these concurrently; they are independent.

```bash
# Spec discovery (run in parallel)
curl -s https://target.tld/api/docs           | tee recon/docs.json
curl -s https://target.tld/swagger.json       | tee recon/swagger.json
curl -s https://target.tld/openapi.json       | tee recon/openapi.json
curl -s https://target.tld/.well-known/openapi.json | tee recon/well-known.json
curl -s https://target.tld/v1/api-docs        | tee recon/v1-api-docs.json
curl -s https://target.tld/v2/api-docs        | tee recon/v2-api-docs.json
curl -s https://target.tld/api/schema         | tee recon/schema.json

# Common path brute force
ffuf -u https://target.tld/FUZZ -w api-wordlist.txt \
     -mc 200,201,204,301,302,401,403 -o recon/ffuf.json

# Endpoint discovery from JS / kiterunner / katana (parallel)
kr scan https://target.tld -w routes-large.kite -o recon/kr.txt
katana -u https://target.tld -jc -o recon/katana.txt

# Parameter discovery per-endpoint
arjun -u https://target.tld/api/users -m GET,POST -oJ recon/arjun-users.json
```

Common paths to probe manually if brute-force is noisy:
`/api/`, `/api/v1/`, `/api/v2/`, `/api/internal/`, `/rest/`, `/graphql`, `/graphiql`,
`/api-docs`, `/swagger`, `/swagger-ui`, `/swagger.json`, `/openapi.json`, `/.well-known/`,
`/actuator/`, `/actuator/env`, `/actuator/heapdump`, `/management/`, `/console/`.

## Phase 2 — Spec Parsing (run alongside recon)

If you obtained an OpenAPI/Swagger spec, parse it and emit:
- `endpoints.txt` — one `METHOD path` per line
- `params.json` — parameter list per endpoint
- `auth_modes.txt` — security schemes referenced

This unblocks fuzzers while recon is still running.

## Phase 3 — Auth Enumeration (parallelizable per auth mode)

For each identified auth mechanism, confirm a working token:
- Unauthenticated (no creds)
- User-role (regular account A and B)
- Admin-role (if available)
- Service-to-service (API key, mTLS, OIDC client-credentials)

See `workflows/jwt_attack_chooser.md` if JWTs are in use.

## Phase 4 — Authorization Matrix (SEQUENTIAL, high reasoning)

This is the highest-value phase for REST APIs. Spend extended thinking budget here.

For every endpoint x every auth context, record the response code and whether cross-user data leaks. Spawn one sub-agent per auth mode and merge.

- BOLA: see `methodology/bola_bfla_matrix.md`
- BFLA: same doc, privilege section
- Payload ID lists: `payloads/bola_idor.txt`, `payloads/bfla_privilege.txt`

## Phase 5 — Input Validation (parallelizable per endpoint)

```bash
# SQLi
sqlmap -r request.txt --batch --level 5 --risk 3
# NoSQLi, cmdi, SSRF, XXE payloads
# -> payloads/injection.txt
# Mass assignment
# -> payloads/mass_assignment.txt
```

## Phase 6 — Resource / Rate Limit

```bash
# Rapid-fire (check 429 enforcement)
seq 1 1000 | xargs -P50 -I{} curl -s -o /dev/null -w "%{http_code}\n" \
  https://target.tld/api/login -d '{"user":"test","pass":"test"}' \
  | sort | uniq -c

# Pagination abuse
GET /api/users?limit=1000000
GET /api/users?page=-1
GET /api/users?offset=9999999999

# Field expansion / projection
GET /api/users?expand=all
GET /api/users?fields=password,secret,api_key

# Batch inflation
POST /api/batch   # body: array of 10k subrequests
```

## Phase 7 — Misconfig / Inventory (parallelizable)

```bash
nuclei -u https://target.tld/api -t exposures/ -t vulnerabilities/ -t misconfiguration/
nuclei -l endpoints.txt -t api-tests/
```

Record every finding per `schemas/finding.json` with `api_type: "rest"`.
