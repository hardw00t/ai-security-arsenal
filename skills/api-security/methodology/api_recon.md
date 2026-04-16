# API Reconnaissance Methodology

Goal: produce `endpoints.txt` (every `METHOD path` pair you'll test) and
`auth_modes.txt` (every way to authenticate) before attack phases.

## Sources (run in parallel)

1. **Published spec** — OpenAPI / Swagger / RAML / API Blueprint / AsyncAPI.
   Paths to probe: `/swagger.json`, `/openapi.json`, `/api-docs`,
   `/.well-known/openapi.json`, `/v1/api-docs`, `/v2/api-docs`, `/api/schema`,
   `/api/docs`, `/docs/api.json`, `/api-docs.json`.
2. **Client reverse engineering** — grep JS bundles for `fetch(`, `axios(`,
   `apollo`, `gql\``, URLs. Mobile apps often have embedded `.proto` or
   hardcoded URLs.
3. **Path brute force** — `ffuf`, `kiterunner`, `katana`, `feroxbuster`.
4. **Traffic capture** — Burp / mitmproxy while exercising the app.
5. **Passive** — `wayback`, `commoncrawl`, `github` code search, `ProjectDiscovery chaos`.

## Deduplicate & normalize

Canonical form: `GET /api/v1/users/{id}` — with path parameters templatized
as `{name}` so the matrix stays compact.

## Auth modes

For each endpoint, note security schemes:
- Cookie session
- `Authorization: Bearer <jwt>`
- `Authorization: Bearer <opaque>`
- `X-API-Key`
- HMAC-signed request (AWS SigV4-like)
- mTLS
- OAuth2 flows (auth code, client credentials, password, device)
- Basic

Capture one working token per mode per role (unauth, user, admin).

## Environment inventory (API9:2023)

Hunt for forgotten surface:
- Non-prod hosts: `api-dev.`, `api-staging.`, `api-uat.`, `api-preview.`.
- Old versions: `/api/v0/`, `/api/v1/` when current is `/api/v3/`.
- Mobile-only or partner-only endpoints that never got removed.
- Debug / actuator endpoints: `/actuator/`, `/debug/`, `/_debug/`, `/console/`.

Each forgotten env/version is typically a finding on its own.
