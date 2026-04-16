# BOLA / BFLA Authorization Matrix

The single highest-value methodology for API testing. Spend extended thinking
budget here.

## Matrix shape

Rows = endpoints. Columns = auth contexts. Cell = observed behavior + expected.

| Endpoint                          | unauth | userA(owner) | userB(stranger) | admin |
|-----------------------------------|--------|--------------|-----------------|-------|
| GET  /api/users/{A}               |        |              |                 |       |
| GET  /api/users/{B}               |        |              |                 |       |
| PUT  /api/users/{B}               |        |              |                 |       |
| DELETE /api/users/{B}             |        |              |                 |       |
| GET  /api/admin/users             |        |              |                 |       |
| POST /api/admin/users             |        |              |                 |       |

Fill with `200(data)`, `403`, `404(hides)`, `401`, `500`, etc.

## Parallelism

Spawn one sub-agent per auth column. Each agent iterates all endpoints with
its token. Main agent diffs the result matrices.

## BOLA (API1:2023) test procedure

1. Enumerate endpoints whose path or body carries an object identifier
   (`{id}`, `{uuid}`, `{slug}`, `?orderId=`, `?accountId=`, body `{"userId": ...}`).
2. As userA, observe own resource ID(s).
3. As userA, substitute userB's ID. Expected: 403 or 404. Finding: 200 w/ userB data.
4. Substitute IDs across tenants if multi-tenant.
5. Try ID type confusion:
   - Sequential integers (1, 2, 3...)
   - UUIDs (still test — rotation bugs and enumeration via other endpoints happen)
   - Encoded IDs (base64, hex, HMAC'd — see if server trusts without re-verify)
   - Wildcard / null / array (some frameworks return all rows)
6. Probe nested relationships (orders under users, messages under conversations).
7. Test indirect references (email, username, slug) — often less protected than primary keys.

Payloads: `payloads/bola_idor.txt`.

## BFLA (API5:2023) test procedure

1. Enumerate privileged-sounding endpoints from spec + brute-force discovery.
2. As userA (non-admin), attempt each.
3. Test HTTP method switching: if `GET /api/users` is allowed for userA, try
   `POST /api/users` with an elevation payload.
4. Test header-based method override (`X-HTTP-Method-Override: DELETE`).
5. Test parameter pollution on role/privilege fields (`?role=admin`).
6. Test privilege-spoofing headers (`X-User-Role: admin`, `X-Forwarded-User: admin`).
7. Test `admin` path segment substitution: if `/api/users` works for users,
   try `/api/admin/users` with the same token.

Payloads: `payloads/bfla_privilege.txt`.

## BOPLA (API3:2023) — property-level

Even if object-level auth passes, property-level may not:
- Retrieved object may include fields userA shouldn't see (SSN, internal notes).
- Update payload may accept fields userA shouldn't be able to set (mass assignment).

Checks:
- Diff response fields across auth contexts (admin sees more than user).
- Send `payloads/mass_assignment.txt` keys on POST/PUT and check if server accepts.

## Evidence capture

For each finding, capture both requests (authorized baseline + unauthorized
exploit) and both responses. Populate `schemas/finding.json` with:
- `owasp_api_id`: `API1:2023`, `API3:2023`, or `API5:2023`
- `auth_context`: the column that succeeded (e.g. `"cross-user"` for userA->userB)
- `evidence.request` and `evidence.response` for both sides
