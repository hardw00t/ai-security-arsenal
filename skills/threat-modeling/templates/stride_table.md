# STRIDE Table Templates

## STRIDE-per-Element Worksheet

One row per (element, STRIDE category) applicable combination. Use the element-type applicability matrix from `methodology/stride.md`.

| Element | Type | S | T | R | I | D | E |
|---------|------|---|---|---|---|---|---|
| User | external entity | `<threat/none>` | — | `<threat/none>` | — | — | — |
| Web API | process | `<>` | `<>` | `<>` | `<>` | `<>` | `<>` |
| PostgreSQL | data store | — | `<>` | `<>` | `<>` | `<>` | — |
| API → DB flow | data flow | — | `<>` | — | `<>` | `<>` | — |

Fill each cell with either a threat identifier (e.g. `TM-001`) or `—` for N/A.

## STRIDE-per-Interaction Table (for API-heavy systems)

Generated from OpenAPI via `workflows/stride_from_openapi.md`.

| Operation | Method | Path | Auth | Exposure | S | T | R | I | D | E |
|-----------|--------|------|------|----------|---|---|---|---|---|---|
| `listUsers` | GET | `/users` | Bearer | internet | — | — | — | TM-004 | TM-005 | TM-006 |
| `getUser` | GET | `/users/{id}` | Bearer | internet | — | — | — | TM-007 (IDOR) | — | TM-008 |
| `createUser` | POST | `/users` | Bearer | internet | — | TM-009 (mass assignment) | — | — | — | — |
| `deleteUser` | DELETE | `/users/{id}` | Bearer + admin | internet | — | — | TM-010 (no audit) | — | — | TM-011 |

## Threat Detail Block (one per cell marked with an ID)

```
Threat ID: TM-007
Title: IDOR on GET /users/{id}
STRIDE: Information Disclosure
Element: data flow (API ↔ DB) + process (API server)
Attack Vector: Authenticated user substitutes another user's ID
  in the path and retrieves their record; server does not verify
  the requester's ownership / tenant.
Likelihood: High
Impact: High
Risk: 8 (PII exposure at scale)
Controls (Preventive): Ownership check in route handler;
  enforce row-level security at DB.
Controls (Detective): Alert on enumeration patterns
  (same user hitting /users/{id} with increasing IDs).
CWE: CWE-639
OWASP: API1:2023 (BOLA)
References: <OWASP API Sec Top 10>
```

## Compact All-Threats Summary

For executive summary:

| ID | Title | STRIDE | Risk | Status |
|----|-------|--------|------|--------|
| TM-001 | `<short>` | `<letters>` | `<score>` | `<proposed/planned/implemented/verified>` |

Sort by risk descending; highlight the top 20% separately.
