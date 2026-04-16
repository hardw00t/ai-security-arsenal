# Workflow: Greybox authenticated DAST

**Trigger:** "Perform greybox DAST on <domain> with credentials ..." / "test as logged-in user".

**Precondition:** Written scope authorization AND operator-supplied credentials (or session cookies). Confirm the account tier (low-priv / admin / dual) before starting.

## Critical ordering

**Authentication MUST complete before greybox crawl.** Do not parallelize auth with crawl. Storage state is consumed by every downstream step.

```
┌────────────────────────────────┐
│ 1. Confirm creds + tier        │
├────────────────────────────────┤
│ 2. Phase 0 — Recon (parallel)  │  as blackbox
├────────────────────────────────┤
│ 3. Playwright LOGIN (single)   │  methodology/crawling.md (greybox)
│    - fill form                 │
│    - detect CAPTCHA/2FA → ABORT│
│    - persist storageState.json │
├────────────────────────────────┤
│ 4. Phase 1 — Authed crawl      │  BFS with storageState attached
│    - re-verify auth mid-crawl  │
├────────────────────────────────┤
│ 5. Phase 2 — Authed tests      │  methodology/vuln_testing.md
│    PLUS:                       │
│    - IDOR (2-account diff)     │
│    - Privilege escalation      │
│    - Session mgmt invariants   │
│    - Mass assignment           │
│    - Business logic (extended  │
│      thinking)                 │
├────────────────────────────────┤
│ 6. Re-verify + emit report     │
└────────────────────────────────┘
```

## Multi-account pattern (strongly recommended for IDOR)

Request **two accounts of the same tier** plus **one of a higher tier** when possible:

```
contextA (low-priv)  → storageStateA.json
contextB (low-priv)  → storageStateB.json  # different tenant
contextC (admin)     → storageStateC.json  # optional
```

Run crawls in all three **after** each login completes. Then IDOR = B attempting A's object IDs; privilege escalation = A attempting C's endpoints.

## Session invariants to verify

- Cookie flags: `HttpOnly`, `Secure`, `SameSite=Lax|Strict`.
- Logout invalidates server-side session (reuse cookie after logout ⇒ finding).
- Concurrent-session policy if advertised.
- Idle / absolute timeout behavior.
- Session fixation: assigned session ID persists across login.

## Auth failure playbook

| Symptom | Action |
|---------|--------|
| CAPTCHA on login | Abort; ask operator for a bypass (backdoor form, API token). |
| 2FA required | Ask operator for TOTP seed / backup codes OR a pre-authenticated cookie. |
| Rate-limit on login | Switch to stored cookie; do not brute the login endpoint. |
| CSRF token on login | Playwright already fetches it via form — ensure submit uses the rendered DOM, not a raw POST. |

## Output

`results/target.com/output.json` with `affected.authenticated_as` populated per entry.

## Related

- Blackbox flow: `workflows/blackbox_single_domain.md`
- Multi-domain: `workflows/multi_domain_parallel.md`
- Business logic patterns: `payloads/business_logic.txt`
